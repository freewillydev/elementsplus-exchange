{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
module GrpcClient (elements_hs_grpc_v1) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.Async (withAsync, poll, wait)
import Control.Exception (SomeException, catch, throwIO)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import qualified Data.ByteString.Lazy as L
import Data.Int (Int64)
import Data.Word (Word64)
import Foreign.C.String (CString)
import Foreign.C.Types (CInt(..), CSize(..))
import Foreign.Marshal.Array (peekArray)
import Foreign.Ptr (Ptr, FunPtr)
import GHC.Clock (getMonotonicTimeNSec)
import Network.GRPC.LowLevel.Client
import Network.GRPC.LowLevel.Call (Endpoint(..), MethodName(..), ClientCall, clientCallCancel, unsafeCC)
import Network.GRPC.LowLevel.GRPC (withGRPC, GRPCIOError(..), StatusDetails(..))
import Network.GRPC.LowLevel.Op
import Network.GRPC.Unsafe.ChannelArgs (Arg(..))
import Network.GRPC.Unsafe.Op (StatusCode(..))
import qualified EnforcerCodec

type Cancel = Ptr () -> IO CInt
type Emit = Ptr () -> CString -> CSize -> IO ()
foreign import ccall safe "dynamic" cancelCallback :: FunPtr Cancel -> Cancel
foreign import ccall safe "dynamic" emitCallback :: FunPtr Emit -> Emit
foreign export ccall elements_hs_grpc_v1
  :: Ptr CString -> Int64 -> Word64 -> FunPtr Cancel -> FunPtr Emit -> Ptr () -> IO CInt

-- Negative statuses are local failures; positive statuses are canonical gRPC codes.
-- Native callbacks remain on the calling thread. Only network completion runs in
-- the worker, which is joined before destroying the call, channel or credentials.
elements_hs_grpc_v1 :: Ptr CString -> Int64 -> Word64 -> FunPtr Cancel -> FunPtr Emit -> Ptr () -> IO CInt
elements_hs_grpc_v1 fields timeoutMs maxOutput cancel emit context =
  (do
    start <- getMonotonicTimeNSec
    values <- peekArray 7 fields >>= mapM B.packCString
    case values of
      [method,payload,address,ca,certificate,key,authority]
        | timeoutMs > 0 && timeoutMs <= 600000 && maxOutput > 0 && maxOutput <= 16777216 -> do
          if B.length payload > 1048576 then report (-1) "enforcer request exceeds 1 MiB" else
            case EnforcerCodec.prepare method payload of
              Left _ -> report (-1) "invalid enforcer request for method schema"
              Right (wire,decode) -> do
                let deadline = start + fromIntegral timeoutMs * 1000000
                    options = [MaxReceiveMessageLength (fromIntegral maxOutput), MaxMetadataSize 8192, EnableRetries False]
                      ++ if B.null authority then [] else [SslTargetNameOverride (C.unpack authority)]
                    config = ClientConfig (Endpoint address) options
                      (Just (ClientSSLConfig (Just (C.unpack ca))
                        (Just (ClientSSLKeyCertPair (C.unpack key) (C.unpack certificate))) Nothing))
                      (if B.null authority then Nothing else Just authority)
                stopped <- checkStop deadline
                case stopped of
                  Just code -> report code "enforcer request stopped before connection"
                  Nothing -> withGRPC $ \runtime -> withClient runtime config $ \client -> do
                    methodHandle <- clientRegisterMethodNormal client (MethodName ("/" <> method))
                    outcome <- withClientCall client methodHandle (fromIntegral ((timeoutMs + 999) `div` 1000)) $ \call ->
                      withAsync (exchange client call wire) $ \pending -> do
                        let await = do
                              stop <- checkStop deadline
                              case stop of
                                Just code -> do
                                  clientCallCancel call
                                  _ <- wait pending
                                  pure (Right (Left code))
                                Nothing -> do
                                  ready <- poll pending
                                  case ready of
                                    Nothing -> threadDelay 10000 >> await
                                    Just (Left exception) -> throwIO exception
                                    Just (Right result) -> pure (fmap (Right . rspBody) result)
                        await
                    case outcome of
                      Left failure -> grpcFailure failure
                      Right (Left code) -> report code "enforcer request cancelled or deadline exceeded"
                      Right (Right body) -> case decode body of
                        Left _ -> report (-1) "invalid enforcer protobuf response"
                        Right json -> do
                          let bounded = L.toStrict (L.take (fromIntegral maxOutput + 1) json)
                          if fromIntegral (B.length bounded) > maxOutput
                            then report (-4) "enforcer JSON response exceeded output limit"
                            else report 0 bounded
      _ -> report (-1) "invalid enforcer transport parameters")
  `catch` \(_ :: SomeException) -> report (-1) "enforcer transport exception"
  where
    report code bytes = do
      B.useAsCStringLen (B.take (fromIntegral (min maxOutput 16777216)) bytes) $ \(ptr,len) ->
        emitCallback emit context ptr (fromIntegral len)
      pure code
    checkStop deadline = do
      cancelled <- cancelCallback cancel context
      now <- getMonotonicTimeNSec
      pure (if cancelled /= 0 then Just (-2) else if now >= deadline then Just (-3) else Nothing)
    grpcFailure (GRPCIOBadStatusCode code details)
      | show code == "StatusCancelled" = report (-2) "enforcer request cancelled"
      | show code == "StatusDeadlineExceeded" = report (-3) "enforcer deadline exceeded"
      | otherwise = report (fromIntegral (fromEnum code))
          (C.pack (drop 6 (show code)) <> ": " <> unStatusDetails details)
    grpcFailure GRPCIOTimeout = report (-3) "enforcer deadline exceeded"
    grpcFailure _ = report (-1) "enforcer transport failed"

exchange :: Client -> ClientCall -> B.ByteString -> IO (Either GRPCIOError NormalRequestResult)
exchange client call wire = do
  sent <- runOps (unsafeCC call) (clientCQ client)
    [OpSendInitialMetadata mempty, OpSendMessage wire, OpSendCloseFromClient]
  case sent of
    Left failure -> pure (Left failure)
    Right initial -> do
      received <- runOps (unsafeCC call) (clientCQ client)
        [OpRecvInitialMetadata, OpRecvMessage, OpRecvStatusOnClient]
      pure $ do
        results <- received
        reply <- compileNormalRequestResults (initial ++ results)
        if rspCode reply == StatusOk then Right reply
          else Left (GRPCIOBadStatusCode (rspCode reply) (details reply))
