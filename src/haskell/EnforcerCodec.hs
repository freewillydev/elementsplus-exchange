{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE OverloadedStrings #-}
module EnforcerCodec (prepare) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import qualified Data.ByteString.Lazy as L
import Data.Bifunctor (first)
import Data.Proxy (Proxy(..))
import qualified Data.Aeson as A
import qualified Data.Aeson.Key as K
import qualified Data.Aeson.KeyMap as M
import qualified Data.Text as T
import Data.Char (toLower, isUpper, toUpper)
import qualified Proto3.Suite as P
import qualified Proto3.Suite.JSONPB as J
import qualified Cusf.Mainchain.V1.Validator as V
import qualified Cusf.Mainchain.V1.Wallet as W

-- The generated protocol types, not JSON-shaped mock messages, define the wire.
prepare :: B.ByteString -> B.ByteString
        -> Either String (B.ByteString, B.ByteString -> Either String L.ByteString)
prepare method original = do
  payload <- normalizeRequest method original
  select method payload

select :: B.ByteString -> B.ByteString
       -> Either String (B.ByteString, B.ByteString -> Either String L.ByteString)
select method payload = case C.unpack method of
  "cusf.mainchain.v1.WalletService/CreateBmmCriticalDataTransaction" ->
    codec (Proxy @W.CreateBmmCriticalDataTransactionRequest) (Proxy @W.CreateBmmCriticalDataTransactionResponse) payload
  "cusf.mainchain.v1.WalletService/BroadcastWithdrawalBundle" ->
    codec (Proxy @W.BroadcastWithdrawalBundleRequest) (Proxy @W.BroadcastWithdrawalBundleResponse) payload
  "cusf.mainchain.v1.ValidatorService/GetTwoWayPegData" ->
    codec (Proxy @V.GetTwoWayPegDataRequest) (Proxy @V.GetTwoWayPegDataResponse) payload
  "cusf.mainchain.v1.ValidatorService/GetChainInfo" ->
    codec (Proxy @V.GetChainInfoRequest) (Proxy @V.GetChainInfoResponse) payload
  "cusf.mainchain.v1.ValidatorService/GetChainTip" ->
    codec (Proxy @V.GetChainTipRequest) (Proxy @V.GetChainTipResponse) payload
  "cusf.mainchain.v1.ValidatorService/GetSidechains" ->
    codec (Proxy @V.GetSidechainsRequest) (Proxy @V.GetSidechainsResponse) payload
  "cusf.mainchain.v1.ValidatorService/GetCtip" ->
    codec (Proxy @V.GetCtipRequest) (Proxy @V.GetCtipResponse) payload
  _ -> Left "refusing an unrecognized enforcer gRPC method"

codec :: forall request response.
         (P.Message request, J.FromJSONPB request, P.Message response, J.ToJSONPB response)
      => Proxy request -> Proxy response -> B.ByteString
      -> Either String (B.ByteString, B.ByteString -> Either String L.ByteString)
codec _ _ payload = do
  request <- J.eitherDecode (L.fromStrict payload) :: Either String request
  pure (L.toStrict (P.toLazyByteString request), \wire ->
    (A.encode . camelKeys . flip J.toJSONPB J.jsonPBOptions :: response -> L.ByteString) <$> first show (P.fromByteString wire))

-- proto3-suite preserves proto field names; the existing node API uses ProtoJSON
-- lowerCamelCase. No selected message contains a map with user-controlled keys.
camelKeys :: A.Value -> A.Value
camelKeys (A.Object fields) = A.Object $ M.fromList
  [(K.fromText (camel (K.toText key)), camelKeys value) | (key,value) <- M.toList fields]
  where
    camel name = case T.splitOn "_" name of
      [] -> name
      firstPart:rest -> firstPart <> T.concat (map upperFirst rest)
    upperFirst text = case T.uncons text of
      Nothing -> text
      Just (headChar,tailText) -> T.cons (toUpper headChar) tailText
camelKeys (A.Array values) = A.Array (fmap camelKeys values)
camelKeys value = value

normalizeRequest :: B.ByteString -> B.ByteString -> Either String B.ByteString
normalizeRequest method payload = do
  fields <- A.eitherDecodeStrict' payload >>= \value -> case value of
    A.Object object -> Right (M.toList object)
    _ -> Left "enforcer request must be an object"
  allowed <- case C.unpack method of
    "cusf.mainchain.v1.WalletService/CreateBmmCriticalDataTransaction" ->
      Right ["sidechain_id","value_sats","height","critical_hash","prev_bytes"]
    "cusf.mainchain.v1.WalletService/BroadcastWithdrawalBundle" -> Right ["sidechain_id","transaction"]
    "cusf.mainchain.v1.ValidatorService/GetTwoWayPegData" -> Right ["sidechain_id","start_block_hash","end_block_hash"]
    "cusf.mainchain.v1.ValidatorService/GetCtip" -> Right ["sidechain_number"]
    "cusf.mainchain.v1.ValidatorService/GetChainInfo" -> Right []
    "cusf.mainchain.v1.ValidatorService/GetChainTip" -> Right []
    "cusf.mainchain.v1.ValidatorService/GetSidechains" -> Right []
    _ -> Left "refusing an unrecognized enforcer gRPC method"
  normalized <- traverse (field allowed) fields
  let object = M.fromList normalized
  if M.size object /= length fields then Left "duplicate enforcer request field alias"
    else Right (L.toStrict (A.encode (A.Object object)))
  where
    snake = T.concatMap (\char -> if isUpper char then T.pack ['_',toLower char] else T.singleton char)
    field allowed (key,value) =
      let name = snake (K.toText key)
          validNested (A.Object object) = all (== "hex") (M.keys object)
          validNested (A.Array _) = False
          validNested _ = True
      in if name `elem` allowed && validNested value then Right (K.fromText name,value)
           else Left "unknown enforcer request field"
