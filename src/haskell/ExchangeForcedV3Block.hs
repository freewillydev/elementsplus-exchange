{-# LANGUAGE ConstraintKinds, DataKinds, FlexibleContexts, FlexibleInstances, GADTs #-}
{-# LANGUAGE MultiParamTypeClasses, TypeApplications, TypeFamilies #-}
-- Source/cursor workflows and codecs. No operation here grants a verified
-- execution receipt or changes chain activation.
module ExchangeForcedV3Block where

import Control.Monad (guard, when)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Except (ExceptT, runExceptT, throwE)
import Control.Operation
import Control.Operation.Validation
import CapabilityContext
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import qualified Data.Set as Set
import Data.Word (Word8, Word32, Word64)
import qualified Exchange
import qualified ExchangeCustody as Custody
import ExchangeForcedV3
import Withdrawal (wordBE)
import Workflow (NativeBytes)

newtype ForcedV3BlockBytes = ForcedV3BlockBytes (Word64,B.ByteString)
instance Validation ForcedV3BlockBytes where
  type ValidationResult ForcedV3BlockBytes = Maybe B.ByteString
  validate (ForcedV3BlockBytes (mode,bytes)) = case mode of
    0 -> entryBytes bytes
    1 -> nextState bytes
    2 -> Just (B.singleton (markerKind bytes))
    3 -> cursorBinding bytes
    -- No pinned fresh outer/settlement relation has been registered. A host
    -- boolean or structurally valid marker cannot create that missing receipt.
    4 -> guard (bytes==B.singleton 0) >> pure (B.singleton 1)
    _ -> Nothing

-- State145, actual txid32, sidechain8, authenticated parent8, output4, payload.
entryBytes :: B.ByteString -> Maybe B.ByteString
entryBytes bytes = do
  guard (B.length bytes>=237 && B.length bytes<=4301)
  let state=B.take 145 bytes
      payload=B.drop 197 bytes
      pin=slice 1 32 state
      side=integerBE (slice 177 8 bytes)
      parent=integerBE (slice 185 8 bytes)
      kind=B.index payload 5
  guard (validate (ForcedV3State pin state) && side>0 && parent>0 &&
    nonzeroHash (slice 145 32 bytes) && B.take 5 payload==B.pack [69,67,88,70,3] &&
    kind<=4 && slice 8 32 payload==pin && integerBE (slice 6 2 payload)==toInteger(B.length payload-8))
  _<-appendBudget state (fromInteger parent) (fromIntegral kind)
  pure (B.singleton 3<>slice 65 16 state<>slice 33 32 state<>
    slice 177 16 bytes<>slice 145 32 bytes<>slice 193 4 bytes<>
    B.singleton 3<>pin<>B.singleton kind<>B.drop 40 payload)

appendBudget :: B.ByteString -> Word64 -> Word64 -> Maybe [Word64]
appendBudget state parent kind = validate (ForcedV3Append
  [readAt 65 8,readAt 73 8,readAt 113 8,readAt 121 8,readAt 129 8,
   readAt 137 4,readAt 141 4,parent,kind])
  where readAt offset width=fromInteger(integerBE(slice offset width state))

-- State145, cryptographically computed next root32, authenticated parent8,kind1.
nextState :: B.ByteString -> Maybe B.ByteString
nextState bytes = do
  guard (B.length bytes==186)
  let state=B.take 145 bytes; pin=slice 1 32 state; root=slice 145 32 bytes
      parent=fromInteger(integerBE(slice 177 8 bytes));kind=fromIntegral(B.index bytes 185)
  guard (validate (ForcedV3State pin state) && nonzeroHash root)
  fields<-appendBudget state parent kind
  case fields of
    [hi,lo,count,work] -> pure (B.take 33 state<>root<>wordBE 8 hi<>wordBE 8 lo<>
      slice 81 48 state<>wordBE 8 parent<>wordBE 4 count<>wordBE 4 work)
    _ -> Nothing

-- Classify only a bounded script prefix, including nonminimal push forms.
-- The full strict parser subsequently rejects malformed reserved markers.
markerKind :: B.ByteString -> Word8
markerKind bytes
  | B.length bytes<2 || B.head bytes/=106 = 0
  | otherwise = case offset of
      Just n | slice n 4 bytes==B.pack [69,67,88,70] -> 1
             | slice n 4 bytes==B.pack [69,67,88,67] -> 2
      _ -> 0
  where offset=case B.index bytes 1 of
          n | n<=75 -> Just 2
          76 -> Just 3
          77 -> Just 4
          78 -> Just 6
          _ -> Nothing

-- expected txid32, actual txid32, exact cursor24, marker count8, full script.
-- Zero expected txid means a carry block, which must contain no cursor marker.
cursorBinding :: B.ByteString -> Maybe B.ByteString
cursorBinding bytes = do
  guard (B.length bytes>=96 && B.length bytes<=4204)
  let expected=B.take 32 bytes;actual=slice 32 32 bytes
      fields=slice 64 24 bytes;count=integerBE(slice 88 8 bytes);script=B.drop 96 bytes
  if not(nonzeroHash expected)
    then guard (expected==B.replicate 32 0 && count==0 && B.null script && actual==expected)
    else do
      guard (count==1 && actual==expected)
      _<-validate (ForcedV3Cursor script)
      guard (B.drop 7 script==fields)
  pure (B.singleton 1)

-- These projections are observations, not proof receipts. The host still owns
-- VerifiedCustodySource and selects whether a caller may supply consumption.
data SourceContext = SourceContext
  { sourceHeadersValid :: Bool, sourceHeight :: Word64, sourceParent :: Word64
  , sourceDepositCursor :: Word64, sourceHasReceipt :: Bool, sourceCustodyOnly :: Bool }
  deriving (Eq,Show)
data SourceConsumption = SourceConsumption B.ByteString B.ByteString B.ByteString
  deriving (Eq,Show)
data SourceHash = ConfigurationHash | EntryHash | StepHash deriving (Enum,Eq,Show)

class BlockOutputs op where
  blockTransactions :: op -> IO Word64
  transactionOutputs :: op -> Word64 -> IO Word64
  selectBlockOutput :: op -> Word64 -> Word64 -> IO ()
  selectedMarker :: op -> IO Word8
  selectedCursorProfile :: op -> IO Bool
  selectedTransaction :: op -> IO B.ByteString
  selectedScript :: op -> IO B.ByteString
  selectedAdmission :: op -> IO (Maybe (B.ByteString,B.ByteString))
  expectedCursor :: op -> IO B.ByteString

  -- Preserve transaction/output order and stop at the first rejected step.
  foldBlockOutputs :: op -> a -> (a -> Word64 -> SourceFlow a) -> SourceFlow a
  foldBlockOutputs value initial step = do
    count <- liftIO (blockTransactions value)
    let transactions tx state
          | tx==count = pure state
          | otherwise = do
              outputs <- liftIO (transactionOutputs value tx)
              let scan output accumulated
                    | output==outputs = pure accumulated
                    | otherwise = do
                        liftIO (selectBlockOutput value tx output)
                        next <- step accumulated output
                        scan (output+1) next
              next <- scan 0 state
              transactions (tx+1) next
    transactions 0 initial

class SourceFacts op where
  sourceHeaderPresent :: op -> Bool -> IO Bool
  sourceHeaderFacts :: op -> IO SourceContext
  sourceConfiguration :: op -> IO B.ByteString
  sourcePin :: op -> IO B.ByteString
  sourceAsset :: op -> IO B.ByteString
  sourcePrevious :: op -> IO B.ByteString
  sourceConsumption :: op -> IO (Maybe SourceConsumption)

class SourceEffects op where
  sourceHash :: op -> SourceHash -> B.ByteString -> IO B.ByteString
  sourceDiagnostic :: op -> String -> IO ()
  publishSource :: op -> B.ByteString -> IO ()

type SourceFlow = ExceptT (Maybe String) IO

requireSource :: Bool -> String -> SourceFlow ()
requireSource ok message = when (not ok) (throwE (Just message))

needSource :: Maybe a -> String -> SourceFlow a
needSource value message = maybe (throwE (Just message)) pure value

checkBlockCursor :: BlockOutputs op => op -> B.ByteString -> SourceFlow ()
checkBlockCursor value expected = do
  (count,actual,script) <- foldBlockOutputs value (0,B.replicate 32 0,B.empty) $ \state@(count,firstTransaction,firstScript) _ -> do
    marker <- liftIO (selectedMarker value)
    if marker/=2 then pure state else do
      valid <- liftIO (selectedCursorProfile value)
      requireSource valid "ECXCv3 output profile is invalid"
      if count/=0 then pure (2,firstTransaction,firstScript) else do
        actual <- liftIO (selectedTransaction value)
        script <- liftIO (selectedScript value)
        pure (1,actual,script)
  _ <- needSource (cursorBinding (B.take 32 expected<>actual<>B.drop 32 expected<>wordBE 8 count<>script))
    "ECXCv3 requires one exact full-width marker in its actual transition transaction, or none on carry"
  pure ()

appendBlockSource :: (BlockOutputs op,SourceFacts op,SourceEffects op) => op -> SourceFlow ()
appendBlockSource value = do
  let headerError = "ECXFv3 carry requires exact prior header/height/parent and unchanged singleton; consumption needs a verified fresh receipt"
      economicsError = "ECXFv3 carry economics or collateral asset differs from pinned configuration"
  present <- liftIO (sourceHeaderPresent value False)
  requireSource present headerError
  priorPresent <- liftIO (sourceHeaderPresent value True)
  requireSource priorPresent headerError
  context <- liftIO (sourceHeaderFacts value)
  requireSource (sourceHeadersValid context) headerError
  economics <- liftIO (sourceConfiguration value)
  configHash <- liftIO (sourceHash value ConfigurationHash economics)
  pin <- liftIO (sourcePin value)
  requireSource (configHash==pin) economicsError
  asset <- liftIO (sourceAsset value)
  requireSource (asset==slice 50 32 economics) economicsError
  previous <- liftIO (sourcePrevious value)
  requireSource (validate (ForcedV3State pin previous)) "ECXFv3 previous header state is invalid"
  (initial,expected) <- if not (sourceHasReceipt context)
    then pure (previous,B.replicate 56 0)
    else do
      receipt <- liftIO (sourceConsumption value)
      case receipt of
        Nothing -> liftIO (ioError (userError "missing native source consumption"))
        Just (SourceConsumption transaction root cursor) -> do
          let next = B.take 81 previous<>root<>cursor<>B.drop 129 previous
          requireSource (validate (ForcedV3State pin next)) "verified custody cursor is outside the authenticated source state"
          pure (next,transaction<>cursor<>wordBE 8 (sourceDepositCursor context))
  checkBlockCursor value expected
  (next,_) <- foldBlockOutputs value (initial,Set.empty) $ \current@(state,locators) output -> do
    marker <- liftIO (selectedMarker value)
    if marker/=1 then pure current else do
      requireSource (output<=fromIntegral (maxBound :: Word32)) "ECXFv3 output index overflow"
      action <- liftIO (selectedAdmission value)
      -- The shared admission workflow has already published its exact error.
      (payload,metadata) <- maybe (throwE Nothing) pure action
      let kind = B.index metadata 1
      requireSource (not (sourceCustodyOnly context) || Custody.forcedKindAllowed kind)
        "fresh exact-custody profile cannot execute this forced action class"
      txid <- liftIO (selectedTransaction value)
      let locator = (txid,output)
      requireSource (Set.notMember locator locators) "duplicate ECXFv3 source locator"
      entry <- needSource (entryBytes (state<>txid<>wordBE 8 (sourceHeight context)<>
        wordBE 8 (sourceParent context)<>wordBE 4 output<>payload))
        "ECXFv3 source entry or persistent admission budget is invalid"
      entryHash <- liftIO (sourceHash value EntryHash entry)
      root <- liftIO (sourceHash value StepHash (slice 33 48 state<>entryHash))
      updated <- needSource (nextState (state<>root<>wordBE 8 (sourceParent context)<>B.singleton kind))
        "ECXFv3 source state update rejected"
      pure (updated,Set.insert locator locators)
  liftIO (publishSource value next)

runSourceFlow :: SourceEffects op => op -> SourceFlow () -> IO Bool
runSourceFlow value flow = runExceptT flow >>= either
  (\message -> maybe (pure ()) (sourceDiagnostic value) message >> pure False) (const (pure True))

newtype ForcedBlockSession = ForcedBlockSession NativeBytes

blockRead :: ForcedBlockSession -> Word32 -> Word64 -> B.ByteString -> IO B.ByteString
blockRead (ForcedBlockSession native) = native

blockField :: ForcedBlockSession -> Word32 -> Int -> IO B.ByteString
blockField value step size = blockRead value step 0 B.empty >>= exactBlockBytes size

exactBlockBytes :: Int -> B.ByteString -> IO B.ByteString
exactBlockBytes size bytes
  | B.length bytes==size = pure bytes
  | otherwise = ioError (userError "invalid source projection length")

blockBool :: ForcedBlockSession -> Word32 -> IO Bool
blockBool value step = blockRead value step 0 B.empty >>= \bytes -> case B.unpack bytes of
  [0] -> pure False
  [1] -> pure True
  _ -> ioError (userError "invalid source boolean")

blockEffect :: ForcedBlockSession -> Word32 -> Word64 -> B.ByteString -> IO ()
blockEffect value step index input = do
  result <- blockRead value step index input
  when (result/=B.singleton 1) (ioError (userError "source effect failed"))

instance BlockOutputs ForcedBlockSession where
  blockTransactions value = fromInteger . integerBE <$> blockField value 200 8
  transactionOutputs value index = fromInteger . integerBE <$>
    (blockRead value 201 index B.empty >>= exactBlockBytes 8)
  selectBlockOutput value index output = blockEffect value 202 index (wordBE 8 output)
  selectedMarker value = markerKind <$> blockRead value 203 0 B.empty
  selectedCursorProfile value = (==0) <$> validate (Exchange.OutputProfile False
    (\field -> blockBool value ([2,14,4,5,6,7]!!field)))
  selectedTransaction value = blockField value 205 32
  selectedScript value = blockRead value 204 0 B.empty
  selectedAdmission (ForcedBlockSession native) = Exchange.checkForcedOutput True (Exchange.ForcedOutputSession native)
  expectedCursor value = blockField value 206 56

instance SourceFacts ForcedBlockSession where
  sourceHeaderPresent value prior = blockBool value (if prior then 101 else 100)
  sourceHeaderFacts value = do
    bytes <- blockField value 102 138
    when (any (>1) (B.unpack (B.drop 136 bytes))) (ioError (userError "invalid source flags"))
    let n offset = fromInteger (integerBE (slice offset 8 bytes)) :: Word64
        receipt = B.index bytes 136==1
        valid = n 0<0x8000000000000000 && n 8==n 0+1 &&
          n 16/=0 && n 16>=n 24 && n 16==n 32 && n 40==n 48 && n 56==n 64 &&
          nonzeroHash (slice 72 32 bytes) && (receipt || slice 72 32 bytes==slice 104 32 bytes)
    pure (SourceContext valid (n 8) (n 16) (n 48) receipt (B.index bytes 137==1))
  sourceConfiguration value = blockField value 103 259
  sourcePin value = blockField value 104 32
  sourceAsset value = blockField value 105 32
  sourcePrevious value = blockField value 106 145
  sourceConsumption value = do
    bytes <- blockField value 107 80
    pure (Just (SourceConsumption (B.take 32 bytes) (slice 32 32 bytes) (B.drop 64 bytes)))

instance SourceEffects ForcedBlockSession where
  sourceHash value kind bytes = blockRead value 208 (fromIntegral (fromEnum kind)) bytes >>= exactBlockBytes 32
  sourceDiagnostic value = blockEffect value 13 0 . C.pack
  publishSource value = blockEffect value 207 0

type ForcedBlockCapabilities = '[BlockOutputs,SourceFacts,SourceEffects]
instance Operation ForcedBlockSession ForcedBlockCapabilities where
  type Context ForcedBlockSession = CapabilityContext ForcedBlockCapabilities ForcedBlockSession
  type Outcome ForcedBlockSession = IO Bool
  data DSL ForcedBlockSession where
    CheckBlockCursor :: Context ForcedBlockSession => DSL ForcedBlockSession
    AppendBlockSource :: Context ForcedBlockSession => DSL ForcedBlockSession
  interpret operation request = withOperation @ForcedBlockSession operation $ \value -> case request of
    CheckBlockCursor -> Just (runSourceFlow value (liftIO (expectedCursor value) >>= checkBlockCursor value))
    AppendBlockSource -> Just (runSourceFlow value (appendBlockSource value))
