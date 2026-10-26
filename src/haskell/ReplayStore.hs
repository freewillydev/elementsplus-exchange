{-# LANGUAGE DataKinds, FlexibleContexts, FlexibleInstances, GADTs #-}
{-# LANGUAGE MultiParamTypeClasses, TypeApplications, TypeFamilies #-}
-- Copyright (c) 2026 The Elements Core developers
-- Distributed under the MIT software license.
module ReplayStore where

import BmmConstants (depositAddressLimit, replayConstants)
import CapabilityContext (CapabilityContext)
import Control.Exception (Exception, SomeException, evaluate, fromException, throwIO, try)
import Control.Monad (foldM, replicateM, unless, when)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Except (ExceptT, runExceptT, throwE)
import Control.Operation
import qualified Data.Binary.Get as G
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import qualified Data.ByteString.Lazy as L
import Data.Int (Int32, Int64)
import qualified Data.Map.Strict as M
import qualified Data.Set as S
import Data.Word (Word8, Word16, Word32, Word64)
import Workflow (NativeBytes)

-- Existing native SERIALIZE_METHODS encodings, not a new disk format.
type Hash = B.ByteString
data Slot = Slot Hash [(Hash,Word32,Word32)] [(Hash,Word32,Word16)]
  (Maybe B.ByteString) Int64 deriving (Eq, Show)
data Tip = Tip Word32 Hash Bool Word32 Hash Slot [(Word8,Slot)]
  [(Word8,Word8,Hash)] B.ByteString deriving (Eq, Show)
data Deposit = Deposit B.ByteString Hash Word32 Int64 B.ByteString deriving (Eq, Show)
data Edge = Edge Hash Word32 Word32 Bool Hash deriving (Eq, Show)
data Paid = Paid Word8 Hash Word32 Hash deriving (Eq, Show)

decode :: G.Get a -> B.ByteString -> Either Int32 a
decode parser bytes = case G.runGetOrFail (parser <* end) (L.fromStrict bytes) of
  Right (_,_,value) -> Right value
  Left _ -> Left (-1)
  where end = G.isEmpty >>= \empty -> unless empty (fail "trailing replay record")

flag :: G.Get Bool
flag = G.getWord8 >>= \value -> case value of
  0 -> pure False
  1 -> pure True
  _ -> fail "invalid replay flag"

compact :: G.Get Word64
compact = G.getWord8 >>= \tag -> case tag of
  253 -> canonical 253 (fromIntegral <$> G.getWord16le)
  254 -> canonical 65536 (fromIntegral <$> G.getWord32le)
  255 -> canonical 4294967296 G.getWord64le
  _ -> pure (fromIntegral tag)
  where canonical minimumValue parser = parser >>= \value ->
          if value < minimumValue then fail "noncanonical replay size" else pure value

-- Check available bytes before allocating a count-controlled list.
counted :: Int64 -> G.Get a -> G.Get [a]
counted width parser = do
  count <- compact
  available <- L.length <$> G.lookAhead G.getRemainingLazyByteString
  when (width <= 0 || toInteger count > div (toInteger available) (toInteger width) ||
        toInteger count > toInteger (maxBound :: Int)) (fail "oversized replay collection")
  replicateM (fromIntegral count) parser

hash :: G.Get Hash
hash = G.getByteString 32
optional :: G.Get a -> G.Get (Maybe a)
optional parser = flag >>= \present -> if present then Just <$> parser else pure Nothing
depositRecord :: G.Get Deposit
depositRecord = Deposit <$> G.getByteString 36 <*> hash <*> G.getWord32le <*> G.getInt64le
  <*> (B.pack <$> counted 1 G.getWord8)
edgeRecord :: G.Get Edge
edgeRecord = Edge <$> hash <*> G.getWord32le <*> G.getWord32le <*> flag <*> hash
paidRecord :: G.Get Paid
paidRecord = Paid <$> G.getWord8 <*> hash <*> G.getWord32le <*> hash

saneDeposit :: Word64 -> Deposit -> Bool
saneDeposit maximumMoney (Deposit out block _ value address) =
  nonzero (B.take 32 out) && decode G.getWord32le (B.drop 32 out) /= Right maxBound &&
  nonzero block && value > 0 && toInteger value <= toInteger maximumMoney &&
  not (B.null address) && B.length address <= fromIntegral depositAddressLimit
saneEdge :: Hash -> Edge -> Bool
saneEdge parent (Edge successor height nextHeight committed critical) =
  nonzero parent && nonzero successor && height < maxBound && nextHeight == height+1 &&
  (not committed || nonzero critical)
proposals :: G.Get [(Hash,Word32,Word32)]
proposals = counted 40 ((,,) <$> hash <*> G.getWord32le <*> G.getWord32le)
withdrawals :: G.Get [(Hash,Word32,Word16)]
withdrawals = counted 38 ((,,) <$> hash <*> G.getWord32le <*> G.getWord16le)
treasury :: G.Get (Maybe B.ByteString)
treasury = flag >>= \present -> if present then Just <$> G.getByteString 36 else pure Nothing
slot :: G.Get Slot
slot = Slot <$> hash <*> proposals <*> withdrawals <*> treasury <*> G.getInt64le

tip :: G.Get Tip
tip = do
  height <- G.getWord32le
  block <- hash
  stateBytes <- L.toStrict <$> G.lookAhead G.getRemainingLazyByteString
  active <- hash
  activated <- flag
  activationHeight <- G.getWord32le
  activationBlock <- hash
  configured <- Slot active <$> proposals <*> withdrawals <*> treasury <*> G.getInt64le
  others <- counted 44 ((,) <$> G.getWord8 <*> slot)
  actions <- counted 34 ((,,) <$> G.getWord8 <*> G.getWord8 <*> hash)
  pure (Tip height block activated activationHeight activationBlock configured others actions stateBytes)

nonzero :: B.ByteString -> Bool
nonzero = B.any (/=0)

saneTip :: Word64 -> Tip -> Bool
saneTip maximumMoney (Tip height block activated activationHeight activationBlock configured others actions _) =
  nonzero block && activation && saneSlot configured &&
  all (saneSlot . snd) others && unique ctips && validActions False actions
  where
    activeOf (Slot active _ _ _ _) = nonzero active
    activation = if activated then activeOf configured && nonzero activationBlock && activationHeight <= height
                 else activationHeight == 0 && not (nonzero activationBlock)
    saneSlot (Slot active pending bundles ctip value) =
      maybe (value == 0) (const (nonzero active)) ctip &&
      value >= 0 && toInteger value <= toInteger maximumMoney &&
      all (\(key,h,v) -> nonzero key && h <= height && toInteger v <= toInteger height-toInteger h) pending &&
      all (\(_,h,v) -> h <= height && toInteger v <= toInteger height-toInteger h+2) bundles &&
      unique [key | (key,_,_) <- bundles] && (nonzero active || null bundles)
    ctips = [out | Slot _ _ _ (Just out) _ <- configured : map snd others]
    otherSlots = M.fromList others
    validActions _ [] = True
    validActions used ((key,kind,m6):rest) =
      (kind == 1 || (kind == 2 && not (nonzero m6))) &&
      case M.lookup key otherSlots of
        Just value -> activeOf value && validActions used rest
        Nothing -> not used && activeOf configured && validActions True rest
    unique xs = S.size (S.fromList xs) == length xs

-- Private process-local effect tags; old domain selectors remain reserved.
data Effect = Open | Previous | Next | IdentityExists | IdentityRead | TipExists | TipRead
  | HashState | Shape | DepositRead | DepositExists | EdgeRead | EdgeExists
  | WithdrawalRead | WithdrawalExists | OccurrenceExists | ProposalRead | ProposalExists
  | BeginBatch | WriteDeposit | WriteEdge | WriteWithdrawal | WriteOccurrence | WriteTip
  | CommitBatch | Report | QueryKey | RecordExists | RecordRead
  | ScanClear | ScanOpen | ScanValid | ScanPrefix | ScanKey | ScanRead
  | ScanPush | ScanNext | ScanCursor | ScanFinish
  | ClearError | ReleaseStore | ReopenStore | WriteIdentity deriving (Eq, Show, Enum, Bounded)

data Store = Store Word64 NativeBytes
class ReplayRecords op where
  checkReplayTip :: op -> IO Int32
class ReplayAdmission op where
  admitReplayAppend :: op -> ExceptT Int32 IO AppendPlan
class ReplayCommit op where
  commitReplayAppend :: op -> AppendPlan -> ExceptT Int32 IO ()
class ReplayLookup op where
  lookupReplay :: op -> RecordKind -> ExceptT Int32 IO ()
class ReplayScan op where
  scanReplayDeposits :: op -> ExceptT Int32 IO ()
class ReplayLoad op where
  loadReplayStore :: op -> ExceptT Int32 IO Int32
class ReplayReset op where
  resetReplayStore :: op -> ExceptT Int32 IO ()

data RecordKind = DepositRecord | EdgeRecord | WithdrawalRecord | OccurrenceRecord deriving (Eq, Show)

data AppendPlan = AppendPlan Word64 Bool Word64 Bool deriving (Eq, Show)

indices :: Word64 -> [Word64]
indices count = if count == 0 then [] else [0..count-1]
request :: NativeBytes -> Effect -> Word64 -> B.ByteString -> ExceptT Int32 IO B.ByteString
request native command index = liftIO . native (fromIntegral (fromEnum command)) index
readValue :: NativeBytes -> Effect -> Word64 -> G.Get a -> ExceptT Int32 IO a
readValue native command index parser = request native command index B.empty >>= either throwE pure . decode parser
effect :: NativeBytes -> Effect -> Word64 -> B.ByteString -> ExceptT Int32 IO ()
effect native command index bytes = request native command index bytes >>= \reply ->
  unless (B.null reply) (throwE (-1))
report :: NativeBytes -> String -> ExceptT Int32 IO ()
report native message = effect native Report 0 (C.pack message)
require :: NativeBytes -> String -> Bool -> ExceptT Int32 IO ()
require native message accepted = unless accepted (report native message >> throwE 0)
exists :: NativeBytes -> Effect -> Word64 -> ExceptT Int32 IO Bool
exists native command index = readValue native command index flag
record :: NativeBytes -> Effect -> Effect -> String -> ExceptT Int32 IO (Maybe B.ByteString)
record native present readRecord description = do
  found <- exists native present 0
  if not found then pure Nothing else do
    bytes <- request native readRecord 0 B.empty
    case B.uncons bytes of
      Just (1,body) -> pure (Just body)
      Just (0,body) | B.null body -> report native ("persistent parent replay " ++ description ++ " record is malformed") >> pure Nothing
      _ -> throwE (-1)

schemaConstant :: String -> Word32
schemaConstant name = fromIntegral (head [value | (_,key,value) <- replayConstants, key == name])

-- The read status distinguishes missing data from corruption; append uses a
-- boolean result. Both keep the original native diagnostics and effect order.
requireRead :: NativeBytes -> String -> Bool -> ExceptT Int32 IO ()
requireRead native message accepted = unless accepted (report native message >> throwE 2)

-- Loading must distinguish an absent record from a failed native decode.
-- A malformed tip keeps its decode diagnostic, unlike a missing/invalid tip.
loadRecord :: NativeBytes -> Effect -> Effect -> String -> G.Get a -> ExceptT Int32 IO (Maybe a)
loadRecord native present readRecord description parser = do
  found <- exists native present 0
  if not found then pure Nothing else do
    value <- readValue native readRecord 0 (optional parser)
    case value of
      Just _ -> pure value
      Nothing -> do
        report native ("persistent parent replay " ++ description ++ " record is malformed")
        throwE 2

instance ReplayLoad Store where
  loadReplayStore (Store maximumMoney native) = do
    effect native ClearError 0 B.empty
    exists native Open 0 >>= requireRead native "persistent parent replay database is not open"
    identity <- loadRecord native IdentityExists IdentityRead "identity" ((,) <$> G.getWord32le <*> hash)
    case identity of
      Nothing -> do
        exists native TipExists 0 >>= requireRead native "persistent parent replay has a tip but no identity" . not
        pure 0
      Just (storedSchema, storedIdentity) -> do
        schema <- readValue native Shape 0 G.getWord32le
        matching (storedSchema == schema)
        wanted <- readValue native QueryKey 0 hash
        matching (storedIdentity == wanted)
        stored <- loadRecord native TipExists TipRead "tip" tip
        requireRead native "persistent parent replay tip is missing or internally inconsistent"
          (maybe False (saneTip maximumMoney) stored)
        pure 1
    where
      matching accepted = unless accepted $ do
        report native "persistent parent replay schema or immutable network identity does not match"
        throwE 3

instance ReplayReset Store where
  resetReplayStore (Store maximumMoney native) = do
    seed <- readValue native Previous 0 tip
    require native "refusing to seed persistent parent replay with an invalid tip" (saneTip maximumMoney seed)
    mapM_ (\command -> effect native command 0 B.empty)
      [ReleaseStore, ReopenStore, WriteIdentity, WriteTip]
    exists native CommitBatch 0 >>= require native "failed to atomically seed persistent parent replay"

recordNames :: RecordKind -> (String,String)
recordNames kind = case kind of
  DepositRecord -> ("deposit","deposit record")
  EdgeRecord -> ("BMM edge","BMM edge")
  WithdrawalRecord -> ("successful withdrawal","successful-withdrawal record")
  OccurrenceRecord -> ("withdrawal occurrence","withdrawal occurrence")

matchesRecord :: Word64 -> RecordKind -> B.ByteString -> Either Int32 (B.ByteString -> Either Int32 Bool)
matchesRecord maximumMoney kind bytes = case kind of
  DepositRecord -> do
    value@(Deposit out _ _ _ _) <- decode depositRecord bytes
    pure $ \key -> do
      wanted <- decode (G.getByteString 36) key
      pure (saneDeposit maximumMoney value && out == wanted)
  EdgeRecord -> do
    value <- decode edgeRecord bytes
    pure $ \key -> (`saneEdge` value) <$> decode hash key
  _ -> do
    Paid actualSlot actualM6 actualHeight block <- decode paidRecord bytes
    pure $ \key -> do
      (slotId,m6,height) <- decode ((,,) <$> G.getWord8 <*> hash <*>
        (if kind == OccurrenceRecord then Just <$> G.getWord32le else pure Nothing)) key
      pure (nonzero block && actualSlot == slotId && actualM6 == m6 && maybe True (==actualHeight) height)

instance ReplayLookup Store where
  lookupReplay (Store maximumMoney native) kind = do
    opened <- exists native Open 0
    admitted <- if opened && kind == OccurrenceRecord
      then (==schemaConstant "REPLAY_REPROPOSAL_SCHEMA") <$> readValue native Shape 0 G.getWord32le
      else pure opened
    requireRead native (if kind == OccurrenceRecord
      then "withdrawal occurrence lookup requires the re-proposal replay schema"
      else "persistent parent replay database is not open") admitted
    found <- exists native RecordExists 0
    unless found (throwE 1)
    bytes <- request native RecordRead 0 B.empty
    let (description,inconsistent) = recordNames kind
    body <- case B.uncons bytes of
      Just (1,value) -> pure value
      Just (0,value) | B.null value -> do
        report native ("persistent parent replay " ++ description ++ " record is malformed")
        throwE 2
      _ -> throwE (-1)
    matches <- either throwE pure (matchesRecord maximumMoney kind body)
    key <- request native QueryKey 0 B.empty
    accepted <- either throwE pure (matches key)
    requireRead native ("persistent parent replay " ++ inconsistent ++ " is internally inconsistent") accepted

instance ReplayScan Store where
  scanReplayDeposits (Store maximumMoney native) = do
    effect native ScanClear 0 B.empty
    limit <- readValue native Shape 1 G.getWord64le
    require native "invalid parent deposit scan limit or unopened index" (limit > 0 && limit <= 64)
    exists native Open 0 >>= require native "persistent parent replay database is not open"
    effect native ScanOpen 0 B.empty
    after <- readValue native QueryKey 0 (optional (G.getByteString 36))
    scan after limit 0
    effect native ScanFinish 0 B.empty
    where
      scan after limit count = do
        valid <- exists native ScanValid 0
        when valid $ do
          prefix <- readValue native ScanPrefix 0 (optional G.getWord8)
          require native "malformed parent replay key" (prefix /= Nothing)
          when (prefix == Just (fromIntegral (schemaConstant "DB_REPLAY_DEPOSIT"))) $ do
            key <- readValue native ScanKey 0 (optional (G.getByteString 36))
            require native "malformed parent deposit key" (key /= Nothing)
            if after /= Nothing && key == after
              then effect native ScanNext 0 B.empty >> scan after limit count
              else if count == limit then effect native ScanCursor 0 B.empty else do
                value <- readValue native ScanRead 0 (optional depositRecord)
                require native "malformed parent deposit scan record" (case value of
                  Just entry@(Deposit out _ _ _ _) -> saneDeposit maximumMoney entry && Just out == key
                  Nothing -> False)
                effect native ScanPush 0 B.empty
                effect native ScanNext 0 B.empty
                scan after limit (count+1)

instance ReplayRecords Store where
  checkReplayTip (Store maximumMoney native) = do
    bytes <- native (fromIntegral (fromEnum Previous)) 0 B.empty
    pure $ either id (\value -> if saneTip maximumMoney value then 1 else 0) (decode tip bytes)

instance ReplayAdmission Store where
  admitReplayAppend (Store maximumMoney native) = do
    opened <- exists native Open 0
    require native "persistent parent replay database is not open" opened
    previous@(Tip height block _ _ _ _ _ _ previousState) <- readValue native Previous 0 tip
    require native contiguous (saneTip maximumMoney previous)
    next@(Tip nextHeight nextBlock _ _ _ _ _ _ _) <- readValue native Next 0 tip
    require native contiguous (saneTip maximumMoney next && height < maxBound && nextHeight == height+1)
    identity <- record native IdentityExists IdentityRead "identity"
    storedSchema <- case identity of
      Nothing -> pure Nothing
      Just bytes -> Just <$> either throwE pure (decode (G.getWord32le <* hash) bytes)
    schema <- readValue native Shape 0 G.getWord32le
    require native "persistent parent replay append uses the wrong schema" (storedSchema == Just schema)
    stored <- record native TipExists TipRead "tip"
    case stored of
      Nothing -> require native changed False
      Just bytes -> do
        Tip storedHeight storedBlock _ _ _ _ _ _ storedState <- either throwE pure (decode tip bytes)
        require native changed (storedHeight == height && storedBlock == block)
        first <- request native HashState 0 storedState
        when (B.length first /= 32) (throwE (-1))
        second <- request native HashState 0 previousState
        when (B.length second /= 32) (throwE (-1))
        require native changed (first == second)
    (deposits,hasEdge,paid,proposed) <- readValue native Shape 1
      ((,,,) <$> G.getWord64le <*> flag <*> G.getWord64le <*> G.getWord64le)
    _ <- foldM (deposit nextHeight nextBlock) S.empty (indices deposits)
    when hasEdge $ do
      (parent,value@(Edge successor parentHeight successorHeight _ _)) <- readValue native EdgeRead 0
        ((,) <$> hash <*> edgeRecord)
      require native badEdge (saneEdge parent value &&
        parentHeight == height && successorHeight == nextHeight && successor == nextBlock && parent == block)
      exists native EdgeExists 0 >>= require native badEdge . not
    let uniqueSchema = schema == schemaConstant "REPLAY_UNIQUE_SCHEMA"
    _ <- foldM (withdrawal uniqueSchema nextHeight nextBlock) S.empty (indices paid)
    _ <- foldM (proposal uniqueSchema) S.empty (indices proposed)
    pure (AppendPlan deposits hasEdge paid (schema == schemaConstant "REPLAY_REPROPOSAL_SCHEMA"))
    where
      contiguous = "refusing a non-contiguous persistent parent replay append"
      changed = "persistent parent replay tip changed before append"
      badEdge = "persistent parent replay append contains a duplicate or malformed BMM edge"
      deposit nextHeight nextBlock seen index = do
        value@(Deposit out block height _ _) <- readValue native DepositRead index depositRecord
        let message = "persistent parent replay append contains a duplicate or malformed deposit"
        require native message (saneDeposit maximumMoney value && height == nextHeight && block == nextBlock &&
          S.notMember out seen)
        exists native DepositExists index >>= require native message . not
        pure (S.insert out seen)
      withdrawal uniqueSchema nextHeight nextBlock seen index = do
        Paid slotId m6 height block <- readValue native WithdrawalRead index paidRecord
        let key = (slotId,m6)
            message = "persistent parent replay append contains a duplicate or malformed successful withdrawal"
        require native message (nonzero block && height == nextHeight && block == nextBlock && S.notMember key seen)
        when uniqueSchema (exists native WithdrawalExists index >>= require native message . not)
        exists native OccurrenceExists index >>= require native message . not
        pure (S.insert key seen)
      proposal uniqueSchema seen index = do
        key <- readValue native ProposalRead index ((,) <$> G.getWord8 <*> hash)
        require native "persistent parent replay append contains a duplicate M3 proposal identity" (S.notMember key seen)
        when uniqueSchema $ exists native ProposalExists index >>=
          require native "M3 re-proposes a withdrawal that already succeeded on the active parent chain" . not
        pure (S.insert key seen)

instance ReplayCommit Store where
  commitReplayAppend (Store _ native) (AppendPlan deposits hasEdge paid reproposal) = do
    let write command index = effect native command index B.empty
    write BeginBatch 0
    mapM_ (write WriteDeposit) (indices deposits)
    when hasEdge (write WriteEdge 0)
    mapM_ (\index -> do
      found <- exists native WithdrawalExists index
      unless found (write WriteWithdrawal index)
      when reproposal (write WriteOccurrence index)) (indices paid)
    write WriteTip 0
    exists native CommitBatch 0 >>= require native "failed to atomically append persistent parent replay block"

appendReplay :: (ReplayAdmission op, ReplayCommit op) => op -> ExceptT Int32 IO ()
appendReplay value = admitReplayAppend value >>= commitReplayAppend value

data StoreSession = LoadSession | ResetSession | AppendSession | LookupSession RecordKind | ScanSession deriving (Eq, Show)
newtype StoreFailure = StoreFailure Int32 deriving Show
instance Exception StoreFailure

-- Recoverable native failures leave this subworkflow without poisoning the
-- enclosing ABI callback. Completion preserves the original native catch scope
-- for malformed Haskell replies too; preflight exceptions still escape it.
runStoreSession :: StoreSession -> Store -> IO Int32
runStoreSession kind (Store maximumMoney native) = do
  let checked step index input = do
        reply <- native step index input
        case B.uncons reply of
          Just (1,body) -> pure body
          Just (0,body) -> throwIO (StoreFailure (either id fromIntegral (decode G.getWord32le body)))
          _ -> throwIO (StoreFailure (-1))
      value = Store maximumMoney checked
      workflow = case kind of
        LoadSession -> loadReplayStore value
        ResetSession -> resetReplayStore value >> pure 1
        AppendSession -> appendReplay value >> pure 1
        LookupSession recordKind -> lookupReplay value recordKind >> pure 0
        ScanSession -> scanReplayDeposits value >> pure 1
  result <- try @SomeException (runExceptT workflow >>= evaluate . either id id)
  let status = case result of
        Right code -> code
        Left exception -> case fromException exception of
          Just (StoreFailure code) -> code
          Nothing -> -1
      maximumStatus = case kind of LoadSession -> 3; LookupSession _ -> 2; _ -> 1
      completion = if status < 0 || status > maximumStatus then 4 else fromIntegral status
  reply <- native 43 completion B.empty
  pure $ case decode ((,) <$> flag <*> G.getWord32le) reply of
    Right (_,code) | code <= fromIntegral maximumStatus -> fromIntegral code
    _ -> -1

type StoreCapabilities = '[ReplayRecords, ReplayAdmission, ReplayCommit, ReplayLookup, ReplayScan, ReplayLoad, ReplayReset]
instance Operation Store StoreCapabilities where
  type Context Store = CapabilityContext StoreCapabilities Store
  type Outcome Store = IO Int32
  data DSL Store where
    CheckTip :: Context Store => DSL Store
    AppendBlock :: Context Store => DSL Store
    LookupRecord :: Context Store => RecordKind -> DSL Store
    ListDeposits :: Context Store => DSL Store
    LoadStore :: Context Store => DSL Store
    ResetStore :: Context Store => DSL Store
    RunSession :: Context Store => StoreSession -> DSL Store
  interpret operation command = withOperation @Store operation $ \value ->
    case command of
      CheckTip -> Just (checkReplayTip value)
      AppendBlock -> Just (either id (const 1) <$> runExceptT (appendReplay value))
      LookupRecord kind -> Just (either id (const 0) <$> runExceptT (lookupReplay value kind))
      ListDeposits -> Just (either id (const 1) <$> runExceptT (scanReplayDeposits value))
      LoadStore -> Just (either id id <$> runExceptT (loadReplayStore value))
      ResetStore -> Just (either id (const 1) <$> runExceptT (resetReplayStore value))
      RunSession kind -> Just (runStoreSession kind value)
