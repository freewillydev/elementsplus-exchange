{-# LANGUAGE TypeFamilies, DataKinds, FlexibleContexts, FlexibleInstances #-}
{-# LANGUAGE GADTs, KindSignatures, MultiParamTypeClasses, TypeApplications #-}
{-# LANGUAGE ScopedTypeVariables, TypeOperators, UndecidableInstances #-}
-- Copyright (c) 2026 The Elements Core developers
-- Distributed under the MIT software license.
module ParentCache where

import Control.Operation.Validation
import Control.Operation
import CapabilityContext (CapabilityContext)
import Control.Exception (SomeException, evaluate, finally, try)
import Control.Monad (forM_, unless, when)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Except (ExceptT(..), runExceptT, throwE)
import qualified Data.Binary.Get as G
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.Int (Int32, Int64)
import Data.Kind (Type)
import Data.Typeable (Typeable)
import Data.Word (Word8, Word16, Word32, Word64)
import ParentReplay
import qualified ParentBlock as PB
import qualified ParentHeader as PH
import qualified ReplayStore as RS
import qualified Deposit as D
import qualified BmmConstants as Constants
import Workflow (NativeBytes, FoldOperation(..), Continue(..))

newtype CacheInitialization = CacheInitialization (Word32 -> IO Int64)

class CacheAdmission op where
  admitReplayCache :: op -> IO Int32
class CacheConfiguration op where
  configureReplayCache :: op -> IO Int32
class CacheStorage op where
  loadReplayCache :: op -> IO Int32
class CacheBootstrap op where
  rebuildReplayCache :: op -> IO Int32

cacheValue :: (Word32 -> IO Int64) -> Word32 -> IO Word64
cacheValue action step = do
  value <- action step
  if value < 0 || value > 4294967295 then ioError (userError "invalid replay cache field")
    else pure (fromIntegral value)

cacheRequired :: (Word32 -> IO Int64) -> Word32 -> IO ()
cacheRequired action step = action step >>= \result ->
  unless (result == 1) (ioError (userError "replay cache effect failed"))

cacheCompare :: Word32 -> (Word32 -> IO Int64) -> Word32 -> Word32 -> IO Int64
cacheCompare kind action left right = do
  first <- cacheValue action left
  second <- cacheValue action right
  pure (fromIntegral (validate (Record kind 0 0 first second)))

cacheSubworkflow :: Word32 -> Word32 -> Word32 -> (Word32 -> IO Int64) -> IO Int64
cacheSubworkflow kind offset end action = do
  status <- runStore kind (action . (offset+))
  unless (status == 1) (ioError (userError "replay cache subworkflow failed"))
  cacheRequired action end
  pure 1

instance CacheAdmission CacheInitialization where
  admitReplayCache (CacheInitialization action) = runStore 15 observe
    where
      observe step | step `elem` [8,9,11,12,14,15] =
        fromIntegral . (\value -> validate (Record 10 0 0 value 0)) <$> cacheValue action step
      observe 10 = cacheCompare 11 action 27 28
      observe 13 = cacheCompare 11 action 29 30
      observe 16 = cacheCompare 11 action 31 32
      observe step = action step
instance CacheConfiguration CacheInitialization where
  configureReplayCache (CacheInitialization action) = runStore 13 (action . (100+))
instance CacheStorage CacheInitialization where
  loadReplayCache (CacheInitialization action) = do
    cacheRequired action 200
    status <- runStore 16 observe
    -- Native scope cleanup precedes both successful return and bootstrap work.
    when (status >= 0) (cacheRequired action 250)
    pure status
    where
      observe 3 = cacheSubworkflow 12 600 639 action
      observe 9 = cacheCompare 4 action 225 209
      observe 15 = cacheCompare 11 action 215 226
      observe step = action (200+step)
instance CacheBootstrap CacheInitialization where
  rebuildReplayCache (CacheInitialization action) = runStore 18 observe
    where
      observe 4 = cacheRequired action 700 >> cacheSubworkflow 17 700 719 action
      observe step = action (300+step)

initializeReplayCache :: (CacheAdmission op, CacheConfiguration op, CacheStorage op, CacheBootstrap op)
  => op -> IO Int32
initializeReplayCache value = do
  admission <- admitReplayCache value
  case admission of
    0 -> pure 1
    2 -> pure 0
    1 -> do
      configured <- configureReplayCache value
      if configured /= 1 then pure (-1) else do
        loaded <- loadReplayCache value
        case loaded of
          0 -> rebuildReplayCache value
          1 -> pure 1
          _ -> pure (-1)
    _ -> pure (-1)

type CacheInitializationCapabilities = '[CacheAdmission, CacheConfiguration, CacheStorage, CacheBootstrap]
instance Operation CacheInitialization CacheInitializationCapabilities where
  type Context CacheInitialization = CapabilityContext CacheInitializationCapabilities CacheInitialization
  type Outcome CacheInitialization = IO Int32
  data DSL CacheInitialization where
    InitializeReplayCache :: Context CacheInitialization => DSL CacheInitialization
  interpret operation request = withOperation @CacheInitialization operation $ \value ->
    case request of
      InitializeReplayCache -> Just (initializeReplayCache value)

-- Launch checks consume one immutable native snapshot. Hashes and authenticated
-- reads remain native effects, requested only after their preceding checks pass.
newtype CacheStartup = CacheStartup NativeBytes
data LaunchIdentity = LaunchIdentity
  { launchKey :: CacheKey, launchDescription :: B.ByteString, launchManifest :: RS.Hash
  , launchActiveDescription :: B.ByteString, launchProposal :: (Word32,RS.Hash)
  , launchActivation :: (Word32,RS.Hash), launchHeight :: Word32, launchWork :: RS.Hash
  , launchTreasury :: (RS.Hash,Word32,Int64), launchGenesis :: RS.Hash
  , launchWithdrawals :: Bool, launchVersion :: Word32, launchMaximumMoney :: Word64
  } deriving (Eq, Show)

launchIdentity :: G.Get LaunchIdentity
launchIdentity = LaunchIdentity <$> cacheKey <*> vector <*> RS.hash <*> vector
  <*> point <*> point <*> G.getWord32le <*> RS.hash
  <*> ((,,) <$> RS.hash <*> G.getWord32le <*> G.getInt64le)
  <*> RS.hash <*> RS.flag <*> G.getWord32le <*> G.getWord64le
  where vector = B.pack <$> RS.counted 1 G.getWord8
        point = (,) <$> G.getWord32le <*> RS.hash

startupRead :: CacheStartup -> Word32 -> G.Get a -> ExceptT Int32 IO a
startupRead (CacheStartup native) step = readReplayReply native step 0
startupReject :: CacheStartup -> String -> ExceptT Int32 IO a
startupReject value = startupReport value 2
startupReport :: CacheStartup -> Int32 -> String -> ExceptT Int32 IO a
startupReport (CacheStartup native) code message = do
  reply <- liftIO (native 5 0 (C.pack message))
  unless (B.null reply) (throwE (-1))
  throwE code

checkLaunchCheckpoint :: CacheStartup -> LaunchIdentity -> ExceptT Int32 IO Bool
checkLaunchCheckpoint value config = do
  let CacheKey _ _ active _ _ _ = launchKey config
  checkCheckpoint (launchMaximumMoney config)
    (Checkpoint (launchActiveDescription config) active (launchProposal config)
      (launchActivation config) (launchHeight config) (launchTreasury config))
    (startupRead value 2 RS.hash)

data Checkpoint = Checkpoint B.ByteString RS.Hash (Word32,RS.Hash) (Word32,RS.Hash)
  Word32 (RS.Hash,Word32,Int64) deriving (Eq, Show)

getCheckpoint :: G.Get Checkpoint
getCheckpoint = Checkpoint <$> (B.pack <$> RS.counted 1 G.getWord8) <*> RS.hash
  <*> point <*> point <*> G.getWord32le
  <*> ((,,) <$> RS.hash <*> G.getWord32le <*> G.getInt64le)
  where point = (,) <$> G.getWord32le <*> RS.hash

checkCheckpoint :: Word64 -> Checkpoint -> ExceptT Int32 IO RS.Hash -> ExceptT Int32 IO Bool
checkCheckpoint maximumMoney (Checkpoint description active (proposalHeight,proposalHash)
    (activationHeight,activationHash) height (ctip,vout,amount)) readHash = do
  let
      empty = not . RS.nonzero
      inactive = B.null description && empty active &&
        proposalHeight == 0 && empty proposalHash && activationHeight == 0 && empty activationHash
      treasury = validate (Record 16 (if empty ctip then 1 else 0) amount
        (fromIntegral vout) maximumMoney) == 1
  if not treasury then pure False else if inactive then pure (empty ctip)
  else if B.null description || empty active then pure False else do
    actual <- readHash
    pure (actual == active && RS.nonzero proposalHash && RS.nonzero activationHash &&
      proposalHeight < activationHeight && activationHeight <= height)

-- Admission precedes the native lock/error scope used by confirmed lookups.
-- Immutable facts cross once; hashing remains a deferred native effect.
data DepositAdmission = DepositAdmission Word64 NativeBytes
class DepositEligibility op where
  checkDepositEligibility :: op -> ExceptT Int32 IO ()
class DepositIdentity op where
  checkDepositIdentity :: op -> ExceptT Int32 IO ()

depositEffect :: DepositAdmission -> Word32 -> B.ByteString -> ExceptT Int32 IO ()
depositEffect (DepositAdmission _ native) step input = do
  reply <- liftIO (native step 0 input)
  unless (B.null reply) (throwE (-1))

depositReject :: DepositAdmission -> Int32 -> String -> ExceptT Int32 IO a
depositReject value status message = depositEffect value 4 (C.pack message) >> throwE status

instance DepositEligibility DepositAdmission where
  checkDepositEligibility value@(DepositAdmission maximumMoney native) = do
    depositEffect value 0 B.empty
    (configured,slot,requested,amount,size) <- readReplayReply native 1 0
      ((,,,,) <$> RS.flag <*> G.getWord8 <*> G.getInt32le <*> G.getInt64le <*> G.getWord64le)
    unless configured $ depositReject value 1 "this network has no configured BIP300/301 sidechain slot"
    unless (validate (Record 23 1 (fromIntegral requested) (fromIntegral slot) 0) == 1) $
      depositReject value 1 ("drivechain sidechain slot must match configured slot " ++ show slot ++ ", got " ++ show requested)
    unless (validate (Record 1 7 amount size maximumMoney) == 1) $
      depositReject value 1 "invalid slot, amount, or address for drivechain deposit"

instance DepositIdentity DepositAdmission where
  checkDepositIdentity value@(DepositAdmission maximumMoney native) = do
    (proposal,manifest,state,work,anchor,windows,withdrawals,version,expectedVersion) <- readReplayReply native 2 0
      ((,,,,,,,,) <$> (do present <- RS.flag; h <- RS.hash; pure (if present then Just h else Nothing))
        <*> RS.hash <*> RS.hash <*> RS.hash <*> getCheckpoint
        <*> sequence (replicate 6 G.getWord16le) <*> RS.flag <*> G.getWord32le <*> G.getWord32le)
    let require valid = unless valid $ depositReject value 2
          "native deposits require a complete immutable parent genesis-replay identity"
    require (maybe False RS.nonzero proposal && all RS.nonzero [manifest,state,work])
    checkCheckpoint maximumMoney anchor (readReplayReply native 3 0 RS.hash) >>= require
    require (all (>0) windows && withdrawals && version == expectedVersion)

admitDeposit :: (DepositEligibility op, DepositIdentity op) => op -> IO Int32
admitDeposit value = either id (const 0) <$> runExceptT
  (checkDepositEligibility value >> checkDepositIdentity value)

type DepositAdmissionCapabilities = '[DepositEligibility, DepositIdentity]
instance Operation DepositAdmission DepositAdmissionCapabilities where
  type Context DepositAdmission = CapabilityContext DepositAdmissionCapabilities DepositAdmission
  type Outcome DepositAdmission = IO Int32
  data DSL DepositAdmission where
    AdmitDeposit :: Context DepositAdmission => DSL DepositAdmission
  interpret operation request = withOperation @DepositAdmission operation $ \value ->
    case request of
      AdmitDeposit -> Just (admitDeposit value)

-- The native lock encloses this entire fold. Intermediate values are copied
-- snapshots, not native references; only the final stage may authenticate RPC.
data ConfirmedDeposit (a :: Type) = ConfirmedDeposit Word64 NativeBytes
data ConfirmationView = ConfirmationView Word32 RS.Hash Word64 Word32 Word32 Bool Bool
  deriving (Eq, Show)
newtype ConfirmationEvidence = ConfirmationEvidence ConfirmationView deriving (Eq, Show)
type ConfirmationCheck = ExceptT Int32 IO

class ConfirmationSnapshot op where
  confirmationSnapshot :: op -> ConfirmationCheck ConfirmationView
class ConfirmationLookup op where
  confirmationLookup :: op -> ConfirmationView -> ConfirmationCheck ConfirmationEvidence
class ConfirmationFinality op where
  confirmationFinality :: op -> ConfirmationEvidence -> ConfirmationCheck ()

confirmationRead :: ConfirmedDeposit a -> Word32 -> G.Get b -> ConfirmationCheck b
confirmationRead (ConfirmedDeposit _ native) step = readReplayReply native step 0
confirmationEffect :: ConfirmedDeposit a -> Word32 -> Word64 -> B.ByteString -> ConfirmationCheck ()
confirmationEffect (ConfirmedDeposit _ native) step index bytes = do
  reply <- liftIO (native step index bytes)
  unless (B.null reply) (throwE (-1))
confirmationDo :: ConfirmedDeposit a -> Word32 -> ConfirmationCheck ()
confirmationDo value step = confirmationEffect value step 0 B.empty
confirmationReject :: ConfirmedDeposit a -> Int32 -> String -> ConfirmationCheck b
confirmationReject value code message = confirmationEffect value 15 0 (C.pack message) >> throwE code

instance ConfirmationSnapshot (ConfirmedDeposit a) where
  confirmationSnapshot value = do
    budget <- confirmationRead value 0 RS.flag
    if budget then do
      locked <- confirmationRead value 1 RS.flag
      unless locked (confirmationReject value 2 "authenticated parent replay cache is busy warming")
    else confirmationDo value 2
    (CacheSnapshot initialized actual height block activated active activationHeight,epoch) <-
      confirmationRead value 3 ((,) <$> cacheSnapshot <*> G.getWord64le)
    expected <- confirmationRead value 16 cacheKey
    let CacheKey _ proposal _ _ _ _ = actual
        unavailable = confirmationReject value 2 "authenticated parent replay cache is not warmed"
    unless (initialized && actual == expected && epoch /= 0) unavailable
    current <- confirmationRead value 18 G.getWord64le
    unless (epoch == current) unavailable
    bounded <- confirmationRead value 0 RS.flag
    target <- if bounded then confirmationRead value 4
      (RS.optional ((,,) <$> G.getWord32le <*> G.getWord64le <*> RS.flag)) else pure Nothing
    let (through,snapshotEpoch,explicit,standalone) = case target of
          Nothing -> (height,epoch,False,True)
          Just (h,e,x) -> (h,e,x,False)
    unless (snapshotEpoch == epoch) $
      confirmationReject value 2 "authenticated parent replay cache changed during validation"
    unless (activated && Just active == proposal && activationHeight <= through) $
      confirmationReject value 2 ("configured Elements slot proposal is not active at parent height " ++ show through)
    pure (ConfirmationView height block snapshotEpoch activationHeight through explicit standalone)

instance ConfirmationLookup (ConfirmedDeposit a) where
  confirmationLookup value@(ConfirmedDeposit maximumMoney native) view@(ConfirmationView _ _ _ activationHeight through explicit _) = do
    let reject = confirmationReject value (if explicit then 1 else 2)
    opened <- confirmationRead value 5 RS.flag
    unless opened (confirmationReject value 2 "persistent authenticated parent replay index is not open")
    confirmationDo value 6
    status <- liftIO $ RS.runStoreSession (RS.LookupSession RS.DepositRecord)
      (RS.Store maximumMoney (\step -> native (100+step)))
      `finally` (runExceptT (confirmationDo value 17) >>= either
        (const (ioError (userError "deposit lookup cleanup failed"))) pure)
    case status of
      0 -> pure ()
      1 -> reject (if explicit
        then "deposit is not a genesis-replay-derived canonical CTIP increase before the block's authenticated parent anchor"
        else "deposit is not present in the currently warmed parent replay snapshot")
      2 -> mapM_ (confirmationDo value) [10,11,12] >> throwE 2
      _ -> throwE (-1)
    (RS.Deposit _ block height amount address,expectedBlock,expectedAmount,expectedAddress) <-
      confirmationRead value 7 ((,,,) <$> RS.depositRecord <*> RS.hash <*> G.getInt64le
        <*> (B.pack <$> RS.counted 1 G.getWord8))
    unless (block == expectedBlock && amount == expectedAmount && address == expectedAddress) $
      reject "deposit does not exactly match the genesis-replay-derived canonical CTIP increase"
    unless (activationHeight <= height) $ reject
      ("native deposit at parent height " ++ show height ++ " predates Elements proposal activation at height " ++ show activationHeight)
    depth <- D.requiredConfirmationDepth <$> D.selectedConfirmationDepth False native 8
    unless (D.hasDepositDepth height through depth) $ reject
      ("deposit at parent height " ++ show height ++ " does not have " ++ show depth ++
        " confirmations through authenticated parent height " ++ show through)
    pure (ConfirmationEvidence view)

instance ConfirmationFinality (ConfirmedDeposit a) where
  confirmationFinality value@(ConfirmedDeposit _ native) (ConfirmationEvidence (ConfirmationView _ block epoch _ _ _ standalone)) = do
    when standalone $ do
      authenticated <- liftIO $ runExceptT (PH.authenticateActiveHash (PH.networkHeader (PH.offset 200 native)))
      either (throwE . (\status -> if status == 0 then 2 else status)) pure authenticated
      active <- confirmationRead value 9 (RS.optional RS.hash) >>= maybe (throwE 2) pure
      unless (active == block) $ do
        confirmationDo value 10
        confirmationReject value 2 "authenticated parent replay cache is stale after a parent reorganization"
      budget <- confirmationRead value 0 RS.flag
      when budget (confirmationDo value 13)
    confirmationEffect value 14 epoch B.empty

type ConfirmationCapabilities = '[ConfirmationSnapshot, ConfirmationLookup, ConfirmationFinality]
instance Typeable a => Operation (ConfirmedDeposit a) ConfirmationCapabilities where
  type Context (ConfirmedDeposit a) = CapabilityContext ConfirmationCapabilities (ConfirmedDeposit a)
  type Outcome (ConfirmedDeposit a) = ConfirmationCheck a
  data DSL (ConfirmedDeposit a) where
    ReadConfirmation :: Context (ConfirmedDeposit ConfirmationView) => DSL (ConfirmedDeposit ConfirmationView)
    MatchConfirmation :: Context (ConfirmedDeposit ConfirmationEvidence)
      => DSL (ConfirmedDeposit ConfirmationView) -> DSL (ConfirmedDeposit ConfirmationEvidence)
    AuthenticateConfirmation :: Context (ConfirmedDeposit ())
      => DSL (ConfirmedDeposit ConfirmationEvidence) -> DSL (ConfirmedDeposit ())
  interpret operation request = withOperation @(ConfirmedDeposit a) operation $ \value ->
    Just (foldOperation (ConfirmationAlgebra (confirmationSnapshot value)
      (>>= confirmationLookup value) (>>= confirmationFinality value)) request)

instance FoldOperation ConfirmedDeposit where
  data Algebra ConfirmedDeposit result = ConfirmationAlgebra
    (result ConfirmationView)
    (result ConfirmationView -> result ConfirmationEvidence)
    (result ConfirmationEvidence -> result ())
  foldOperation algebra@(ConfirmationAlgebra snapshot match authenticate) request = case request of
    ReadConfirmation -> snapshot
    MatchConfirmation child -> match (foldOperation algebra child)
    AuthenticateConfirmation child -> authenticate (foldOperation algebra child)

data ConfirmationReply = ConfirmationReply
instance (output ~ Outcome (ConfirmedDeposit a)) => Continue (ConfirmedDeposit a) output ConfirmationReply where
  type Continued (ConfirmedDeposit a) ConfirmationReply = IO Int32
  continue _ result = either id (const 0) <$> runExceptT result

data DepositCandidates (a :: Type) = DepositCandidates NativeBytes
data CandidateSnapshot = CandidateSnapshot Word32 Word32 deriving (Eq, Show)
newtype CandidatePage = CandidatePage CandidateSnapshot deriving (Eq, Show)

class CandidateAdmission op where
  candidateSnapshot :: op -> ExceptT Int32 IO CandidateSnapshot
class CandidateDiscovery op where
  candidatePage :: op -> CandidateSnapshot -> ExceptT Int32 IO CandidatePage
class CandidateSelection op where
  selectCandidates :: op -> CandidatePage -> ExceptT Int32 IO ()

candidateRead :: DepositCandidates a -> Word32 -> Word64 -> G.Get b -> ExceptT Int32 IO b
candidateRead (DepositCandidates native) = readReplayReply native
candidateEffect :: DepositCandidates a -> Word32 -> Word64 -> B.ByteString -> ExceptT Int32 IO ()
candidateEffect (DepositCandidates native) step index input = do
  reply <- liftIO (native step index input)
  unless (B.null reply) (throwE (-1))
candidateRequire :: DepositCandidates a -> String -> Bool -> ExceptT Int32 IO ()
candidateRequire value message accepted = unless accepted $
  candidateEffect value 11 0 (C.pack message) >> throwE 0

instance CandidateAdmission (DepositCandidates a) where
  candidateSnapshot value = do
    let available = candidateRequire value "authenticated parent deposit index is unavailable"
        readAt :: Word32 -> G.Get b -> ExceptT Int32 IO b
        readAt step = candidateRead value step 0
    readAt 0 RS.flag >>= available
    (CacheSnapshot initialized actual height _ activated active activation,epoch) <-
      readAt 1 ((,) <$> cacheSnapshot <*> G.getWord64le)
    available initialized
    expected <- readAt 2 cacheKey
    available (actual == expected)
    readAt 3 RS.flag >>= available
    available (epoch /= 0)
    readAt 4 G.getWord64le >>= available . (==epoch)
    let CacheKey _ proposal _ _ _ _ = actual
    candidateRequire value ("configured Elements slot proposal is not active at parent height " ++ show height)
      (activated && Just active == proposal && activation <= height)
    pure (CandidateSnapshot height activation)

instance CandidateDiscovery (DepositCandidates a) where
  candidatePage (DepositCandidates native) snapshot = do
    status <- replayStoreSession RS.ScanSession native 5 6 100 0
    unless (status == 1) (throwE (if status == 0 then 0 else -1))
    pure (CandidatePage snapshot)

instance CandidateSelection (DepositCandidates a) where
  selectCandidates value@(DepositCandidates native) (CandidatePage (CandidateSnapshot height activation)) = do
    depth <- D.requiredConfirmationDepth <$> D.selectedConfirmationDepth False native 7
    count <- candidateRead value 8 0 G.getWord64le
    unless (count <= 64) (throwE (-1))
    forM_ (RS.indices count) $ \index -> do
      deposited <- candidateRead value 9 index G.getWord32le
      when (deposited >= activation && D.hasDepositDepth deposited height depth) $
        candidateEffect value 10 index B.empty

type CandidateCapabilities = '[CandidateAdmission, CandidateDiscovery, CandidateSelection]
instance Typeable a => Operation (DepositCandidates a) CandidateCapabilities where
  type Context (DepositCandidates a) = CapabilityContext CandidateCapabilities (DepositCandidates a)
  type Outcome (DepositCandidates a) = ExceptT Int32 IO a
  data DSL (DepositCandidates a) where
    ReadCandidateSnapshot :: Context (DepositCandidates CandidateSnapshot) => DSL (DepositCandidates CandidateSnapshot)
    ScanCandidates :: Context (DepositCandidates CandidatePage)
      => DSL (DepositCandidates CandidateSnapshot) -> DSL (DepositCandidates CandidatePage)
    FilterCandidates :: Context (DepositCandidates ()) => DSL (DepositCandidates CandidatePage) -> DSL (DepositCandidates ())
  interpret operation request = withOperation @(DepositCandidates a) operation $ \value ->
    Just (foldOperation (CandidateAlgebra (candidateSnapshot value)
      (>>= candidatePage value) (>>= selectCandidates value)) request)

instance FoldOperation DepositCandidates where
  data Algebra DepositCandidates result = CandidateAlgebra
    (result CandidateSnapshot)
    (result CandidateSnapshot -> result CandidatePage)
    (result CandidatePage -> result ())
  foldOperation algebra@(CandidateAlgebra snapshot scan select) request = case request of
    ReadCandidateSnapshot -> snapshot
    ScanCandidates child -> scan (foldOperation algebra child)
    FilterCandidates child -> select (foldOperation algebra child)

data CandidateReply = CandidateReply
instance (output ~ Outcome (DepositCandidates a)) => Continue (DepositCandidates a) output CandidateReply where
  type Continued (DepositCandidates a) CandidateReply = IO Int32
  continue _ result = either id (const 1) <$> runExceptT result

instance CacheAdmission CacheStartup where
  admitReplayCache value = either id id <$> runExceptT (do
    config <- startupRead value 0 launchIdentity
    let CacheKey slot proposal _ checkpoint windows version = launchKey config
        invalid = startupReject value "native drivechain parent launch identity is incomplete or internally inconsistent"
        require valid = unless valid invalid
    case (slot,proposal) of
      (Just _,Just proposalHash) | RS.nonzero checkpoint -> do
        require (not (B.null (launchDescription config)) && RS.nonzero proposalHash)
        actual <- startupRead value 1 RS.hash
        require (actual == proposalHash && RS.nonzero (launchManifest config))
        checkLaunchCheckpoint value config >>= require
        require (RS.nonzero (launchWork config))
        require (case windows of
          [a,b,c,d,e,f] -> all (>0) windows && b<a && d<c && f<e
          _ -> False)
        require (launchWithdrawals config && version == launchVersion config)
        genesis <- startupRead value 3 (RS.optional RS.hash) >>= maybe (throwE 2) pure
        unless (genesis == launchGenesis config) $
          startupReject value "mainchain RPC does not serve the pinned parent genesis"
        (height,work) <- startupRead value 4 (RS.optional ((,) <$> G.getWord32le <*> RS.hash))
          >>= maybe (throwE 2) pure
        unless (height == launchHeight config && work == launchWork config) $
          startupReject value "authenticated parent launch checkpoint height or chainwork is not pinned value"
        pure 1
      _ -> pure 0)

startupLegacy :: CacheStartup -> CacheInitialization
startupLegacy (CacheStartup native) = CacheInitialization $ \step -> do
  result <- runExceptT (readReplayReply native 10 (fromIntegral step) G.getInt64le)
  either (const (ioError (userError "invalid cache initialization effect reply"))) pure result
instance CacheConfiguration CacheStartup where
  configureReplayCache = configureReplayCache . startupLegacy

startupScalar :: CacheStartup -> Word32 -> ExceptT Int32 IO Int64
startupScalar (CacheStartup native) step = readReplayReply native 10 (fromIntegral step) G.getInt64le
startupDo :: CacheStartup -> Word32 -> ExceptT Int32 IO ()
startupDo value step = startupScalar value step >>= \result -> unless (result == 1) (throwE (-1))
startupBool :: CacheStartup -> Word32 -> ExceptT Int32 IO Bool
startupBool value step = startupScalar value step >>= \result -> case result of
  0 -> pure False
  1 -> pure True
  _ -> throwE (-1)
startupSubworkflow :: CacheStartup -> Word32 -> Word32 -> Word32 -> ExceptT Int32 IO ()
startupSubworkflow value kind offset end = do
  let CacheInitialization action = startupLegacy value
  result <- liftIO (cacheSubworkflow kind offset end action)
  unless (result == 1) (throwE (-1))

data LoadedCache = LoadedCache Word32 B.ByteString RS.Hash RS.Hash Word32 RS.Hash Bool RS.Hash Word32 Bool
  deriving (Eq, Show)
loadedCache :: G.Get LoadedCache
loadedCache = LoadedCache <$> G.getWord32le <*> (B.pack <$> RS.counted 1 G.getWord8)
  <*> RS.hash <*> RS.hash <*> G.getWord32le <*> RS.hash <*> RS.flag <*> RS.hash <*> G.getWord32le <*> RS.flag
usableLoadedCache :: LoadedCache -> Bool
usableLoadedCache (LoadedCache checkpoint description ctip required height active activated activationBlock activationHeight hasCtip) =
  height < checkpoint || ((B.null description || RS.nonzero active) &&
    (not activated || (active == required && RS.nonzero activationBlock && activationHeight <= height)) &&
    (not (RS.nonzero ctip) || hasCtip))

replayStoreSession :: RS.StoreSession -> NativeBytes -> Word32 -> Word32 -> Word32 -> Word64 -> ExceptT Int32 IO Int32
replayStoreSession kind native open close offset index = do
  maximumMoney <- readReplayReply native open index G.getWord64le
  result <- liftIO $ RS.runStoreSession kind (RS.Store maximumMoney (\step -> native (offset+step)))
    `finally` (native close 0 B.empty >>= \reply -> unless (B.null reply)
      (ioError (userError "replay store cleanup failed")))
  if result < 0 then throwE (-1) else pure result

-- Decode one native-owned replay scope, compose its capabilities here, then
-- release temporaries before the caller publishes or persists the new state.
parentBlockSession :: NativeBytes -> Word32 -> Word32 -> Word32 -> Word64 -> ExceptT Int32 IO Bool
parentBlockSession native open close offset index = do
  let effects step = native (offset+step)
      block = PB.Block <$> G.getWord32le <*> G.getWord64le <*> G.getWord32le
        <*> G.getWord32le <*> G.getWord32le <*> G.getWord32le <*> pure effects
      run = do
        outcome <- try @SomeException $ do
          result <- runExceptT (readReplayReply native open index block >>= PB.replayBlock)
          evaluate $ case either id (const 0) result of
            0 -> 0
            1 -> 1
            -2 -> 3
            -3 -> 4
            -4 -> 5
            _ -> 2
        let completion = either (const 2) id outcome
        reply <- effects 20481 completion B.empty
        pure $ do
          accepted <- RS.decode RS.flag reply
          unless (completion <= 1 && accepted == (completion == 0)) (Left (-1))
          pure accepted
      closeScope = native close 0 B.empty >>= \reply -> unless (B.null reply)
        (ioError (userError "parent block cleanup failed"))
  result <- liftIO (run `finally` closeScope)
  either throwE pure result

instance CacheStorage CacheStartup where
  loadReplayCache value@(CacheStartup native) = do
    result <- runExceptT $ do
      startupDo value 200
      open <- startupBool value 201
      unless open (startupDo value 202)
      startupSubworkflow value 12 600 639
      forced <- startupBool value 204
      rebuild <- if forced then pure True else startupBool value 205
      if rebuild then pure 0 else do
        status <- replayStoreSession RS.LoadSession native 19 20 100 0
        case status of
          1 -> do
            current <- startupRead value 11 loadedCache
            if usableLoadedCache current then mapM_ (startupDo value) [218,219,220] >> pure 1
              else startupDo value 221 >> pure 0
          0 -> pure 0
          2 -> startupDo value 224 >> pure 0
          3 -> startupDo value 224 >> pure 0
          _ -> throwE (-1)
    case result of
      Left code -> pure code
      Right status -> either id (const status) <$> runExceptT (startupDo value 250)

bootstrapReject :: CacheStartup -> String -> ExceptT Int32 IO a
bootstrapReject value message = startupDo value 307 >> startupReport value 0 message
bootstrapRequired :: CacheStartup -> Word32 -> ExceptT Int32 IO ()
bootstrapRequired value step = startupBool value step >>= \ok ->
  unless ok (startupDo value 307 >> throwE 0)
bootstrapSlots :: CacheStartup -> ExceptT Int32 IO ()
bootstrapSlots value = do
  mapM_ (startupDo value) [302,303,700]
  startupSubworkflow value 17 700 719
  expected <- startupRead value 12 RS.hash
  let mismatch = bootstrapReject value "parent replay bootstrap state does not match its identity commitment"
  unless (RS.nonzero expected) mismatch
  actual <- startupRead value 13 RS.hash
  unless (actual == expected) mismatch
  mapM_ (startupDo value) [309,310]
  (configured,count) <- startupRead value 14 ((,) <$> G.getWord8 <*> G.getWord64le)
  forM_ (RS.indices count) $ \_ -> do
    (slot,hasActive,hasTreasury) <- startupRead value 15 ((,,) <$> G.getWord8 <*> RS.flag <*> RS.flag)
    unless (slot /= configured && hasActive && hasTreasury) $
      bootstrapReject value "parent replay bootstrap contains an invalid global slot"
    mapM_ (startupDo value) [317,318]
    active <- startupRead value 16 RS.hash
    unless (RS.nonzero active) $
      bootstrapReject value "parent replay bootstrap contains a null active proposal"
    startupDo value 322
    (ctip,vout,amount) <- startupRead value 17 ((,,) <$> RS.hash <*> G.getWord32le <*> G.getInt64le)
    if RS.nonzero ctip then mapM_ (startupDo value) [324,325]
      else unless (vout == maxBound && amount == 0) $
        bootstrapReject value "parent replay bootstrap has a malformed absent CTIP"
    inserted <- startupBool value 330
    unless inserted (bootstrapReject value "parent replay bootstrap repeats a global slot")
    startupDo value 331
  mapM_ (startupDo value) [332,333,334]

instance CacheBootstrap CacheStartup where
  rebuildReplayCache value@(CacheStartup native) = either id id <$> runExceptT (do
    enabled <- startupBool value 301
    if enabled then bootstrapSlots value else do
      startupDo value 340
      bootstrapRequired value 341
      previous <- startupRead value 18 RS.hash
      when (RS.nonzero previous) $
        bootstrapReject value "authenticated parent genesis unexpectedly has a predecessor"
      startupDo value 345
      applied <- parentBlockSession native 23 24 1000 0
      unless applied (startupDo value 307 >> throwE 0)
      mapM_ (startupDo value) [347,348,349]
    reset <- replayStoreSession RS.ResetSession native 21 22 100 0
    unless (reset == 1) (startupDo value 307 >> throwE 0)
    startupDo value 337
    pure 1)
instance Operation CacheStartup CacheInitializationCapabilities where
  type Context CacheStartup = CapabilityContext CacheInitializationCapabilities CacheStartup
  type Outcome CacheStartup = IO Int32
  data DSL CacheStartup where
    StartReplayCache :: Context CacheStartup => DSL CacheStartup
  interpret operation request = withOperation @CacheStartup operation $ \value -> case request of
    StartReplayCache -> Just (initializeReplayCache value)

-- Process-local snapshots use the native serializers. Native code owns the
-- lock, block/state objects and durable effects; Haskell owns cache policy.
data CacheKey = CacheKey (Maybe Word8) (Maybe RS.Hash) RS.Hash RS.Hash [Word16] Word32
  deriving (Eq, Show)
data CacheSnapshot = CacheSnapshot Bool CacheKey Word32 RS.Hash Bool RS.Hash Word32
  deriving (Eq, Show)
data CacheTarget = CacheTarget CacheKey Word32 Word32 RS.Hash Bool deriving (Eq, Show)
newtype CacheProgress = CacheProgress NativeBytes
data CacheEffect = CacheConfig | CacheRead | CacheBudgetActive | CacheBudgetRemaining
  | CacheBudgetWrite | CacheDeadline | CacheRevoke | CacheClear | CacheInitialize
  | CacheActiveHash | CacheActiveHeight | CacheReport | CacheOpenBlock | CacheReadBlock
  | CachePreviousHash | CachePrepareState | CacheOpenReplay | CacheMilestone
  | CacheClearEdge | CacheBuildEdge | CacheStoreOpen | CacheAppend | CacheUpdateTip
  | CacheClearBlock | CachePublish | CacheOpenBmm | CacheCloseInitialization | CacheCloseAppend
  | CacheCloseReplay deriving (Eq, Show, Enum, Bounded)

cacheKey :: G.Get CacheKey
cacheKey = CacheKey <$> present G.getWord8 <*> present RS.hash <*> RS.hash <*> RS.hash
  <*> sequence (replicate 6 G.getWord16le) <*> G.getWord32le
  where present parser = do
          exists <- RS.flag
          value <- parser
          pure (if exists then Just value else Nothing)
cacheSnapshot :: G.Get CacheSnapshot
cacheSnapshot = CacheSnapshot <$> RS.flag <*> cacheKey <*> G.getWord32le <*> RS.hash
  <*> RS.flag <*> RS.hash <*> G.getWord32le
cacheTarget :: G.Get CacheTarget
cacheTarget = CacheTarget <$> cacheKey <*> G.getWord32le <*> G.getWord32le <*> RS.hash <*> RS.flag

cacheRequest :: CacheProgress -> CacheEffect -> Word64 -> B.ByteString -> ExceptT Int32 IO B.ByteString
cacheRequest (CacheProgress native) command index = liftIO . native (fromIntegral (fromEnum command)) index
cacheRead :: CacheProgress -> CacheEffect -> Word64 -> G.Get a -> ExceptT Int32 IO a
cacheRead value command index parser = cacheRequest value command index B.empty >>= either throwE pure . RS.decode parser
cacheEffect :: CacheProgress -> CacheEffect -> Word64 -> B.ByteString -> ExceptT Int32 IO ()
cacheEffect value command index bytes = cacheRequest value command index bytes >>= \reply ->
  unless (B.null reply) (throwE (-1))
cacheDo :: CacheProgress -> CacheEffect -> Word64 -> ExceptT Int32 IO ()
cacheDo value command index = cacheEffect value command index B.empty
cacheBool :: CacheProgress -> CacheEffect -> Word64 -> ExceptT Int32 IO Bool
cacheBool value command index = cacheRead value command index RS.flag
cacheMust :: CacheProgress -> CacheEffect -> Word64 -> ExceptT Int32 IO ()
cacheMust value command index = cacheBool value command index >>= \ok -> unless ok (throwE 0)
initializeCacheProgress :: CacheProgress -> Word64 -> ExceptT Int32 IO ()
initializeCacheProgress value@(CacheProgress native) force = do
  cacheDo value CacheInitialize force
  result <- liftIO $ initializeReplayCache (CacheStartup (\step -> native (300+step)))
    `finally` (runExceptT (cacheDo value CacheCloseInitialization 0) >>= either
      (const (ioError (userError "cache initialization cleanup failed"))) pure)
  unless (result == 1) (throwE (if result == 0 then 0 else -1))
cacheFail :: CacheProgress -> String -> ExceptT Int32 IO a
cacheFail value message = cacheEffect value CacheReport 0 (C.pack message) >> throwE 0
cacheHash :: CacheProgress -> Word32 -> ExceptT Int32 IO RS.Hash
cacheHash value height = cacheRead value CacheActiveHash (fromIntegral height) (RS.optional RS.hash)
  >>= maybe (throwE 0) pure
cacheCheckDeadline :: CacheProgress -> ExceptT Int32 IO ()
cacheCheckDeadline value = do
  result <- liftIO $ runDeadline $ \step -> do
    reply <- runExceptT (cacheRead value CacheDeadline (fromIntegral step) G.getInt64le)
    either (const (ioError (userError "invalid parent cache deadline reply"))) pure reply
  unless (result == 0) (throwE (-1))

class CachePreflight op where
  prepareCacheProgress :: op -> ExceptT Int32 IO (Maybe (CacheTarget,CacheSnapshot))
class CacheAdvance op where
  advanceCacheProgress :: op -> CacheTarget -> CacheSnapshot -> ExceptT Int32 IO ()
class CachePublication op where
  publishCacheProgress :: op -> CacheTarget -> ExceptT Int32 IO ()

instance CachePreflight CacheProgress where
  prepareCacheProgress value = do
    target@(CacheTarget key@(CacheKey slot proposal _ checkpoint _ _) checkpointHeight targetHeight targetHash _) <-
      cacheRead value CacheConfig 0 cacheTarget
    case (slot,proposal) of
      (Just _,Just _) | RS.nonzero checkpoint -> do
        when (targetHeight < checkpointHeight) $ cacheFail value
          ("parent height " ++ show targetHeight ++ " predates native drivechain launch checkpoint " ++ show checkpointHeight)
        initial@(CacheSnapshot initialized initialKey _ _ _ _ _) <- cacheRead value CacheRead 0 cacheSnapshot
        current <- if initialized && initialKey == key then pure initial else do
          locked <- cacheBool value CacheBudgetActive 0
          when locked (cacheFail value "authenticated parent replay cache is not warmed")
          cacheDo value CacheRevoke 0
          cacheDo value CacheClear 0
          initializeCacheProgress value 0
          cacheRead value CacheRead 0 cacheSnapshot
        activeCheckpoint <- cacheHash value checkpointHeight
        unless (activeCheckpoint == checkpoint) $ do
          cacheDo value CacheRevoke 0
          cacheFail value "active parent chain no longer contains the pinned drivechain launch checkpoint"
        let CacheSnapshot _ _ height block _ _ _ = current
        pastTip <- if targetHeight >= height then pure False else do
          activeHeight <- cacheRead value CacheActiveHeight 0 (RS.optional G.getWord32le) >>= maybe (throwE 0) pure
          pure (activeHeight < height)
        stale <- if pastTip then pure True else (/= block) <$> cacheHash value height
        warmed <- if not stale then pure current else do
          cacheDo value CacheRevoke 0
          locked <- cacheBool value CacheBudgetActive 0
          when locked (cacheFail value "authenticated parent replay cache is stale after a parent reorganization")
          cacheDo value CacheClear 0
          initializeCacheProgress value 1
          cacheRead value CacheRead 0 cacheSnapshot
        activeTarget <- cacheHash value targetHeight
        unless (activeTarget == targetHash) (cacheFail value "requested parent replay target is not active at its claimed height")
        pure (Just (target,warmed))
      _ -> pure Nothing

instance CacheAdvance CacheProgress where
  advanceCacheProgress value@(CacheProgress native) (CacheTarget _ checkpointHeight targetHeight _ _) (CacheSnapshot _ _ initialHeight initialBlock _ _ _) =
    when (initialHeight < targetHeight) $ do
      let steps = targetHeight-initialHeight
      locked <- cacheBool value CacheBudgetActive 0
      when locked $ do
        cacheCheckDeadline value
        (remaining,reportable) <- cacheRead value CacheBudgetRemaining 0 ((,) <$> G.getWord32le <*> RS.flag)
        when (steps > remaining) $ if not reportable then throwE 0 else cacheFail value
          ("parent replay needs " ++ show steps ++ " uncached blocks; locked validation permits at most " ++
            show remaining ++ " before background warming")
        cacheDo value CacheBudgetWrite (fromIntegral (remaining-steps))
      advance initialHeight initialBlock
    where
      advance height block = when (height < targetHeight) $ do
        let next = height+1 -- Increment only below target, including UINT32_MAX.
            index = fromIntegral next
        cacheCheckDeadline value
        nextHash <- cacheHash value next
        cacheEffect value CacheOpenBlock index nextHash
        cacheMust value CacheReadBlock 0
        previous <- cacheRead value CachePreviousHash 0 RS.hash
        unless (previous == block) $ do
          cacheDo value CacheRevoke 0
          cacheFail value "authenticated parent-state replay is not a contiguous chain"
        cacheDo value CachePrepareState 0
        applied <- parentBlockSession native (fromIntegral (fromEnum CacheOpenReplay))
          (fromIntegral (fromEnum CacheCloseReplay)) 30000 index
        milestone <- if applied then checkCacheMilestone value index else pure False
        unless milestone (cacheDo value CacheRevoke 0 >> throwE 0)
        cacheCheckDeadline value
        cacheDo value CacheClearEdge 0
        when (checkpointHeight < next) (buildCacheBmmEdge value index)
        opened <- cacheBool value CacheStoreOpen 0
        appended <- if opened then (==1) <$> replayStoreSession RS.AppendSession native
          (fromIntegral (fromEnum CacheAppend)) (fromIntegral (fromEnum CacheCloseAppend)) 500 index else pure False
        unless appended (cacheDo value CacheRevoke 0 >> throwE 0)
        -- Persistence is complete before any published in-memory tip change.
        cacheDo value CacheUpdateTip index
        cacheDo value CacheClearBlock 0
        advance next nextHash

instance CachePublication CacheProgress where
  publishCacheProgress value (CacheTarget (CacheKey _ _ _ checkpoint _ _) checkpointHeight targetHeight targetHash requireActive) = do
    let boundary height expected message = do
          active <- cacheHash value height
          unless (active == expected) (cacheDo value CacheRevoke 0 >> cacheFail value message)
    boundary checkpointHeight checkpoint "parent-chain reorg raced the pinned launch checkpoint check"
    boundary targetHeight targetHash "parent-chain reorg raced the replay target check"
    CacheSnapshot _ (CacheKey _ proposal _ _ _ _) height block activated active activationHeight <-
      cacheRead value CacheRead 0 cacheSnapshot
    boundary height block "parent-chain reorg raced the replay cache tip check"
    when (requireActive && not (activated && Just active == proposal && activationHeight <= targetHeight)) $
      cacheFail value ("configured Elements slot proposal is not active at parent height " ++ show targetHeight)
    cacheCheckDeadline value
    cacheDo value CachePublish 0

progressReplayCache :: (CachePreflight op, CacheAdvance op, CachePublication op) => op -> ExceptT Int32 IO ()
progressReplayCache value = do
  prepared <- prepareCacheProgress value
  case prepared of
    Nothing -> pure ()
    Just (target,current) -> advanceCacheProgress value target current >> publishCacheProgress value target

type CacheProgressCapabilities = '[CachePreflight, CacheAdvance, CachePublication]
instance Operation CacheProgress CacheProgressCapabilities where
  type Context CacheProgress = CapabilityContext CacheProgressCapabilities CacheProgress
  type Outcome CacheProgress = IO Int32
  data DSL CacheProgress where
    ProgressReplayCache :: Context CacheProgress => DSL CacheProgress
  interpret operation request = withOperation @CacheProgress operation $ \value -> case request of
    ProgressReplayCache -> Just (either id (const 1) <$> runExceptT (progressReplayCache value))

checkCacheMilestone :: CacheProgress -> Word64 -> ExceptT Int32 IO Bool
checkCacheMilestone value@(CacheProgress native) index = do
  ready <- cacheBool value CacheMilestone index
  if not ready then pure False else do
    result <- liftIO (runExceptT (validateMilestones (Milestone (\step -> native (100+step)))))
    case result of
      Right () -> pure True
      Left 0 -> pure False
      Left failure -> throwE failure

buildCacheBmmEdge :: CacheProgress -> Word64 -> ExceptT Int32 IO ()
buildCacheBmmEdge value@(CacheProgress native) index = do
  cacheDo value CacheOpenBmm 0
  result <- liftIO (runExceptT (scanBmmCommitment (BmmScan (\step -> native (200+step)))))
  canonical <- case result of
    Right _ -> pure True
    Left 0 -> pure False
    Left failure -> throwE failure
  cacheEffect value CacheBuildEdge index (B.singleton (if canonical then 1 else 0))

newtype BmmContext = BmmContext NativeBytes
class BmmCacheAdmission op where
  prepareBmmCache :: op -> PH.HeaderCheck Word64
class BmmCacheRouting op where
  routeBmmCache :: op -> Word64 -> PH.HeaderCheck Bool
class BmmEdgeAuthentication op where
  authenticateBmmEdge :: op -> Word64 -> PH.HeaderCheck ()
class BmmContextPublication op where
  publishBmmContext :: op -> Word64 -> PH.HeaderCheck ()

bmmContextError :: NativeBytes -> Word64 -> PH.HeaderCheck a
bmmContextError native code = do
  status <- PH.scalar native 0 code
  throwE (if status == 2 || status == 3 then fromIntegral status else -1)

bmmRequire :: NativeBytes -> Word64 -> Bool -> PH.HeaderCheck ()
bmmRequire native code valid = unless valid (bmmContextError native code)

bmmAvailable :: NativeBytes -> Word32 -> PH.HeaderCheck ()
bmmAvailable native step = PH.flag native step >>= \valid -> unless valid (throwE 3)

-- Match std::remove_if's first-hole compaction, including partial moves before
-- an exception; native code owns iterators, move assignment and final erase.
pruneBmmCache :: NativeBytes -> Word64 -> Word64 -> PH.HeaderCheck ()
pruneBmmCache native epoch negative = do
  count <- PH.scalar native 10 negative
  let expired index = do
        timeout <- if negative == 1 then PH.flagAt native 12 index else pure False
        entryEpoch <- PH.scalar native 11 index
        pure (entryEpoch /= epoch || timeout)
      first index | index == count = PH.effect native 13 count
                  | otherwise = do
                      remove <- expired index
                      if remove then PH.effect native 13 index >> compact (index+1) else first (index+1)
      compact index | index == count = pure ()
                    | otherwise = do
                        remove <- expired index
                        unless remove (PH.effect native 14 index)
                        compact (index+1)
  first 0
  PH.effect native 15 0

instance BmmCacheAdmission BmmContext where
  prepareBmmCache (BmmContext native) = do
    PH.effect native 1 0
    PH.effect native 2 0
    bounded <- PH.flag native 3
    if bounded then PH.flag native 4 >>= bmmRequire native 1 else PH.effect native 5 0
    epoch <- PH.scalar native 6 0
    when (epoch == 0) $ PH.effect native 7 0 >> PH.effect native 8 0 >> bmmContextError native 2
    PH.effect native 9 0
    pruneBmmCache native epoch 0
    pruneBmmCache native epoch 1
    pure epoch

bmmFind :: NativeBytes -> Word32 -> Word32 -> Word32 -> PH.HeaderCheck (Maybe Word64)
bmmFind native size parent slot = do
  count <- PH.scalar native size 0
  let loop index | index == count = pure Nothing
                 | otherwise = do
                     sameParent <- PH.flagAt native parent index
                     sameSlot <- if sameParent then PH.flagAt native slot index else pure False
                     if sameSlot then pure (Just index) else loop (index+1)
  loop 0

bmmCacheHit :: NativeBytes -> PH.HeaderCheck ()
bmmCacheHit native = do
  PH.flag native 20 >>= bmmRequire native 3
  PH.flag native 21 >>= bmmRequire native 4
  bmmAvailable native 22
  epoch <- PH.scalar native 23 0
  bmmRequire native 5 (epoch /= 0)
  prior <- PH.scalar native 24 0
  bmmRequire native 5 (epoch == prior)
  PH.effect native 25 0
  PH.effect native 26 0

bmmUntrusted :: NativeBytes -> Word64 -> PH.HeaderCheck ()
bmmUntrusted native epoch = do
  PH.effect native 28 0
  ExceptT $ runExceptT body `finally` (D.constructionScalar native 43 0 >>= \result ->
    unless (result == 1) (ioError (userError "invalid BMM replay-lock release")))
  where
    revoke = mapM_ (\step -> PH.effect native step 0) [35,36,37]
    identity field | field > 14 = pure ()
                   | otherwise = PH.flagAt native 30 field >>= bmmRequire native 7 >> identity (field+1)
    body = do
      PH.flag native 29 >>= bmmRequire native 6
      identity 1
      current <- PH.scalar native 31 0
      bmmRequire native 7 (current == epoch)
      PH.flag native 32 >>= bmmRequire native 8
      PH.effect native 33 0
      corrupt <- PH.flag native 34
      when corrupt (revoke >> throwE 3)
      absent <- PH.flag native 78
      when absent (bmmContextError native 9)
      successor <- PH.scalar native 38 0
      tip <- PH.scalar native 39 0
      valid <- if successor > 0xffffffff || tip > 0xffffffff || successor > tip then pure False
        else (< successor) <$> PH.scalar native 40 0
      unless valid (revoke >> bmmContextError native 10)
      PH.flag native 41 >>= bmmRequire native 11
      PH.flag native 42 >>= bmmRequire native 11

instance BmmCacheRouting BmmContext where
  routeBmmCache (BmmContext native) epoch = do
    cached <- bmmFind native 16 17 18
    case cached of
      Just index -> PH.effect native 19 index >> bmmCacheHit native >> pure True
      Nothing -> do
        untrusted <- PH.flag native 27
        when untrusted (bmmUntrusted native epoch)
        -- The budget scope can change; retain the second observation.
        stillUntrusted <- PH.flag native 27
        unless stillUntrusted $ do
          rejected <- bmmFind native 44 45 46
          case rejected of
            Just index -> PH.effect native 47 index >> bmmContextError native 12
            Nothing -> pure ()
        pure False

cacheBmmRejection :: NativeBytes -> PH.HeaderCheck ()
cacheBmmRejection native = do
  PH.effect native 51 Constants.bmmNegativeCacheSeconds
  size <- PH.scalar native 52 0
  when (size > Constants.bmmNegativeCacheSize) (PH.effect native 53 0)

instance BmmEdgeAuthentication BmmContext where
  authenticateBmmEdge (BmmContext native) _ = do
    status <- PH.scalar native 48 0
    when (status > 2) (throwE (-1))
    when (status == 1) (bmmAvailable native 49)
    when (status == 2) (throwE 3)
    when (status == 1) (PH.effect native 50 0 >> cacheBmmRejection native >> throwE 2)
    height <- PH.scalar native 54 0
    checkpoint <- PH.scalar native 55 0
    when (height < checkpoint) $ PH.effect native 56 0 >> cacheBmmRejection native >> bmmContextError native 14
    bmmAvailable native 57
    parent <- PH.scalar native 58 0
    bmmRequire native 15 (parent < 0xffffffff)
    PH.flagAt native 59 (parent+1) >>= \valid -> unless valid (throwE 3)
    mapM_ (bmmAvailable native) [60,61]
    successor <- PH.scalar native 62 0
    bmmRequire native 16 (successor == parent+1)
    PH.flag native 63 >>= bmmRequire native 16
    PH.effect native 64 0
    bmmAvailable native 65
    PH.effect native 66 0

instance BmmContextPublication BmmContext where
  publishBmmContext (BmmContext native) epoch = do
    bmmAvailable native 67
    PH.effect native 68 0
    canonical <- PH.flag native 69
    PH.effect native (if canonical then 70 else 71) 0
    PH.effect native 72 0
    current <- PH.scalar native 73 0
    bmmRequire native 17 (current /= 0 && current == epoch)
    PH.effect native 74 0
    size <- PH.scalar native 75 0
    when (size > Constants.bmmEdgeCacheSize) (PH.effect native 76 0)
    bmmRequire native 18 canonical
    PH.flag native 77 >>= bmmRequire native 19

authenticateBmmContext :: (BmmCacheAdmission op, BmmCacheRouting op, BmmEdgeAuthentication op, BmmContextPublication op)
  => op -> PH.HeaderCheck ()
authenticateBmmContext value = do
  epoch <- prepareBmmCache value
  cached <- routeBmmCache value epoch
  unless cached (authenticateBmmEdge value epoch >> publishBmmContext value epoch)

type BmmContextCapabilities = '[BmmCacheAdmission, BmmCacheRouting, BmmEdgeAuthentication, BmmContextPublication]
instance Operation BmmContext BmmContextCapabilities where
  type Context BmmContext = CapabilityContext BmmContextCapabilities BmmContext
  type Outcome BmmContext = IO Int32
  data DSL BmmContext where
    AuthenticateBmmContext :: Context BmmContext => DSL BmmContext
  interpret operation request = withOperation @BmmContext operation $ \value -> case request of
    AuthenticateBmmContext -> Just (either id (const 0) <$> runExceptT (authenticateBmmContext value))
