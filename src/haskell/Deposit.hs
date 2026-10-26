{-# LANGUAGE ForeignFunctionInterface, TypeFamilies #-}
{-# LANGUAGE ConstraintKinds, DataKinds, FlexibleContexts, FlexibleInstances #-}
{-# LANGUAGE GADTs, MultiParamTypeClasses, TypeApplications, ScopedTypeVariables #-}
-- Copyright (c) 2026 The Elements Core developers
-- Distributed under the MIT software license.
module Deposit where

import CapabilityContext (CapabilityContext)
import Control.Exception (SomeException, try)
import Control.Monad (guard, unless, when, forM_)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Except (ExceptT, runExceptT, throwE)
import Data.Bits ((.&.), (.|.), clearBit, shiftL, shiftR, testBit)
import qualified Data.Binary.Get as G
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.Char (digitToInt)
import Data.Int (Int32, Int64)
import Data.Functor.Identity (runIdentity)
import Data.List (find, elemIndex)
import BmmConstants (withdrawalStatuses, withdrawalLifecycle, alphaPeginOneConfirmationHeight,
  depositAddressLimit, depositMarker, legacyDepositMarker, sidechainSlot,
  peginIdentityNetwork, peginIdentitySlot, peginIdentityDepth, peginIdentityPins)
import Data.Word (Word8, Word32, Word64)
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Marshal.Array (peekArray, pokeArray)
import Foreign.Ptr (Ptr, FunPtr, castPtr, nullFunPtr)
import Foreign.Storable (peek, peekElemOff, poke)
import Withdrawal (readLE, wordLE)
import ParentReplay (transition, Record(..), nonEmptyBounded)
import qualified ParentReplay
import qualified ReplayStore as RS
import Control.Operation
import Control.Operation.Validation
import Workflow (NativeBytes, CommandFlow(..), PredicateFlow(..), orderedFacts, runReportedEffects)

data InputLimit = InputLimit Bool Word64 Word64 (Word32 -> Word64 -> Word64 -> IO Word64)
instance Validation InputLimit where
  type ValidationResult InputLimit = IO Bool
  validate (InputLimit enabled transactions limit readField)
    | not enabled = pure True
    | otherwise = nextTransaction 0 limit
    where
      nextTransaction tx remaining
        | tx == transactions = pure True
        | otherwise = readField 0 tx 0 >>= \count -> nextInput tx count 0 remaining
      nextInput tx count input remaining
        | input == count = nextTransaction (tx+1) remaining
        | otherwise = do
            pegin <- readField 1 tx input
            case pegin of
              0 -> nextInput tx count (input+1) remaining
              1 | remaining == 0 -> pure False
                | otherwise -> nextInput tx count (input+1) (remaining-1)
              _ -> ioError (userError "invalid deposit input flag")

data NativeAdmissionFlow = NativeAdmissionFlow Word32 Word32
instance Validation NativeAdmissionFlow where
  type ValidationResult NativeAdmissionFlow = Int32
  validate (NativeAdmissionFlow phase result) = transition phase result
    ([(step,(finish (fromIntegral step),fromIntegral step+1)) | step <- [1..5]] ++
     [(6,(7,-10)),(7,(finish 6,8)),(8,(finish 6,finish 6))])
    where finish code = 65536 + 256 + 8 + code

-- Pinned Alpha/Beta identities share facts but retain their original read order.
-- Mode 2 clamps an already-selected depth without reading identity facts.
data ConfirmationPolicy = ConfirmationPolicy Word32 Int64 Word32 (Word32 -> IO Int32)
requiredConfirmationDepth :: Word32 -> Word32
requiredConfirmationDepth = max 1

hasDepositDepth :: Word32 -> Word32 -> Word32 -> Bool
hasDepositDepth deposit tip required =
  required > 0 && deposit <= tip && tip - deposit >= required - 1

instance Validation ConfirmationPolicy where
  type ValidationResult ConfirmationPolicy = IO Int64
  validate (ConfirmationPolicy mode height configured readFact) =
    confirmationPolicy mode height configured readFact

confirmationPolicy :: Monad m => Word32 -> Int64 -> Word32 -> (Word32 -> m Int32) -> m Int64
confirmationPolicy mode height configured readFact
    | mode > 2 = pure (-1)
    | mode == 2 = pure (fromIntegral (requiredConfirmationDepth configured))
    | mode == 0 = matches alpha (pure 1) (pure 0)
    | otherwise = matches [0,1,2,3,8,9,5,7] (pure 6) $
        if height >= alphaPeginOneConfirmationHeight then matches alpha (pure 1) fallback else fallback
    where
      alpha = [0,1,2,3,4,5,6,7]
      fallback = pure (fromIntegral configured)
      matches [] yes _ = yes
      matches (step:rest) yes no = readFact step >>= \reply -> case reply of
        0 -> no
        1 -> matches rest yes no
        _ -> pure (-1)

-- Copied native facts, not a new consensus or persisted identity encoding.
data ConfirmationIdentity = ConfirmationIdentity B.ByteString Bool Bool (Maybe Word8)
  B.ByteString B.ByteString B.ByteString Word32 deriving (Eq, Show)
data ConfirmationSelection = ConfirmationSelection Bool Int64 ConfirmationIdentity deriving (Eq, Show)

confirmationSelection :: Bool -> G.Get ConfirmationSelection
confirmationSelection alpha = do
  height <- G.getInt64le
  network <- B.pack <$> RS.counted 1 G.getWord8
  elements <- RS.flag
  parent <- RS.flag
  present <- RS.flag
  slot <- G.getWord8
  unless (present || slot == 0) (fail "noncanonical absent confirmation slot")
  identity <- ConfirmationIdentity network elements parent (if present then Just slot else Nothing)
    <$> RS.hash <*> RS.hash <*> RS.hash <*> G.getWord32le
  pure (ConfirmationSelection alpha height identity)

instance Validation ConfirmationSelection where
  type ValidationResult ConfirmationSelection = Int64
  validate (ConfirmationSelection alpha height (ConfirmationIdentity network elements parent slot genesis parentGenesis manifest configured)) =
    runIdentity (confirmationPolicy (if alpha then 0 else 1) height configured (pure . fact))
    where
      matches value name = lookup name peginIdentityPins == Just (ParentReplay.hashHex value)
      fact step = fromIntegral . fromEnum $ case step of
        0 -> network == C.pack peginIdentityNetwork
        1 -> elements
        2 -> parent
        3 -> fmap fromIntegral slot == Just peginIdentitySlot
        4 -> matches genesis "PEGIN_ALPHA_GENESIS"
        5 -> matches parentGenesis "PEGIN_PARENT_GENESIS"
        6 -> matches manifest "PEGIN_ALPHA_MANIFEST"
        7 -> configured == peginIdentityDepth
        8 -> matches genesis "PEGIN_BETA_GENESIS"
        9 -> matches manifest "PEGIN_BETA_MANIFEST"
        _ -> error "unknown confirmation identity fact"

selectedConfirmationDepth :: Bool -> NativeBytes -> Word32 -> ExceptT Int32 IO Word32
selectedConfirmationDepth alpha native step = do
  reply <- liftIO (native step 0 B.empty)
  selection <- either throwE pure (RS.decode (confirmationSelection alpha) reply)
  let depth = validate selection
  unless (depth >= 0 && depth <= fromIntegral (maxBound :: Word32)) (throwE (-1))
  pure (fromIntegral depth)

data ConfirmationWorkflow = ConfirmationWorkflow Bool NativeBytes
instance Validation ConfirmationWorkflow where
  type ValidationResult ConfirmationWorkflow = IO Int32
  validate (ConfirmationWorkflow alpha native) = fmap (either id (const 1)) $ runExceptT $ do
    depth <- selectedConfirmationDepth alpha native 0
    reply <- liftIO (native 1 (fromIntegral depth) B.empty)
    unless (B.null reply) (throwE (-1))

-- Signed timestamps travel as their Word64 bit patterns. Integer subtraction
-- avoids overflowing the age cutoff at the signed timestamp boundary.
data FeeFreeSelection = FeeFreeSelection Int64 (Word32 -> IO Word64)
instance Validation FeeFreeSelection where
  type ValidationResult FeeFreeSelection = IO Int32
  validate (FeeFreeSelection age readField) = validate
    (CommandFlow 16 (\phase reply -> validate (FeeFreeSelectionFlow phase reply)) fact)
    where
      flag value = if value then 1 else 0
      signed value = toInteger (fromIntegral value :: Int64)
      fact 10 = pure (flag (age>0))
      fact 11 = do
        timestamp <- readField 11
        now <- readField 17
        pure (flag (signed timestamp <= signed now - toInteger age))
      fact step = readField step >>= \value -> pure $ case step of
        4 -> flag (value==0)
        5 -> flag (value==1)
        6 -> flag (value==1)
        7 -> flag (value==0)
        8 -> flag (value==0)
        _ -> if value<=1 then fromIntegral value else -1

-- One locked mempool scan; rejected candidates advance without later reads.
data FeeFreeSelectionFlow = FeeFreeSelectionFlow Word32 Word32
instance Validation FeeFreeSelectionFlow where
  type ValidationResult FeeFreeSelectionFlow = Int32
  validate (FeeFreeSelectionFlow phase result) = transition phase result
    ([(1,(-11,2)),(2,(-1,3)),(3,(-11,4))] ++
     [(step,(16,fromIntegral step+1)) | step <- [4..9]] ++
     [(10,(12,11)),(11,(16,12)),(12,(16,13)),(13,(16,14)),
      (14,(-1,15)),(15,(-1,16)),(16,(-1,3))])

data RawMatch = RawMatch Int64 Int64 Int64 Word32 (Word32 -> IO Int64)
instance Validation RawMatch where
  type ValidationResult RawMatch = IO Int32
  validate (RawMatch slot amount bound hasAddress action)
    | slot < 0 || slot > 255 || amount <= 0 || amount > bound || hasAddress /= 1 = pure 1
    | otherwise = action 1 >>= \found -> case found of
        0 -> check 2
        1 -> pure 3
        2 -> pure 2
        _ -> pure (-1)
    where
      check stage
        | stage > 8 = pure 0
        | otherwise = action stage >>= \fact ->
            if fact < 0 || (stage /= 6 && stage /= 7 && fact > 1) then pure (-1)
            else if case stage of 3 -> fact == 0; 7 -> fact <= 1; _ -> fact == 1
              then check (stage+1) else pure (fromIntegral stage+1)

data LiveVerify = LiveVerify Word64 Word64 Word64 (Word32 -> IO Int32)
instance Validation LiveVerify where
  type ValidationResult LiveVerify = IO Int32
  validate (LiveVerify index inputs witnesses action)
    | index >= inputs || index >= witnesses = pure 1
    | otherwise = runReportedEffects action
        (\stage -> lookup stage [(1,13),(3,14),(4,14),(5,14),(6,15),(7,16),(8,17),(9,17),(10,17),(11,17)]) [1..12]

newtype PreviousSequence = PreviousSequence Int64
instance Validation PreviousSequence where
  type ValidationResult PreviousSequence = Int64
  validate (PreviousSequence current) = if current > 0 then current - 1 else -1

data EvidenceBuild = EvidenceBuild Int64 Int64 Word32 (Word32 -> IO Int32)
canBuildEvidence :: Int64 -> Int64 -> Word32 -> Bool
canBuildEvidence sequenceNumber height flags =
  validate (PreviousSequence sequenceNumber) >= 0 && flags == 3 && height >= 0
instance Validation EvidenceBuild where
  type ValidationResult EvidenceBuild = IO Int32
  validate (EvidenceBuild sequenceNumber height flags action)
    | not (canBuildEvidence sequenceNumber height flags) = pure 1
    | otherwise = runReportedEffects action
        (\stage -> lookup stage [(5,8),(6,8),(7,8)]) [1,5,6,7,2,3,4]

data HeaderBuild = HeaderBuild Word64 Int64 (Word32 -> Word64 -> IO Int32)
headerWindow :: Word64 -> Int64 -> Bool
headerWindow first tip = validate (Record 22 0 tip first 2016) == 1
instance Validation HeaderBuild where
  type ValidationResult HeaderBuild = IO Int32
  validate (HeaderBuild first tip action)
    | not (headerWindow first tip) = pure 1
    | otherwise = runReportedEffects (uncurry action)
        (\(stage,height) -> if stage == 2 then Just (3,height) else Nothing)
        ((1,0) : [(stage,height) | height <- [first..fromIntegral tip], stage <- [2,4]])

data CtipSearch = CtipSearch Word64 (Word32 -> Word64 -> IO Int32)
instance Validation CtipSearch where
  type ValidationResult CtipSearch = IO Int32
  validate (CtipSearch count action) = search 0 False
    where
      search index found
        | index >= count = pure (if found then 0 else 1)
        | otherwise = orderedFacts (\stage -> action stage index)
            [(stage,0) | stage <- [1,3,4,5]] 1 >>= \candidate -> case candidate of
            0 -> search (index+1) found
            1 | found -> pure 2
              | otherwise -> action 2 index >>= \stored -> case stored of
                  0 -> search (index+1) False
                  1 -> search (index+1) True
                  _ -> pure (-1)
            _ -> pure (-1)

-- One reconstruction operation keeps the fork's source checks, treasury search
-- and confirmation traversal in Haskell. Native code owns RPC and serialization.
data Construction = Construction Int64 Int64 Word32 Int32 NativeBytes
type ConstructionCheck = ExceptT Int32 IO
class DepositSource op where
  readDepositSource :: op -> ConstructionCheck ()
class PriorTreasury op where
  readPriorTreasury :: op -> ConstructionCheck ()
class ConfirmationHeaders op where
  readConfirmationHeaders :: op -> ConstructionCheck ()

constructionWord :: B.ByteString -> IO Word64
constructionWord bytes
  | B.length bytes == 8 = pure (ParentReplay.replayWord bytes)
  | otherwise = ioError (userError "invalid construction scalar reply")

constructionScalar :: NativeBytes -> Word32 -> Word64 -> IO Word64
constructionScalar native step index = native step index B.empty >>= constructionWord

constructionEffect :: NativeBytes -> Word32 -> B.ByteString -> IO ()
constructionEffect native step payload = do
  reply <- native step 0 payload
  unless (B.null reply) (ioError (userError "invalid construction effect reply"))

constructionFlag :: Word64 -> ConstructionCheck Bool
constructionFlag value = case value of
  0 -> pure False
  1 -> pure True
  _ -> throwE (-1)

instance DepositSource Construction where
  readDepositSource (Construction sequenceNumber height flags _ native) = do
    unless (canBuildEvidence sequenceNumber height flags) (throwE 1)
    liftIO (constructionEffect native 0 B.empty)
    forM_ [1..3] $ \step -> do
      valid <- constructionFlag =<< liftIO (constructionScalar native step 0)
      unless valid (throwE 2)
    liftIO (constructionEffect native 4 B.empty)

-- Only the previous-transaction scan historically tolerates native failures.
-- Its envelope preserves runtime-error text and rethrows the original native
-- exception when the existing fatal-message rule matches; other stages fail closed.
candidateReply :: NativeBytes -> Word32 -> Word64 -> IO (Maybe B.ByteString)
candidateReply native step index = do
  result <- native (100+step) index B.empty
  case B.uncons result of
    Just (0,body) -> pure (Just body)
    Just (1,message) -> do
      when (validate (MessageMatches 2 message) == 1) $ do
        _ <- native 109 0 B.empty
        ioError (userError "native candidate exception was not rethrown")
      pure Nothing
    Just (2,body) | B.null body -> pure Nothing
    _ -> ioError (userError "invalid candidate reply envelope")

instance PriorTreasury Construction where
  readPriorTreasury (Construction sequenceNumber _ _ slot native) = do
    count <- liftIO (constructionScalar native 10 0)
    let action step index = do
          reply <- candidateReply native step index
          case reply of
            Nothing -> pure 0
            Just body -> case step of
              1 -> do
                unless (B.length body == 16) (ioError (userError "invalid candidate hex snapshot"))
                let field 1 = pure (ParentReplay.replayWord (B.take 8 body))
                    field 2 = pure (ParentReplay.replayWord (B.drop 8 body))
                    field 4 = pure 1
                    field _ = ioError (userError "invalid candidate hex field")
                status <- validate (ReadExecution 0 2 0 field)
                pure (if status == 0 then 1 else if status == 1 then 0 else -1)
              5 -> pure $ if slot >= 0 && slot <= 255 && B.length body == 4 &&
                ParentReplay.treasurySlot (fromIntegral (ParentReplay.replayWord body)) 0xb4 == slot
                then 1 else 0
              _ -> do
                value <- constructionWord body
                pure (if value <= 1 then fromIntegral value else -1)
    status <- liftIO (validate (CtipSearch count action))
    case status of
      0 -> liftIO (constructionEffect native 11 (wordLE 8 (fromIntegral (validate (PreviousSequence sequenceNumber)))))
      1 -> throwE 3
      2 -> throwE 4
      _ -> throwE (-1)

instance ConfirmationHeaders Construction where
  readConfirmationHeaders (Construction _ height _ _ native) = do
    tip <- fromIntegral <$> liftIO (constructionScalar native 12 0)
    let first = fromIntegral height
    unless (headerWindow first tip) (throwE 5)
    liftIO (constructionEffect native 20 B.empty)
    forM_ [first..fromIntegral tip] $ \current -> do
      valid <- constructionFlag =<< liftIO (constructionScalar native 21 current)
      unless valid (throwE 6)
      liftIO (constructionEffect native 22 B.empty)

constructEvidence :: (DepositSource op, PriorTreasury op, ConfirmationHeaders op) => op -> ConstructionCheck ()
constructEvidence value = readDepositSource value >> readPriorTreasury value >> readConfirmationHeaders value

type ConstructionCapabilities = '[DepositSource, PriorTreasury, ConfirmationHeaders]
instance Operation Construction ConstructionCapabilities where
  type Context Construction = CapabilityContext ConstructionCapabilities Construction
  type Outcome Construction = IO Int32
  data DSL Construction where
    ReconstructEvidence :: Context Construction => DSL Construction
  interpret operation request = withOperation @Construction operation $ \value -> case request of
    ReconstructEvidence -> Just (either id (const 0) <$> runExceptT (constructEvidence value))

-- Borrowed witness fields remain live for this synchronous request. The same
-- evidence/witness rules serve both this workflow and their independent APIs.
data Parsing = Parsing Word64 Word64 Word64 DeterministicEvidence
  (Ptr Int64 -> DepositWitness) NativeBytes
class EvidenceParsing op where
  parseEvidence :: op -> ConstructionCheck ()
class InclusionVerification op where
  verifyInclusion :: op -> ConstructionCheck ()
class TreasuryVerification op where
  verifyTreasury :: op -> ConstructionCheck ()
class DestinationSelection op where
  selectDestination :: op -> ConstructionCheck ()
class DepositPublication op where
  publishDeposit :: op -> ConstructionCheck ()

parseChecked :: Int32 -> IO a -> ConstructionCheck a
parseChecked failure action = do
  result <- liftIO (try action)
  case result of
    Left (_ :: SomeException) -> throwE failure
    Right value -> pure value

parseStatus :: Int32 -> Int32 -> ConstructionCheck ()
parseStatus group status = unless (status == 0) (throwE (group+status))

parseFlag :: NativeBytes -> Word32 -> Word64 -> ConstructionCheck Bool
parseFlag native step index = constructionFlag =<< liftIO (constructionScalar native step index)

parsingInt32 :: NativeBytes -> Word32 -> Word64 -> IO Int32
parsingInt32 native step index = do
  value <- constructionScalar native step index
  if value <= fromIntegral (maxBound :: Int32) || value >= fromIntegral (minBound :: Int32)
    then pure (fromIntegral value) else ioError (userError "invalid parsing int32 reply")

instance EvidenceParsing Parsing where
  parseEvidence (Parsing inputs index witnesses evidence _ native) = do
    unless (index < inputs && index < witnesses) (throwE 1)
    status <- parseChecked (-2) (validate evidence)
    parseStatus 0x100 status
    liftIO (constructionEffect native 0 B.empty)
    forM_ [1..3] $ \step -> parseFlag native step 0 >>= \valid -> unless valid (throwE 2)

instance InclusionVerification Parsing where
  verifyInclusion (Parsing _ _ _ _ _ native) = do
    row <- liftIO (native 4 0 B.empty)
    unless (B.length row == 24) (throwE (-1))
    let word offset = ParentReplay.replayWord (B.take 8 (B.drop offset row))
    when (word 0 > fromIntegral (maxBound :: Word32) || word 16 > fromIntegral (maxBound :: Word32)) (throwE (-1))
    status <- parseChecked (-3) (checkInclusion (fromIntegral (word 0)) (word 8) (fromIntegral (word 16))
      (\index -> parsingInt32 native 5 (fromIntegral index)))
    parseStatus 0x200 status
    liftIO (constructionEffect native 6 B.empty)

historicalTreasury :: B.ByteString -> Bool
historicalTreasury script = B.length script == 4 &&
  ParentReplay.treasurySlot (fromIntegral (ParentReplay.replayWord script)) 0xb4 == fromIntegral sidechainSlot

instance TreasuryVerification Parsing where
  verifyTreasury (Parsing _ _ _ _ witness native) = do
    count <- liftIO (constructionScalar native 7 0)
    let scan index matches
          | index == count = pure matches
          | otherwise = do
              hashMatches <- parseFlag native 8 index
              bounded <- if hashMatches then parseFlag native 9 index else pure False
              matchesScript <- if bounded then historicalTreasury <$> liftIO (native 10 index B.empty) else pure False
              if matchesScript then do
                reply <- liftIO (native 11 index B.empty)
                unless (B.null reply) (throwE (-1))
                scan (index+1) (matches+1)
              else scan (index+1) matches
    matches <- scan 0 0
    previous <- if matches == 0 then pure 0 else fromIntegral <$> liftIO (constructionScalar native 12 0)
    (decoded,value) <- parseChecked (-5) $ allocaBytes 8 $ \output -> do
      poke output 0
      result <- validate (witness output)
      amount <- peek output
      pure (result /= 0,amount)
    liftIO (constructionEffect native 13 (wordLE 8 (fromIntegral value)))
    treasury <- historicalTreasury <$> liftIO (native 14 0 B.empty)
    current <- fromIntegral <$> liftIO (constructionScalar native 15 0)
    let facts = fromIntegral (fromEnum treasury) .|. (fromIntegral (fromEnum decoded) `shiftL` 1)
    parseStatus 0x200 (validate (DepositCtip facts matches current previous value))

instance DestinationSelection Parsing where
  selectDestination (Parsing _ _ _ _ _ native) = do
    count <- liftIO (constructionScalar native 16 0)
    when (count > fromIntegral (maxBound :: Word32)) (throwE (-4))
    result <- parseChecked (-4) (destinationScan (fromIntegral count)
      (\index step -> parsingInt32 native (20+step) (fromIntegral index)))
    when (result < 0) (throwE (0x300-fromIntegral result))

instance DepositPublication Parsing where
  publishDeposit (Parsing _ _ _ _ _ native) = liftIO (constructionEffect native 24 B.empty)

parseDeposit :: (EvidenceParsing op, InclusionVerification op, TreasuryVerification op,
  DestinationSelection op, DepositPublication op) => op -> ConstructionCheck ()
parseDeposit value = parseEvidence value >> verifyInclusion value >> verifyTreasury value >>
  selectDestination value >> publishDeposit value

type ParsingCapabilities = '[EvidenceParsing, InclusionVerification, TreasuryVerification, DestinationSelection, DepositPublication]
instance Operation Parsing ParsingCapabilities where
  type Context Parsing = CapabilityContext ParsingCapabilities Parsing
  type Outcome Parsing = IO Int32
  data DSL Parsing where
    ParseDeposit :: Context Parsing => DSL Parsing
  interpret operation request = withOperation @Parsing operation $ \value -> case request of
    ParseDeposit -> Just (either id (const 0) <$> runExceptT (parseDeposit value))

-- One borrowed transaction view serves lookup, legacy authentication and claim
-- verification. Each constructor selects a capability after payload equality.
data Claim = Claim Word64 Word64 Word64 Word64
  (Word32 -> Ptr Int64 -> DepositWitness) NativeBytes
class CheckpointDiscovery op where
  discoverCheckpoint :: op -> ConstructionCheck ()
class LegacyAuthentication op where
  authenticateLegacy :: op -> ConstructionCheck ()
class TransactionVerification op where
  verifyClaimTransaction :: op -> ConstructionCheck ()

claimWitness :: Claim -> Word32 -> ConstructionCheck (Bool,Int64)
claimWitness (Claim _ _ _ _ witness _) mode = parseChecked (-5) $ allocaBytes 8 $ \output -> do
  poke output 0
  kind <- validate (witness mode output)
  value <- peek output
  pure (kind /= 0,value)

instance CheckpointDiscovery Claim where
  discoverCheckpoint value@(Claim inputs index witnesses _ _ native) = do
    unless (index < inputs && index < witnesses) (throwE 1)
    (eligible,_) <- claimWitness value 3
    -- The old native call evaluated both hashes even when eligibility was false.
    identity <- liftIO (native 0 0 B.empty)
    unless (B.length identity == 68) (throwE (-2))
    let previous = B.take 32 (B.drop 32 identity)
        vout = ParentReplay.replayWord (B.drop 64 identity)
        record = if eligible && vout == 0 then checkpointRecord (B.take 32 identity) previous else B.empty
    when (B.null record) (throwE 1)
    unless (B.length record == 136) (throwE (-2))
    liftIO (constructionEffect native 1 record)

instance LegacyAuthentication Claim where
  authenticateLegacy value@(Claim _ _ _ _ _ native) = do
    (decoded,actual) <- claimWitness value 1
    destination <- parseFlag native 10 0
    expected <- fromIntegral <$> liftIO (constructionScalar native 11 0)
    parseStatus 0 (validate (LegacyClaim (fromIntegral (fromEnum decoded) .|.
      (fromIntegral (fromEnum destination) `shiftL` 1)) actual expected))
    liftIO (constructionEffect native 12 B.empty)

instance TransactionVerification Claim where
  verifyClaimTransaction value@(Claim inputs index witnesses outputs _ native) = do
    (facts,witnessed) <- if inputs == 1 && index == 0 && witnesses == 1 then do
      inputFacts <- liftIO (constructionScalar native 20 0)
      when (inputFacts > 15) (throwE (-1))
      if inputFacts /= 15 then pure (fromIntegral inputFacts,0) else do
        (decoded,amount) <- claimWitness value 1
        projected <- liftIO (native 21 0 (B.singleton (fromIntegral (fromEnum decoded))))
        flags <- liftIO (constructionWord projected)
        when (flags > 3) (throwE (-1))
        pure (15 .|. (fromIntegral (fromEnum decoded) `shiftL` 4) .|. (fromIntegral flags `shiftL` 5),amount)
      else pure (0,0)
    -- Output projection historically follows even a failed input preflight.
    outs <- mapM (\i -> do
      row <- liftIO (native 22 i B.empty)
      unless (B.length row == 16) (throwE (-1))
      let flags = ParentReplay.replayWord (B.take 8 row)
          amount = fromIntegral (ParentReplay.replayWord (B.drop 8 row))
      when (flags > 255) (throwE (-1))
      pure (fromIntegral flags,amount)) (take (fromIntegral (min 2 outputs)) [0..])
    claimed <- fromIntegral <$> liftIO (constructionScalar native 23 0)
    parseStatus 0 (validate (AuthenticatedDeposit inputs index witnesses facts claimed witnessed outputs outs))

type ClaimCapabilities = '[CheckpointDiscovery, LegacyAuthentication, TransactionVerification]
instance Operation Claim ClaimCapabilities where
  type Context Claim = CapabilityContext ClaimCapabilities Claim
  type Outcome Claim = IO Int32
  data DSL Claim where
    DiscoverCheckpoint :: Context Claim => DSL Claim
    AuthenticateLegacy :: Context Claim => DSL Claim
    VerifyClaimTransaction :: Context Claim => DSL Claim
  interpret operation request = withOperation @Claim operation $ \value ->
    let run = Just . fmap (either id (const 0)) . runExceptT
    in case request of
      DiscoverCheckpoint -> run (discoverCheckpoint value)
      AuthenticateLegacy -> run (authenticateLegacy value)
      VerifyClaimTransaction -> run (verifyClaimTransaction value)

data TreasuryDelta = TreasuryDelta Int64 Int64 Int64 Int64
instance Validation TreasuryDelta where
  type ValidationResult TreasuryDelta = Bool
  validate (TreasuryDelta previous current claimed maximumValue) =
    current >= 0 && current <= maximumValue && current > previous &&
      toInteger current - toInteger previous == toInteger claimed

data Preflight = Preflight Word32 Int64 Int64
instance Validation Preflight where
  type ValidationResult Preflight = Int32
  validate (Preflight rule amount bound) = case rule of
    0 -> accepted (amount > 0 && amount <= bound)
    1 -> accepted (amount >= 0 && amount <= bound)
    2 -> accepted (amount > 0)
    3 -> accepted (amount >= 0 && amount < bound)
    4 -> accepted (amount >= 0 && amount <= 4294967295)
    10 -> accepted (amount == 0)
    11 -> accepted (amount <= bound)
    _ | rule==5 || rule==9 -> accepted (amount == 1)
      | rule>=6 && rule<=8 -> accepted (amount == 1 && bound == 1)
      | otherwise -> -1
    where accepted condition = if condition then 1 else 0

data DefaultWalletFlow = DefaultWalletFlow Word32 Word32
instance Validation DefaultWalletFlow where
  type ValidationResult DefaultWalletFlow = Int32
  validate (DefaultWalletFlow phase result) = transition phase result
    [(1,(2,-11)),(2,(3,4)),(4,(5,-11))]

data NativeImportFlow = NativeImportFlow Word32 Word32
instance Validation NativeImportFlow where
  type ValidationResult NativeImportFlow = Int32
  validate (NativeImportFlow phase result) = transition phase result
    [(1,(2,3)),(3,(-1,4)),(4,(6,5)),(5,(-1,6)),(6,(-1,-11))]

data BlockPreflightFlow = BlockPreflightFlow Word32 Word32
instance Validation BlockPreflightFlow where
  type ValidationResult BlockPreflightFlow = Int32
  validate (BlockPreflightFlow phase result) = transition phase result
    [(1,(-11,2)),(2,(-1,3)),(3,(-11,4)),(4,(5,17)),(5,(-1,6)),
     (6,(17,7)),(7,(16,8)),(8,(-1,9)),(9,(13,10)),(10,(11,14)),
     (11,(13,12)),(12,(-10,-10)),(13,(-10,-10)),(14,(18,15)),
     (15,(19,16)),(16,(-1,6)),(17,(-1,3)),(18,(-10,-10)),(19,(-10,-10))]

data MempoolWitnessFlow = MempoolWitnessFlow Word32 Word32
instance Validation MempoolWitnessFlow where
  type ValidationResult MempoolWitnessFlow = Int32
  validate (MempoolWitnessFlow phase result) = transition phase result
    [(1,(-11,2)),(2,(14,3)),(3,(-1,4)),(4,(5,6)),(5,(-1,14)),
     (6,(7,11)),(7,(10,8)),(8,(14,9)),(9,(-1,14)),(10,(-1,14)),
     (11,(12,13)),(12,(-1,14)),(13,(10,14)),(14,(-1,1))]

data ImportFlow = ImportFlow Word32 Word32
instance Validation ImportFlow where
  type ValidationResult ImportFlow = Int32
  validate (ImportFlow phase result) = transition phase result
    [(1,(-1,2)),(2,(4,3)),(3,(-1,4)),(4,(-1,5)),(5,(6,7)),
     (7,(8,9)),(9,(-1,10)),(10,(-1,-11))]

data SponsorshipFlow = SponsorshipFlow Word32 Word32
instance Validation SponsorshipFlow where
  type ValidationResult SponsorshipFlow = Int32
  validate (SponsorshipFlow phase result) = transition phase result
    [(1,(2,3)),(3,(4,5)),(5,(-1,6)),(6,(10,7)),(7,(9,8)),(9,(-1,6)),(10,(11,-11))]

data SatoshiFlow = SatoshiFlow Word32 Word32
instance Validation SatoshiFlow where
  type ValidationResult SatoshiFlow = Int32
  validate (SatoshiFlow 0 _) = 6
  validate (SatoshiFlow phase result) = transition phase result
    [(1,(3,2)),(2,(-1,-11)),(3,(5,4)),(4,(5,-11)),(6,(1,7)),(7,(1,-11))]

data BroadcastFlow = BroadcastFlow Word32 Word32
data MessageMatches = MessageMatches Word32 B.ByteString
instance Validation MessageMatches where
  type ValidationResult MessageMatches = Int32
  validate (MessageMatches kind message) = case lookup kind
    [(0,"already in block chain"),(1,"txn-already-in-mempool"),(2,"multiple slot CTIP")] of
      Nothing -> -1
      Just needle -> if C.pack needle `B.isInfixOf` message then 1 else 0

instance Validation BroadcastFlow where
  type ValidationResult BroadcastFlow = Int32
  validate (BroadcastFlow phase result) = transition phase result
    [(1,(2,-11)),(2,(3,-12)),(3,(4,-11)),(4,(5,-11))]

data EventLayout = EventLayout Word32 Word32 Word32
instance Validation EventLayout where
  type ValidationResult EventLayout = Maybe (B.ByteString, Maybe B.ByteString, Bool)
  validate (EventLayout kind index status)
    | (kind == 4 || kind == 9) && status > 2 = error "invalid event layout status"
    | fromIntegral index >= length layout = Nothing
    | otherwise = let (key,value) = layout !! fromIntegral index
                  in Just (C.pack key, C.pack <$> value, fromIntegral index + 1 == length layout)
    where
      dynamic key = (key,Nothing)
      literal key value = (key,Just value)
      header source name state = [dynamic "event_id", literal "source" source,
                                  literal "kind" name, literal "status" state]
      fields = map dynamic
      layout = case kind of
        0 -> header "sidechain" "bundle_commitment" "sidechain_committed" ++ fields ["m6id","sidechain"]
        1 -> header "sidechain" "deposit" "sidechain_confirmed" ++ fields
          ["sidechain_txid","vin","mainchain_txid","mainchain_vout","value_sats","asset","claim_script","sidechain"]
        2 -> header "sidechain" "withdrawal" "sidechain_confirmed" ++ fields
          ["sidechain_txid","vout","value_sats","asset","mainchain_genesis_hash","mainchain_script"]
        3 -> header "l1" "deposit" "l1_confirmed" ++ fields
          ["sidechain_id","sequence_number","mainchain_txid","mainchain_vout","address_hex","value_sats"]
        4 -> header "l1" "withdrawal_bundle" (withdrawalStatuses !! fromIntegral status) ++ fields ["sidechain_id","m6id"]
        5 -> fields ["m6id"]
        6 -> fields ["sidechain"]
        7 -> fields ["sequence_number"]
        8 -> fields ["mainchain_transaction"]
        9 -> [literal "acknowledgement" (snd (withdrawalLifecycle !! fromIntegral status))]
        10 -> fields ["l1"]
        11 -> fields ["block_hash","height"]
        12 -> fields ["block_hash"]
        13 -> fields ["height"]
        14 -> fields ["timestamp"]
        15 -> fields ["sidechainId","valueSats","height","criticalHash","prevBytes"]
        16 -> fields ["hex"]
        17 -> fields ["sidechainId","endBlockHash"]
        _ -> error "invalid event layout kind"

data EventIdentity = EventIdentity Word32 B.ByteString Word64 Word32
instance Validation EventIdentity where
  type ValidationResult EventIdentity = B.ByteString
  validate (EventIdentity kind hash number status) = C.intercalate (C.pack ":") $
    case kind of
      0 -> fields "sidechain:bundle" signed
      1 -> fields "sidechain:deposit" unsigned
      2 -> fields "sidechain:withdrawal" unsigned
      3 -> fields "l1:deposit" signed
      4 | status < 3 -> [C.pack "l1:withdrawal", hash,
                         C.pack (withdrawalStatuses !! fromIntegral status), signed]
      _ -> error "invalid peg event identity kind or status"
    where
      signed = C.pack (show (fromIntegral number :: Int64))
      unsigned = C.pack (show number)
      fields prefix suffix = [C.pack prefix, hash, suffix]

data ReadExecution = ReadExecution Word32 Word32 Word64 (Word32 -> IO Word64)
instance Validation ReadExecution where
  type ValidationResult ReadExecution = IO Int32
  validate (ReadExecution mode kind limit action)
    | mode > 1 || (mode == 1 && (kind /= 0 || limit /= 0)) = pure minBound
    | otherwise = run (next 0 0)
    where
      next phase value | mode == 0 = validate (PegSchema kind phase value limit)
                       | otherwise = fromIntegral (validate (DepositProjection phase value))
      run command
        | command <= 0 = pure (if command < -1 then minBound else fromIntegral (-command))
        | step < 1 || step > (if mode == 0 then 5 else 10) = pure minBound
        | otherwise = do
            value <- action (fromIntegral step)
            if testBit command 8 then pure (if value == 1 then 0 else 1)
              else run (next (fromIntegral step) value)
        where step = clearBit command 8

data PegEvent = PegEvent Word32 Int64 Int64 Int64 | WithdrawalStatusFlow Word32 Word32
             | L1Normalization Word32 Word32
             | SidechainEvents Word32 Word32
             | WithdrawalStatus Int64 B.ByteString
             | L1Location Word32 Word32
             | PegSchema Word32 Word32 Word64 Word64
instance Validation PegEvent where
  type ValidationResult PegEvent = Int64
  validate (PegSchema kind phase value limit) = case (kind,phase) of
    (0,0) -> 1
    (0,1) -> branch 0 (-1)
    (1,0) -> 1
    (1,1) -> branch 258 3
    (1,3) -> branch 4 (-1)
    (1,4) -> branch 261 (-1)
    (2,0) -> 1
    (2,1) -> branch 2 (-1)
    (2,2) -> branch (if limit == 0 then 260 else 3) (-1)
    (2,3) -> if limit == 0 || value == limit * 2 then 260 else -1
    (3,0) -> 1
    (3,1) -> branch 3 258
    (3,3) -> branch 260 261
    (4,0) -> 1
    (4,1) -> branch 258 259
    (5,0) -> 1
    (5,1) -> branch 2 (-1)
    (5,2) -> branch (-1) 0
    (6,0) -> 1
    (6,1) -> branch 258 0
    _ -> error "invalid peg schema phase"
    where branch yes no = case value of
            1 -> yes
            0 -> no
            _ -> error "invalid peg schema predicate"
  validate (WithdrawalStatus state status) = validate (PegEvent 2 state ordinal 0)
    where ordinal = maybe 3 fromIntegral (elemIndex (C.unpack status) withdrawalStatuses)
  validate (L1Location phase result)
    | result > 1 = error "invalid L1 location result"
    | otherwise = case phase of
        0 -> 1
        1 -> next 2
        2 -> next 3
        3 -> next 4
        4 -> if result == 1 then 5 else 256 + 6
        5 -> next (256 + 6)
        _ -> error "invalid L1 location phase"
    where next step = if result == 1 then step else -1
  validate (SidechainEvents phase result)
    | result > 1 = error "invalid sidechain event result"
    | otherwise = case phase of
        0 -> 1
        1 -> if ok then 2 else 4
        2 -> if ok then 3 else 4
        3 -> next 4
        4 -> if ok then 5 else 256 + 27
        5 -> next 6
        6 -> if ok then 7 else 11
        7 -> if ok then 8 else 10
        8 -> if ok then 9 else 10
        9 -> next 10
        10 -> next 6
        11 -> if ok then 12 else 26
        12 -> if ok then 13 else 25
        13 -> if ok then 14 else 25
        14 -> if ok then 15 else 25
        15 -> if ok then 16 else 25
        16 -> if ok then 17 else 25
        17 -> next 18
        18 -> if ok then 19 else 20
        19 -> next 20
        20 -> next 25
        25 -> next 11
        26 -> next 4
        _ -> error "invalid sidechain event phase"
    where
      ok = result == 1
      next step = if ok then step else -1
  validate (L1Normalization phase result)
    | result > 1 = error "invalid L1 normalization result"
    | otherwise = case phase of
        0 -> 1
        1 -> if ok then 2 else 3
        2 -> next 4
        3 -> -1
        4 -> if ok then 5 else 256 + 34
        5 -> if ok then 6 else 7
        6 -> next 8
        7 -> -1
        8 -> if ok then 32 else 9
        9 -> if ok then 10 else 11
        10 -> next 12
        11 -> -1
        12 -> if ok then 13 else 32
        13 -> if ok then 14 else 15
        14 -> if ok then 16 else 17
        15 -> -1
        16 -> next 27
        17 -> if ok then 18 else 31
        18 -> next 19
        19 -> if ok then 20 else 21
        20 -> next 21
        21 -> if ok then 22 else 23
        22 -> next 23
        23 -> next 27
        27 -> next 28
        28 -> if ok then 29 else 30
        29 -> next 31
        30 -> if ok then 31 else 33
        31 -> next 12
        32 -> next 4
        33 -> -1
        _ -> error "invalid L1 normalization phase"
    where
      ok = result == 1
      next step = if ok then step else -1
  validate (WithdrawalStatusFlow phase result)
    | result > 1 = error "invalid withdrawal status action result"
    | otherwise = case phase of
        0 -> 1
        1 -> if ok then 2 else 3
        2 -> next 4
        3 -> -1
        4 -> if ok then 5 else 256 + 17
        5 -> if ok then 6 else 16
        6 -> if ok then 7 else 16
        7 -> if ok then 8 else 16
        8 -> if ok then 9 else 16
        9 -> if ok then 10 else 11
        10 -> if ok then 12 else 11
        11 -> -1
        12 -> if ok then 13 else 16
        13 -> if ok then 14 else 15
        14 -> next 16
        15 -> -1
        16 -> next 4
        _ -> error "invalid withdrawal status phase"
    where
      ok = result == 1
      next step = if ok then step else -1
  validate (PegEvent kind a b c) = case kind of
    0 | a < 0 || a > 7 || b < 0 || b > 7 -> -6
      | otherwise -> case [i | i <- [0..2], testBit a i] of
          [i] -> if testBit b i then fromIntegral i else -2
          _ -> -1
    1 -> if a >= 0 && b > 0 && c >= 0 then 0 else -3
    2 | a < 0 || a > 3 || b < 0 || b > 3 -> -6
      | b == 3 -> -4
      | b == 0 -> max 1 a
      | a > 1 && a /= b + 1 -> -5
      | otherwise -> b + 1
    _ -> -6

-- The native reader supplies four initialized Int64 fields per requested step.
-- 0 preserves a parser error, 1 succeeds; other statuses are adapter faults.
type ReadPegFields = Ptr () -> Word32 -> Ptr Int64 -> IO Int32
foreign import ccall safe "dynamic" readPegFields :: FunPtr ReadPegFields -> ReadPegFields
type EvidenceFields = (Int64, Int64, Int64, Int64)
data EvidencePlan = EvidenceDone Int32 | EvidenceRead Word32 (EvidenceFields -> EvidencePlan)
data LiveEvidence = LiveEvidence Word32 (FunPtr ReadPegFields) (Ptr ())
instance Validation LiveEvidence where
  type ValidationResult LiveEvidence = IO Int32
  validate (LiveEvidence phase reader context) = run (liveEvidencePlan phase)
    where
      run (EvidenceDone result) = pure result
      run (EvidenceRead step next) = do
        snapshot <- allocaBytes 32 $ \output -> do
          pokeArray output (replicate 4 (0 :: Int64))
          status <- readPegFields reader context step output
          if status == 0 then pure Nothing else if status /= 1 then error "live evidence reader fault"
          else Just <$> ((,,,) <$> peekElemOff output 0 <*> peekElemOff output 1 <*>
            peekElemOff output 2 <*> peekElemOff output 3)
        maybe (pure (-1)) (run . next) snapshot

-- A suspended request owns only immutable Haskell values, never native buffers.
liveEvidencePlan :: Word32 -> EvidencePlan
liveEvidencePlan phase = case phase of
    0 -> fields 0 $ \(slot,network,genesis,_) ->
      require (slot >= 0 && slot <= 255) 1 $
      require (network /= 0) 2 $ require (genesis /= 0) 3 $
      fields 1 $ \(object,chain,_,_) -> require (object /= 0) 4 $ require (chain /= 0) 5 $
      fields 2 $ \(challenge,_,_,_) -> require (challenge /= 0) 6 $
      fields 3 $ \(synced,_,_,_) -> require (synced /= 0) 7 $
      fields 4 $ \(enforcer,enforcerNetwork,_,_) -> require (enforcer /= 0 && enforcerNetwork /= 0) 8 $
      fields 5 $ \(hash,height,expected,_) -> require (hash /= 0 && height == expected) 9 (EvidenceDone 0)
    1 -> fields 0 $ \(object,_,_,_) -> require (object /= 0) 10 $
      fields 1 $ \(confirmations,height,expected,_) -> require (confirmations > 0) 11 $
      require (height == expected) 12 $ fields 2 $ \(valid,match,_,_) ->
      require (valid /= 0) 13 $ require (match /= 0) 14 (EvidenceDone 0)
    2 -> fields 0 $ \(object,_,_,_) -> require (object /= 0) 15 $
      fields 1 $ \(confirmations,_,_,_) -> require (confirmations > 0) 16 $
      fields 2 $ \(present,value,expected,_) -> require (present /= 0 && value == expected) 17 (EvidenceDone 0)
    3 -> fields 0 $ \(vout,_,_,_) -> validVout vout $
      fields 1 $ \(value,sequenceNumber,depositSequence,match) ->
      require (value > 0 && sequenceNumber >= 0) 18 $
      require (sequenceNumber >= depositSequence) 19 $
      require (sequenceNumber /= depositSequence || match /= 0) 20 (EvidenceDone 0)
    4 -> fields 0 $ \(count,_,_,_) -> bounded count $ slots count False
    5 -> fields 0 $ \(count,_,_,_) -> bounded count $ blocks count False
    _ -> error "invalid live evidence phase"
    where
      require accepted failure next = if accepted then next else EvidenceDone failure
      bounded count next = if count < 0 then error "invalid evidence array count" else next
      validVout value = require (value >= 0 && value <= 0xffffffff) 35
      address 0 next = next
      address count next = fields 9 $ \(a,b,c,d) ->
        require (all (\byte -> byte >= 0x21 && byte <= 0x7e) (take (fromIntegral (min 4 count)) [a,b,c,d])) 37 $
          address (max 0 (count-4)) next
      slots 0 found = require found 23 $
        fields 3 $ \(height,tip,_,_) -> require (height >= 0 && height <= tip) 24 $
        fields 4 $ \(title,_,_,_) -> require (title /= 0) 25 $
        fields 5 $ \(hash1,_,_,_) -> require (hash1 /= 0) 25 $
        fields 6 $ \(hash2,_,_,_) -> require (hash2 /= 0) 25 (EvidenceDone 0)
      slots count found = fields 1 $ \(object,slot,expected,_) -> require (object /= 0) 21 $
        if slot /= expected then slots (count-1) found else require (not found) 22 $
          fields 2 $ \_ -> slots (count-1) True
      blocks 0 found = require found 34 (EvidenceDone 0)
      blocks count found = fields 1 $ \(object,_,_,_) -> require (object /= 0) 26 $
        fields 2 $ \(kind,size,_,_) -> if kind == 0 then blocks (count-1) found else
          require (kind == 1) 27 $ bounded size $ events (count-1) size found
      events remaining 0 found = blocks remaining found
      events remaining count found = fields 3 $ \(object,_,_,_) -> require (object /= 0) 28 $
        fields 4 $ \(present,valid,_,_) -> if present == 0 then next found else require (valid /= 0) 29 $
        fields 5 $ \(match,vout,_,_) -> validVout vout $
        if match == 0 then next found else require (not found) 30 $
        fields 6 $ \(value,expected,sequenceNumber,_) -> require (value > 0 && value == expected) 31 $
          require (sequenceNumber >= 0) 32 $ fields 7 $ \(size,_,_,_) -> bounded size $ require (size /= 0) 36 $
          address size $ fields 8 $ \(destination,_,_,_) -> require (destination /= 0) 33 $
          fields 10 $ \_ -> next True
        where next = events remaining (count-1)

      fields = EvidenceRead

-- Immutable historical records, in native hash order and DataStream field order.
-- These private ABI bytes do not change any transaction or persisted-state format.
legacyCheckpoints :: [(B.ByteString, B.ByteString, B.ByteString)]
legacyCheckpoints =
  [ row "feed724d3382997ae6500d8185353e116d557a4f299b58e8f722c1aa400ab730"
        "000001d9988239435d51e763fd4231893dad22d7d03048266a5e21361e2db065"
        "7de4aeb747a54bbe6b590d2038f445b9dc995217fb1b4e524c4129cdd0f06bea"
        2000 14402000 8 "ert1q9263y9nqf2kwjl7hrhsgewefq7859w93z5n8x8"
  , row "7d78b50fa26e51ca01d1a916820971e46dd6d11e8da7c06571b95d8c6dd4a382"
        "00000268748226d792c32914d26f5608a766a13741f3762c35cb053084ac4d1c"
        "010a70b5e1fca8e8433dd2efc7c3b8f0783e98b133bbf03bcbe05cdd29a4edab"
        100000 14400000 7 "ert1q2d25juv3qvlk90pfsnqed7f9wzzgevp8y2vfmv" ]
  where
    row txid parent outpoint value ctip sequenceNumber address =
      let previous = hash outpoint; destination = C.pack address
      in (hash txid, previous, hash parent <> previous <> wordLE 4 0 <>
          B.concat (map (wordLE 8) [value,ctip,sequenceNumber]) <>
          B.singleton (fromIntegral (B.length destination)) <> destination)
    hash = B.reverse . B.pack . pairs
    pairs [] = []
    pairs (a:b:rest) = fromIntegral (digitToInt a * 16 + digitToInt b) : pairs rest
    pairs _ = error "malformed checkpoint constant"

data CheckpointLookup = CheckpointLookup Word32 (Ptr Word8) (Ptr Word8) Word32
instance Validation CheckpointLookup where
  type ValidationResult CheckpointLookup = IO B.ByteString
  validate (CheckpointLookup eligible txid previous vout)
    | eligible > 1 = error "invalid checkpoint eligibility"
    | eligible == 0 || vout /= 0 = pure B.empty
    | otherwise = do
        identity <- copyBytes txid 32
        outpoint <- copyBytes previous 32
        pure (checkpointRecord identity outpoint)

checkpointRecord :: B.ByteString -> B.ByteString -> B.ByteString
checkpointRecord identity outpoint = maybe B.empty (\(_,_,record) -> record) $
  find (\(known,prior,_) -> identity == known && outpoint == prior) legacyCheckpoints

-- Facts: witness decoded, destination accepted by the upstream address decoder.
data LegacyClaim = LegacyClaim Word32 Int64 Int64
instance Validation LegacyClaim where
  type ValidationResult LegacyClaim = Int32
  validate (LegacyClaim facts actual expected)
    | facts .&. 1 == 0 || actual /= expected = 1
    | facts .&. 2 == 0 = 2
    | otherwise = 0

-- Actions 0/1 read each opcode (1 also returns nonempty/consumed bits),
-- 2 decodes the address, and 3 publishes a valid candidate. No callback reentry.
type InspectDestination = Ptr () -> Word32 -> Word32 -> IO Int32
foreign import ccall unsafe "dynamic" inspectDestination :: FunPtr InspectDestination -> InspectDestination
data DepositDestination = DepositDestination Word32 (FunPtr InspectDestination) (Ptr ())
instance Validation DepositDestination where
  type ValidationResult DepositDestination = IO Int64
  validate (DepositDestination count inspector context) = destinationScan count (inspectDestination inspector context)

destinationScan :: Word32 -> (Word32 -> Word32 -> IO Int32) -> IO Int64
destinationScan count inspect = go 0 Nothing
    where
      go index found
        | index == count = pure (maybe (-1) fromIntegral found)
        | otherwise = do
            first <- inspect index 0
            if first < 0 || first > 511 then error "destination first opcode adapter fault" else pure ()
            second <- inspect index 1
            if second < 0 || second > 2047 then error "destination second opcode adapter fault" else pure ()
            let script = first .|. (second `shiftL` 9)
            if script .&. 511 /= 106 || (script `shiftR` 9) .&. 511 > 78 ||
                    (script `shiftR` 18) .&. 3 /= 3 then go (index+1) found
            else do
              decoded <- inspect index 2
              if decoded == 1 then do
                published <- inspect index 3
                if published == 1 then pure () else error "destination publication adapter fault"
              else pure ()
              case (decoded,found) of
                (0,_) -> go (index+1) found
                (1,Nothing) -> go (index+1) (Just index)
                (1,Just _) -> pure (-2)
                _ -> error "destination decoder adapter fault"

-- Phases retain the native caller's ordering around parsing and coin storage.
data DepositStatePhase = CheckCheckpoint | CheckPrior | ConnectPrior | DisconnectPresent
  | DisconnectCheckpoint | DisconnectCurrent | CheckCheckpointAnchor | CheckAnchor
  deriving (Enum, Bounded)

-- Facts: state present, decoding failed, state/anchor matches its expected value.
data DepositStateWorkflow = DepositStateWorkflow Word32 (Word32 -> IO Int64)
instance Validation DepositStateWorkflow where
  type ValidationResult DepositStateWorkflow = IO Int32
  validate (DepositStateWorkflow start native)
    | start `notElem` [0,11,19,27] = pure (-1)
    | otherwise = validate (PredicateFlow True start 82
        (\phase result -> fromIntegral (validate (DepositVerification phase result))) readFact)
    where
      readFact step = do
        result <- native step
        case lookup step [(2,0),(9,1),(25,2),(28,3),(30,4),(33,5),(13,6),(17,7)] of
          Nothing -> pure result
          Just phase | result < 0 || result > 7 -> pure (-1)
                     | otherwise -> case validate (DepositStateRule phase (fromIntegral result)) of
                         0 -> pure 1
                         code | code > 0 && code <= 11 -> do
                           published <- native (82+fromIntegral code)
                           pure (if published == 1 then 0 else -1)
                         _ -> pure (-1)

data DepositStateRule = DepositStateRule Word32 Word32 | DepositVerification Word32 Word32
                     | DepositProjection Word32 Word64
instance Validation DepositStateRule where
  type ValidationResult DepositStateRule = Int32
  validate (DepositProjection phase value) = case phase of
    0 -> 1
    1 -> if value == 1 then 2 else 7
    2 -> if value == 0 then 3 else 7
    3 -> if value == 1 then 4 else 7
    4 -> if value == 15 then 5 else 7
    5 -> 7
    7 -> if value > 0 then 8 else 0
    8 -> 9
    9 -> if value > 1 then 10 else 0
    10 -> 0
    _ -> error "invalid deposit projection phase"
  validate (DepositVerification phase result)
    | result > 1 = error "invalid deposit verification result"
    | otherwise = case phase of
        0 -> 1
        1 -> if ok then 2 else 5
        2 -> next 3
        3 -> next 4
        4 -> next 0
        5 -> if ok then 6 else 8
        6 -> if ok then 7 else 8
        7 -> -1
        8 -> next 9
        9 -> next 10
        10 -> next 0
        11 -> 12
        12 -> if ok then 13 else 14
        13 -> next 0
        14 -> if ok then 15 else 16
        15 -> if ok then 7 else 16
        16 -> next 17
        17 -> if ok then 0 else 18
        18 -> -1
        19 -> 20
        20 -> if ok then 21 else 24
        21 -> next 22
        22 -> next (256 + 23)
        24 -> next 25
        25 -> next (256 + 26)
        27 -> 28
        28 -> next 29
        29 -> if ok then 30 else 32
        30 -> next (256 + 31)
        32 -> next 33
        33 -> next (256 + 34)
        35 -> 36
        36 -> if ok then 37 else 38
        37 -> if ok then 39 else 38
        38 -> -1
        39 -> next 40
        40 -> if ok then 41 else 43
        41 -> if ok then 42 else 43
        42 -> if ok then 44 else 43
        43 -> -1
        44 -> next 45
        45 -> next 46
        46 -> next 47
        47 -> next 48
        48 -> next 49
        49 -> next (256 + 50)
        51 -> 52
        52 -> if ok then 53 else 58
        53 -> if ok then 54 else 57
        54 -> if ok then 55 else 57
        55 -> if ok then 56 else 57
        56 -> next 57
        57 -> next 52
        58 -> if ok then 256 + 59 else 256 + 60
        61 -> 62
        62 -> next 63
        63 -> next 64
        64 -> next 65
        65 -> next (256 + 66)
        67 -> 68
        68 -> next 69
        69 -> next 70
        70 -> next (256 + 71)
        72 -> 73
        73 -> next 74
        74 -> next 75
        75 -> next (256 + 76)
        77 -> 78
        78 -> next 79
        79 -> if ok then 256 + 82 else 80
        80 -> if ok then 256 + 81 else -1
        _ -> error "invalid deposit verification phase"
    where
      ok = result == 1
      next phase' = if ok then phase' else -1
  validate (DepositStateRule phase facts)
    | phase > fromIntegral (fromEnum (maxBound :: DepositStatePhase)) = error "invalid deposit state phase"
    | otherwise = case toEnum (fromIntegral phase) of
        CheckCheckpoint -> if present then 1 else if corrupt then 2 else 0
        CheckPrior -> requireState 3 (match 4)
        ConnectPrior -> requireState 5 (match 6)
        DisconnectPresent -> requireState 7 0
        DisconnectCheckpoint -> match 8
        DisconnectCurrent -> match 9
        CheckCheckpointAnchor -> match 10
        CheckAnchor -> match 11
    where
      present = facts .&. 1 /= 0
      corrupt = facts .&. 2 /= 0
      match failure = if facts .&. 4 /= 0 then 0 else failure
      requireState missing next = if present then next else if corrupt then 2 else missing

type DecodeCtip = Ptr () -> Ptr Int64 -> IO Int32
foreign import ccall unsafe "dynamic" decodeCtip :: FunPtr DecodeCtip -> DecodeCtip
-- Facts: unspent, explicit asset, pegged asset, explicit value, script consumed.
-- Three nine-bit opcode slots; 256 represents upstream GetOp failure.
type ReadCtipOpcode = Ptr () -> Word32 -> IO Int32
foreign import ccall unsafe "dynamic" readCtipOpcode :: FunPtr ReadCtipOpcode -> ReadCtipOpcode
data PersistedCtip = PersistedCtip Word32 Int64 Word32 (FunPtr DecodeCtip) (Ptr ())
                  | CtipScript (Word32 -> IO Int32)
                  | PersistedCtipWorkflow Word32 Int64 (Word32 -> IO Int32) (FunPtr DecodeCtip) (Ptr ())
instance Validation PersistedCtip where
  type ValidationResult PersistedCtip = IO Int32
  validate (PersistedCtipWorkflow facts amount readOpcode decoder context) = do
    script <- validate (CtipScript readOpcode)
    ended <- readOpcode 3
    if ended < 0 || ended > 1 then error "invalid CTIP cursor fact"
      else if decoder == nullFunPtr then error "missing CTIP payload decoder"
      else validate (PersistedCtip (facts .|. (fromIntegral ended `shiftL` 4)) amount (fromIntegral script) decoder context)
  validate (CtipScript readOpcode) = go 0 0
    where
      go 3 packed = pure packed
      go index packed = do
        opcode <- readOpcode index
        if opcode < 0 || opcode > 256 then error "CTIP script adapter fault"
        else go (index + 1) (packed .|. (opcode `shiftL` (9 * fromIntegral index)))
  validate (PersistedCtip facts amount script decoder context)
    | facts .&. 15 /= 15 || amount /= 0 = pure 1
    | script .&. 511 > 78 || (script `shiftR` 9) .&. 511 /= 117 ||
        (script `shiftR` 18) .&. 511 /= 0 || facts .&. 16 == 0 = pure 2
    | otherwise = allocaBytes 16 $ \fields -> do
        result <- decodeCtip decoder context fields
        if result == 0 then pure 4
        else if result < 8 || result > 15 then error "CTIP payload adapter fault"
        else do
          [value,sequenceNumber] <- peekArray 2 fields
          pure $ if result /= 15 || value <= 0 || sequenceNumber < 0 then 3 else 0

-- Inclusion facts: exact outpoint, merkle root, matching txid, first header.
-- Header callback bits: upstream PoW result, predecessor hash match.
type CheckParentHeader = ReadCtipOpcode
data DepositInclusion = DepositInclusion Word32 Word64 Word32 (FunPtr CheckParentHeader) (Ptr ())
instance Validation DepositInclusion where
  type ValidationResult DepositInclusion = IO Int32
  validate (DepositInclusion facts matches count checker context) =
    checkInclusion facts matches count (readCtipOpcode checker context)

checkInclusion :: Word32 -> Word64 -> Word32 -> (Word32 -> IO Int32) -> IO Int32
checkInclusion facts matches count checkHeader
    | facts .&. 1 == 0 = pure 1
    | facts .&. 14 /= 14 || matches /= 1 = pure 2
    | count < 1 || count > 2017 = error "deposit header adapter count invalid"
    | otherwise = go 0
    where
      go index
        | index == count = pure 0
        | otherwise = do
            result <- checkHeader index
            if result < 0 || result > 3 then error "parent header adapter fault"
            else if result .&. 1 == 0 then pure 3
            else if index > 0 && result .&. 2 == 0 then pure 4
            else go (index+1)

-- Facts: current output uses the historical treasury script, witness decoded.
data DepositCtip = DepositCtip Word32 Word64 Int64 Int64 Int64
instance Validation DepositCtip where
  type ValidationResult DepositCtip = Int32
  validate (DepositCtip facts matches current previous witnessed)
    | facts .&. 1 == 0 || current <= 0 = 5
    | matches /= 1 = 6
    | facts .&. 2 == 0 || previous <= 0 || current <= previous ||
        toInteger current - toInteger previous /= toInteger witnessed = 7
    | otherwise = 0

type HashTransaction = Ptr Word8 -> Word32 -> Ptr Word8 -> IO Int32
foreign import ccall unsafe "dynamic" hashTransaction :: FunPtr HashTransaction -> HashTransaction

-- The caller decodes sequence fields and the header vector using upstream
-- serialization. It returns three Int64s: current sequence, prior sequence, count.
type DecodeEvidence = DecodeCtip

data DeterministicEvidence = DeterministicEvidence Word32 Word32 (Ptr Word32) (Ptr (Ptr Word8))
  (Ptr Word8) (FunPtr HashTransaction) (FunPtr DecodeEvidence) (Ptr ())

instance Validation DeterministicEvidence where
  type ValidationResult DeterministicEvidence = IO Int32
  validate (DeterministicEvidence maximumTx count sizes fields prevout hasher decoder context)
    | count /= 11 = pure 1
    | otherwise = do
      lengths <- peekArray 11 sizes
      pointers <- peekArray 11 fields
      marker <- copyBytes (pointers !! 4) (min 22 (lengths !! 4))
      if marker /= C.pack depositMarker then pure 1
      else if any (\i -> lengths !! i == 0 || lengths !! i > maximumTx) [5,6,7] ||
              lengths !! 10 == 0 || lengths !! 10 > 2017 * 80 + 16 then pure 2
      else allocaBytes 32 $ \txid -> do
        hashed <- hashTransaction hasher (pointers !! 5) (lengths !! 5) txid
        matches <- if hashed == 1 then (==) <$> copyBytes txid 32 <*> copyBytes prevout 32
                   else if hashed == 0 then pure False else error "transaction hash adapter fault"
        if not matches then pure 3 else allocaBytes 24 $ \decoded -> do
          status <- decodeCtip decoder context decoded
          if status == 0 then pure 4 else if status /= 1 then error "evidence decoder adapter fault" else do
            [current,previous,headers] <- peekArray 3 decoded
            pure $ if current < 0 || previous < 0 || previous == maxBound || current /= previous + 1 then 5
                   else if headers < 1 || headers > 2017 then 6 else 0

copyBytes :: Ptr Word8 -> Word32 -> IO B.ByteString
copyBytes ptr size = B.packCStringLen (castPtr ptr, fromIntegral size)

data DepositWitness = DepositWitness Int64 Word32 Word32 Word32 (Ptr Word32) (Ptr (Ptr Word8))
  (Ptr Word8) (Ptr Word8) (Ptr Word8) (FunPtr HashTransaction) (Ptr Int64)

data DepositOutputs = DepositOutputs Word32 Int64 [Word8] [(Word8, Int64)]

legacyWitnessShape :: Word32 -> B.ByteString -> Word32 -> Bool
legacyWitnessShape count marker txidSize =
  count == 6 && marker == C.pack legacyDepositMarker && txidSize == 32

-- Only bounded prefix fields are copied. Opaque transaction bytes stay with
-- the caller and are decoded/hashed by its upstream Elements adapter.
instance Validation DepositWitness where
  type ValidationResult DepositWitness = IO Int32
  validate (DepositWitness maximumMoney maximumTx mode count sizes fields asset genesis prevout hasher valueOut)
    | mode == 3 = if count /= 6 then pure 0 else do
        markerSize <- peekElemOff sizes 4
        markerPtr <- peekElemOff fields 4
        marker <- copyBytes markerPtr (min 22 markerSize)
        txidSize <- peekElemOff sizes 5
        pure (if legacyWitnessShape count marker txidSize then 1 else 0)
    | count `notElem` [6,8,11] = pure 0
    | otherwise = do
      lengths <- peekArray (fromIntegral count) sizes
      pointers <- peekArray (fromIntegral count) fields
      let caps = [9,33,33,101,22,33,33,depositAddressLimit+1,0,0,0]
      stack <- sequence [copyBytes ptr (min size cap) | (ptr,size,cap) <- zip3 pointers lengths caps]
      expectedAsset <- copyBytes asset 32
      expectedGenesis <- copyBytes genesis 32
      expectedTxid <- copyBytes prevout 32
      let parsed = do
            kind <- case (count, stack !! 4) of
              (6, marker) | legacyWitnessShape count marker (lengths !! 5) -> Just 1
              (8, marker) | marker == C.pack depositMarker && lengths !! 0 == 8 &&
                            lengths !! 5 == 32 && lengths !! 6 == 32 &&
                            nonEmptyBounded (lengths !! 7) depositAddressLimit -> Just 2
              (11, marker) | marker == C.pack depositMarker -> Just 3
              _ -> Nothing
            guard (mode == 0 || (mode == 1 && kind /= 2) || (mode == 2 && kind == 2))
            guard (B.length (head stack) >= 8 && stack !! 1 == expectedAsset &&
                   stack !! 2 == expectedGenesis && lengths !! 3 <= 100)
            let value = fromIntegral (readLE (B.take 8 (head stack)))
            guard (value > 0 && value <= maximumMoney)
            pure (kind,value)
      case parsed of
        Nothing -> pure 0
        Just (kind,value) -> do
          matches <- if kind /= 3 then pure (stack !! 5 == expectedTxid) else
            if lengths !! 5 > maximumTx then pure False else allocaBytes 32 $ \txid -> do
              result <- hashTransaction hasher (pointers !! 5) (lengths !! 5) txid
              if result == 0 then pure False else if result == 1 then (== expectedTxid) <$> copyBytes txid 32
              else error "transaction hash adapter fault"
          if matches then poke valueOut value >> pure kind else pure 0

-- Input flags: witness recognized, pegin bit. Output flags: script matches,
-- explicit pegged asset, explicit value, committed nonce. Other wallet outputs
-- may sponsor fees; the committed recipient still receives the entire mint.
instance Validation DepositOutputs where
  type ValidationResult DepositOutputs = Int32
  validate (DepositOutputs facts value inputs recipients)
    | any (\flags -> flags .&. 1 == 0 && flags .&. 2 /= 0) inputs = 1
    | length (filter (\flags -> flags .&. 1 /= 0) inputs) /= 1 = 2
    | facts .&. 1 /= 0 = 3
    | facts .&. 2 == 0 = 4
    | facts .&. 4 == 0 = 5
    | facts .&. 8 == 0 = 6
    | any (\(flags,amount) -> flags .&. 14 /= 6 || amount /= value) matching = 7
    | length matching /= 1 = 8
    | otherwise = 0
    where matching = filter (\(flags,_) -> flags .&. 1 /= 0) recipients

outputRules :: Word32 -> Int64 -> Word32 -> Ptr Word8 -> Word32 -> Ptr Word8 -> Ptr Int64 -> IO Int32
outputRules facts value inputCount inputs outputCount flags amounts = do
  ins <- peekArray (fromIntegral inputCount) inputs
  outs <- readOutputs (fromIntegral outputCount) flags amounts
  pure (execute (Check (DepositOutputs facts value ins outs)) Validate)

readOutputs :: Int -> Ptr Word8 -> Ptr Int64 -> IO [(Word8, Int64)]
readOutputs count flags amounts = mapM (\i -> (,) <$> peekElemOff flags i <*> peekElemOff amounts i) [0..count-1]

-- Input facts: pegin, outpoint match, empty scriptSig, no issuance, decoded
-- witness, witness txid match, OP_TRUE claim. Output facts: explicit pegged
-- asset, explicit value, null nonce, fee script, committed destination.
data AuthenticatedDeposit = AuthenticatedDeposit Word64 Word64 Word64 Word32
  Int64 Int64 Word64 [(Word8, Int64)]
instance Validation AuthenticatedDeposit where
  type ValidationResult AuthenticatedDeposit = Int32
  validate (AuthenticatedDeposit inputs index witnesses facts claimed witnessed count outs)
    | inputs /= 1 || index /= 0 = 1
    | witnesses /= 1 = 2
    | facts .&. 15 /= 15 = 3
    | facts .&. 112 /= 112 || witnessed /= claimed = 4
    | count < 1 || count > 2 = 5
    | otherwise = go outs 0 0 (0 :: Int) (0 :: Int)
    where
      go [] credited fee credits fees =
        if credits == 1 && fees <= 1 && credited > 0 && fee >= 0 &&
           credited + fee == toInteger claimed then 0 else 8
      go ((flags,amount):rest) credited fee credits fees
        | flags .&. 7 /= 7 = 6
        | flags .&. 8 /= 0 = go rest credited (fee + toInteger amount) credits (fees+1)
        | flags .&. 16 == 0 = 7
        | otherwise = go rest (credited + toInteger amount) fee (credits+1) fees

authenticatedRules :: Word64 -> Word64 -> Word64 -> Word32 -> Int64 -> Int64
  -> Word64 -> Ptr Word8 -> Ptr Int64 -> IO Int32
authenticatedRules inputs index witnesses facts claimed witnessed count flags amounts = do
  -- Never read more than the adapter's two slots, even for an invalid count.
  outs <- readOutputs (fromIntegral (min 2 count)) flags amounts
  pure (execute (Check (AuthenticatedDeposit inputs index witnesses facts claimed witnessed count outs)) Validate)
