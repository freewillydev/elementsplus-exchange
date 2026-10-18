{-# LANGUAGE ForeignFunctionInterface, TypeFamilies, RankNTypes, FlexibleContexts, TypeOperators #-}
-- Copyright (c) 2026 The Elements Core developers
-- Distributed under the MIT software license.
module Drivechain where

import Control.Exception (SomeException, catch, evaluate, mask_)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.Bits ((.&.), shiftR, testBit)
import Data.Int (Int32, Int64)
import Data.IORef (newIORef)
import Data.Typeable (Typeable)
import Data.Word (Word8, Word16, Word32, Word64)
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Marshal.Alloc (alloca)
import Foreign.C.Types (CSize(..), CBool(..), CInt(..))
import Foreign.Marshal.Array (peekArray, pokeArray, withArray, withArrayLen, allocaArray)
import Foreign.Ptr (Ptr, FunPtr, castPtr, nullPtr, nullFunPtr, plusPtr)
import Foreign.Storable (poke, peek, peekElemOff)
import Foreign.StablePtr (newStablePtr, deRefStablePtr, freeStablePtr, castStablePtrToPtr, castPtrToStablePtr)
import Withdrawal (withdrawal, wordLE, wordBE, PreflightFlow(..), DestinationFlow(..), EventFlow(..), SubmissionFlow(..), OutputFlow(..), JournalReadFlow(..), JournalPersistFlow(..), RpcBurnFlow(..), RpcClaimFlow(..), RpcVerifyFlow(..))
import qualified Withdrawal
import qualified Deposit
import qualified Bmm
import qualified ParentReplay
import qualified Exchange
import qualified Usdd
import qualified ScriptPolicy
import Control.Operation
import Control.Operation.Validation
import Workflow (CommandFlow(..), PredicateFlow(..), countMatches)

foreign import ccall unsafe "memcmp" compareAnnexBytes :: Ptr Word8 -> Ptr Word8 -> CSize -> IO CInt

elements_hs_script_cache_encode :: Word32 -> Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> IO Int32
elements_hs_script_cache_encode mode size input capacity output = run `catch` handleFailure (-1)
  where
    shape = case mode of
      0 -> size >= 29 && size <= 805 && capacity == 822
      1 -> size `elem` [1,81] && capacity == 115
      _ -> False
    run | not shape || input == nullPtr || output == nullPtr = pure (-1)
        | otherwise = do
            bytes <- B.packCStringLen (castPtr input,fromIntegral size)
            case execute (Check (Exchange.ScriptCacheEncoding (mode == 1) bytes)) Validate of
              Just encoded | B.length encoded == fromIntegral capacity -> do
                B.useAsCString encoded (\ptr -> copyBytes output (castPtr ptr) (fromIntegral capacity))
                pure 0
              _ -> pure (-1)

elements_hs_annex_retention :: Word64 -> Word64 -> Ptr Word8 -> Ptr Word8 -> IO Int32
elements_hs_annex_retention fullSize bodySize full body = (do
  accepted <- execute (Check (ScriptPolicy.AnnexRetention fullSize bodySize
    (full/=nullPtr) (body/=nullPtr) (peek full)
    ((==0) <$> compareAnnexBytes body (full `plusPtr` 1) (fromIntegral bodySize)))) Validate
  pure (if accepted then 1 else 0)) `catch` handleFailure (-1)

elements_hs_merkle_replacement :: Word32 -> Word32 -> Word32 -> Word32 -> IO Int32
elements_hs_merkle_replacement mode index position flags = guardResult (-1) $
  execute (Check (ScriptPolicy.MerkleReplacement mode index position flags)) Validate

elements_hs_frontier_wire :: Word64 -> Word32 -> FunPtr PolicyEffect -> Ptr () -> IO Int32
elements_hs_frontier_wire count reading
  | reading>1 = \_ _ -> pure (-1)
  | otherwise = callbackCall callReentrantPredicate (\action ->
      execute (Check (Usdd.FrontierWire count (reading==1) action)) Validate)

elements_hs_parameter_gate :: Word32 -> Int64 -> Int64 -> IO Int32
elements_hs_parameter_gate mode first second = guardResult (-1) $
  execute (Check (ScriptPolicy.ParameterGate mode first second)) Validate

elements_hs_optional_environment :: Word32 -> Word32 -> Word32 -> IO Int32
elements_hs_optional_environment kind present fields = guardResult (-1) $
  execute (Check (ScriptPolicy.OptionalEnvironment kind present fields)) Validate

elements_hs_optional_checkpoint :: Word32 -> Ptr Word8 -> IO Int32
elements_hs_optional_checkpoint present input
  | present>1 = pure (-1)
  | otherwise = (do
      bytes <- if input==nullPtr then pure B.empty else B.packCStringLen (castPtr input,80)
      let fields = sum [if B.any (/=0) (B.take width (B.drop offset bytes)) then flag else 0 |
            (flag,offset,width) <- [(1,0,32),(2,32,8),(4,40,8),(8,48,32)]]
      evaluate (execute (Check (ScriptPolicy.OptionalEnvironment 5 present fields)) Validate))
      `catch` handleFailure (-1)

elements_hs_wallet_issue_amount :: Ptr Double -> IO Int32
elements_hs_wallet_issue_amount input
  | input==nullPtr = pure (-1)
  | otherwise = (do
      amount <- peek input
      evaluate (if execute (Check (Withdrawal.WalletIssueAmount amount)) Validate then 1 else 0))
      `catch` handleFailure (-1)

elements_hs_jet_height :: Word32 -> Word64 -> IO Int32
elements_hs_jet_height present height
  | present>1 = pure (-1)
  | otherwise = guardResult (-1) (if execute (Check (Exchange.JetHeight (present==1) height)) Validate then 1 else 0)

elements_hs_bond_input :: Word64 -> Word64 -> Word32 -> Ptr Word8 -> Ptr Word8 -> IO Int32
elements_hs_bond_input index current flags actual expected = (do
    accepted <- execute (Check (Exchange.BondInput index current flags matches)) Validate
    pure (if accepted then 1 else 0)) `catch` handleFailure (-1)
  where
    matches
      | actual==nullPtr || expected==nullPtr = pure False
      | otherwise = (==) <$> B.packCStringLen (castPtr actual,32) <*> B.packCStringLen (castPtr expected,32)

elements_hs_groth16_header :: Word32 -> Word32 -> Ptr Word8 -> IO Int32
elements_hs_groth16_header version size input
  | version>255 || size/=79 || input==nullPtr = pure (-1)
  | otherwise = (do
      header <- B.packCStringLen (castPtr input,79)
      evaluate (if execute (Check (Exchange.Groth16Header (fromIntegral version) header)) Validate then 1 else 0))
      `catch` handleFailure (-1)

elements_hs_canonical_values :: Word32 -> Word32 -> Ptr Word8 -> IO Int32
elements_hs_canonical_values version size input
  | lookup version [(4,609),(5,850),(23,1627)]/=Just size || input==nullPtr = pure (-1)
  | otherwise = (do
      bytes <- B.packCStringLen (castPtr input,fromIntegral size)
      evaluate (if execute (Check (Exchange.CanonicalPublicValues version bytes)) Validate then 1 else 0))
      `catch` handleFailure (-1)

elements_hs_canonical_activation :: Word32 -> Ptr Word8 -> IO Int32
elements_hs_canonical_activation size input
  | size/=364 || input==nullPtr = pure (-1)
  | otherwise = (do
      bytes <- B.packCStringLen (castPtr input,364)
      evaluate (if execute (Check (Exchange.CanonicalActivation bytes)) Validate then 1 else 0))
      `catch` handleFailure (-1)

elements_hs_muldiv128 :: Word64 -> Word64 -> Word64 -> Word64 -> Word64 -> Ptr Word64 -> IO Int32
elements_hs_muldiv128 high low multiplier divisorHigh divisorLow output
  | output==nullPtr = pure (-1)
  | otherwise = (case execute (Check (Exchange.MulDiv128 high low multiplier divisorHigh divisorLow)) Validate of
      Nothing -> pure 0
      Just limbs -> pokeArray output limbs >> pure 1) `catch` handleFailure (-1)

elements_hs_bmm_wait_error :: Word64 -> Ptr Word8 -> IO Int32
elements_hs_bmm_wait_error = elements_hs_bmm_message 0

elements_hs_bmm_message :: Word32 -> Word64 -> Ptr Word8 -> IO Int32
elements_hs_bmm_message kind size input
  | kind > 1 || size > fromIntegral (maxBound :: Int) || (size /= 0 && input == nullPtr) = pure (-1)
  | otherwise = (do
      message <- if size == 0 then pure B.empty else B.packCStringLen (castPtr input,fromIntegral size)
      pure (if validate ((if kind==0 then Bmm.DefinitiveWaitError else Bmm.DuplicateRequest) message)
            then 1 else 0)) `catch` handleFailure (-1)

elements_hs_anchor_rule :: Word32 -> Ptr Word8 -> IO Int32
elements_hs_anchor_rule size input
  | size `notElem` [145,290,294,439] || input==nullPtr = pure (-1)
  | otherwise = (do
      bytes <- B.packCStringLen (castPtr input,fromIntegral size)
      evaluate (if execute (Check (Bmm.AnchorRule bytes)) Validate then 1 else 0)) `catch` handleFailure (-1)

elements_hs_anchor_checkpoint :: Word32 -> Ptr Word8 -> Ptr Word8 -> IO Int32
elements_hs_anchor_checkpoint size input output
  | size/=145 || input==nullPtr || output==nullPtr = pure (-1)
  | otherwise = (do
      bytes <- B.packCStringLen (castPtr input,145)
      publishBytes 80 output (execute (Check (Bmm.AnchorCheckpoint bytes)) Validate)) `catch` handleFailure (-1)

type WalletBundleEffect = Ptr () -> Word32 -> Word64 -> Ptr Word8 -> Word32 -> Ptr (Ptr Word8) -> IO Int64
type MoneyParser = Ptr Word8 -> Word32 -> IO Int64
type PolicyEffect = Ptr () -> Word32 -> IO Int32
type ProofBuildEffect = Ptr () -> Word32 -> Word64 -> IO Int32
type MatchFact = Ptr () -> Word32 -> IO Int64
type ProofFacts = Ptr () -> Word32 -> Ptr Word64 -> IO Int32
foreign import ccall safe "dynamic" callProofFacts :: FunPtr ProofFacts -> ProofFacts
foreign import ccall safe "dynamic" callMatchFact :: FunPtr MatchFact -> MatchFact
foreign import ccall "dynamic" callProofBuildEffect :: FunPtr ProofBuildEffect -> ProofBuildEffect
callbackCall :: Num result => (FunPtr native -> Ptr () -> action) -> (action -> IO result) -> FunPtr native -> Ptr () -> IO result
callbackCall convert run callback context
  | callback == nullFunPtr = pure (-1)
  | otherwise = run (convert callback context) `catch` handleFailure (-1)

proofCall :: ((Word32 -> Word64 -> IO Int32) -> IO Int32) -> FunPtr ProofBuildEffect -> Ptr () -> IO Int32
proofCall = callbackCall callProofBuildEffect

elements_hs_bmm_proof_build :: Word64 -> Int64 -> FunPtr ProofBuildEffect -> Ptr () -> IO Int32
elements_hs_bmm_proof_build previous parent = proofCall (\action -> execute (Check (Bmm.ProofBuild previous parent action)) Validate)

elements_hs_deposit_ctip_search :: Word64 -> FunPtr ProofBuildEffect -> Ptr () -> IO Int32
elements_hs_deposit_ctip_search count = proofCall (\action -> execute (Check (Deposit.CtipSearch count action)) Validate)

elements_hs_deposit_headers :: Word64 -> Int64 -> FunPtr ProofBuildEffect -> Ptr () -> IO Int32
elements_hs_deposit_headers first tip = proofCall (\action -> execute (Check (Deposit.HeaderBuild first tip action)) Validate)

elements_hs_deposit_previous_sequence :: Int64 -> IO Int64
elements_hs_deposit_previous_sequence current = guardResult (-1) $
  execute (Check (Deposit.PreviousSequence current)) Validate

elements_hs_deposit_build :: Int64 -> Int64 -> Word32 -> FunPtr PolicyEffect -> Ptr () -> IO Int32
elements_hs_deposit_build sequenceNumber height flags = policyCall (\action ->
  execute (Check (Deposit.EvidenceBuild sequenceNumber height flags action)) Validate)

publishVotes :: Ptr Word16 -> Maybe (Bool,[Word16]) -> IO Int32
publishVotes votes result = case result of
  Nothing -> pure 0
  Just (False,_) -> pure 2
  Just (True,updated) -> pokeArray votes updated >> pure 1

elements_hs_replay_leader :: Word32 -> Ptr Word16 -> IO Int64
elements_hs_replay_leader count votes = run `catch` handleFailure (-2)
  where
    run | (count /= 0 && votes == nullPtr) || toInteger count * 2 > toInteger (maxBound :: Int) = pure (-2)
        | otherwise = do
            values <- peekArray (fromIntegral count) votes
            evaluate (execute (Check (ParentReplay.VoteLeader values)) Validate)

withReplayVotes :: Word32 -> Ptr Word8 -> Ptr Word16 -> (B.ByteString -> [Word16] -> IO a) -> IO a
withReplayVotes count hashes votes action
  | (count /= 0 && (hashes == nullPtr || votes == nullPtr)) ||
      toInteger count * 32 > toInteger (maxBound :: Int) = ioError (userError "invalid replay vote buffers")
  | otherwise = do
      keys <- B.pack <$> peekArray (fromIntegral count*32) hashes
      values <- peekArray (fromIntegral count) votes
      action keys values

elements_hs_replay_leading :: Word32 -> Ptr Word8 -> Ptr Word16 -> IO Int64
elements_hs_replay_leading count hashes votes = (`catch` handleFailure (-2)) $
  withReplayVotes count hashes votes $ \keys values ->
    case execute (Check (ParentReplay.LeadingVote keys values)) Validate of
      Nothing -> pure (-1)
      Just (leader,updated) -> pokeArray votes updated >> pure leader

elements_hs_replay_explicit :: Word32 -> Word32 -> Ptr Word8 -> Ptr Word16 -> IO Int32
elements_hs_replay_explicit vote count hashes votes = run `catch` handleFailure (-1)
  where
    run | vote > 65535 = pure (-1)
        | vote == 65535 = pure 0
        | otherwise = withReplayVotes count hashes votes $ \keys values -> do
            let (code,updated) = execute (Check (ParentReplay.ExplicitVote (fromIntegral vote) keys values)) Validate
            if code == 1 || code == 2 then pokeArray votes updated else pure ()
            pure code

elements_hs_replay_alarm :: Word32 -> Ptr Word16 -> IO Int32
elements_hs_replay_alarm count votes = run `catch` handleFailure (-1)
  where
    run | (count /= 0 && votes == nullPtr) || toInteger count * 2 > toInteger (maxBound :: Int) = pure (-1)
        | otherwise = do
            values <- peekArray (fromIntegral count) votes
            publishVotes votes (execute (Check (ParentReplay.VoteAlarm values)) Validate)

elements_hs_replay_upvote :: Word32 -> Ptr Word8 -> Ptr Word8 -> Ptr Word16 -> IO Int32
elements_hs_replay_upvote count hashes target votes = run `catch` handleFailure (-1)
  where
    run
      | target == nullPtr = pure (-1)
      | otherwise = withReplayVotes count hashes votes $ \keys values -> do
          key <- B.pack <$> peekArray 32 target
          publishVotes votes (execute (Check (ParentReplay.VoteUpdate key keys values)) Validate)

elements_hs_count_matches :: Word64 -> FunPtr ProofBuildEffect -> Ptr () -> IO Int64
elements_hs_count_matches count = callbackCall callProofBuildEffect (\action -> countMatches count (action 1))

elements_hs_coinbase_messages :: Word64 -> FunPtr IndexedFact -> Ptr () -> IO Int32
elements_hs_coinbase_messages count = callbackCall callIndexedFact (\action ->
  execute (Check (ParentReplay.CoinbaseMessages count action)) Validate)

elements_hs_m4_repeat :: Word32 -> FunPtr MatchFact -> Ptr () -> IO Int32
elements_hs_m4_repeat upvote = callbackCall callMatchFact (\action ->
  execute (Check (ParentReplay.M4Repeat upvote action)) Validate)

elements_hs_m8_acceptance :: Word64 -> FunPtr IndexedFact -> Ptr () -> IO Int32
elements_hs_m8_acceptance count = callbackCall callIndexedFact (\action ->
  execute (Check (ParentReplay.M8Acceptance count action)) Validate)

elements_hs_m2_proposal :: Word32 -> Word32 -> Word32 -> Word32 -> Word32 -> FunPtr IndexedFact -> Ptr () -> IO Int32
elements_hs_m2_proposal height unusedAge unusedThreshold usedAge usedThreshold = callbackCall callIndexedFact (\action ->
  execute (Check (ParentReplay.M2Proposal height unusedAge unusedThreshold usedAge usedThreshold action)) Validate)

elements_hs_m4_mode :: Word32 -> Word64 -> FunPtr MatchFact -> Ptr () -> IO Int32
elements_hs_m4_mode flags votes = callbackCall callMatchFact (\action ->
  execute (Check (ParentReplay.M4Mode flags votes action)) Validate)

elements_hs_m3_proposal :: FunPtr IndexedFact -> Ptr () -> IO Int32
elements_hs_m3_proposal = callbackCall callIndexedFact (\action ->
  execute (Check (ParentReplay.M3Proposal action)) Validate)

elements_hs_m6_id :: Word64 -> Word64 -> Int64 -> Int64 -> Word32 -> FunPtr IndexedFact -> Ptr () -> IO Int32
elements_hs_m6_id outputs inputs previous maximumValue hasSlot = callbackCall callIndexedFact (\action ->
  execute (Check (ParentReplay.M6Id outputs inputs previous maximumValue hasSlot action)) Validate)

elements_hs_active_slots :: Word32 -> Ptr Word8 -> Ptr Word8 -> IO Int32
elements_hs_active_slots count input output = run `catch` handleFailure (-1)
  where
    run | count > 257 || (count /= 0 && (input == nullPtr || output == nullPtr)) = pure (-1)
        | otherwise = do
            entries <- B.pack <$> peekArray (fromIntegral count*2) input
            writeReply (execute (Check (ParentReplay.ActiveSlots entries)) Validate) output count

elements_hs_block_publish :: Word32 -> FunPtr PolicyEffect -> Ptr () -> IO Int32
elements_hs_block_publish flags = policyCall (\action ->
  execute (Check (ParentReplay.BlockPublish flags action)) Validate)

elements_hs_prune_slots :: Word64 -> FunPtr MatchFact -> Ptr () -> IO Int32
elements_hs_prune_slots count = callbackCall callMatchFact (\action ->
  execute (Check (ParentReplay.PruneSlots count action)) Validate)

elements_hs_m6_withdrawal :: Word64 -> Word64 -> Word64 -> Word32 -> Word32 -> FunPtr MatchFact -> Ptr () -> IO Int32
elements_hs_m6_withdrawal decreases changes inputs threshold single = callbackCall callMatchFact (\action ->
  execute (Check (ParentReplay.M6Withdrawal decreases changes inputs threshold single action)) Validate)

elements_hs_ctip_changes :: Word64 -> FunPtr MatchFact -> Ptr () -> IO Int32
elements_hs_ctip_changes count = callbackCall callMatchFact (\action ->
  execute (Check (ParentReplay.CtipChanges count action)) Validate)

elements_hs_ctip_replacements :: Word64 -> FunPtr PolicyEffect -> Ptr () -> IO Int32
elements_hs_ctip_replacements count = policyCall (\action ->
  execute (Check (ParentReplay.CtipReplacements count action)) Validate)

type IndexedFact = Ptr () -> Word32 -> Word64 -> IO Int64
foreign import ccall safe "dynamic" callIndexedFact :: FunPtr IndexedFact -> IndexedFact

type InboxEffect = Ptr () -> Word32 -> Word64 -> Word64 -> IO Int64
foreign import ccall safe "dynamic" callInboxEffect :: FunPtr InboxEffect -> InboxEffect
elements_hs_exchange_derive_inbox :: Word64 -> Word64 -> Word64 -> FunPtr InboxEffect -> Ptr () -> IO Int32
elements_hs_exchange_derive_inbox count forced deposits = callbackCall callInboxEffect (\action ->
  execute (Exchange.InboxRequest action) (Exchange.deriveInbox count forced deposits))

type CursorEffect = Ptr () -> Word32 -> Word64 -> Word64 -> Ptr Word64 -> IO Int32
foreign import ccall safe "dynamic" callCursorEffect :: FunPtr CursorEffect -> CursorEffect
elements_hs_credential_read :: Word64 -> Ptr Word64 -> FunPtr CursorEffect -> Ptr () -> IO Int32
elements_hs_credential_read capacity = workCall (\readField ->
  execute (Check (Bmm.CredentialRead capacity (readField 0))) Validate)

elements_hs_tls_file_admission :: Word32 -> FunPtr CursorEffect -> Ptr () -> IO Int32
elements_hs_tls_file_admission privateKey callback context
  | privateKey>1 = pure (-1)
  | otherwise = cursorCall (\readField ->
      execute (Check (Bmm.TlsFileAdmission (privateKey/=0) (\step -> readField step 0 0))) Validate) callback context

elements_hs_startup_args :: Word32 -> Word64 -> Word64 -> FunPtr CursorEffect -> Ptr () -> IO Int32
elements_hs_startup_args slot moneyLimit timeoutMaximum = cursorCall (\readField ->
  execute (Check (Bmm.StartupArgs slot moneyLimit timeoutMaximum (\step -> readField step 0 0))) Validate)

elements_hs_bmm_work_budget :: Word64 -> Ptr Word64 -> FunPtr CursorEffect -> Ptr () -> IO Int32
elements_hs_bmm_work_budget count = workCall (\readField -> do
  result <- execute (Check (Bmm.WorkBudget count readField)) Validate
  pure (0,result))

elements_hs_deposit_input_limit :: Word32 -> Word64 -> Word64 -> FunPtr CursorEffect -> Ptr () -> IO Int32
elements_hs_deposit_input_limit enabled count limit callback context
  | enabled > 1 = pure (-1)
  | otherwise = cursorCall (\readField -> do
      accepted <- execute (Check (Deposit.InputLimit (enabled/=0) count limit readField)) Validate
      pure (if accepted then 1 else 0)) callback context

elements_hs_template_budget :: Int64 -> Int64 -> Ptr Word64 -> FunPtr CursorEffect -> Ptr () -> IO Int32
elements_hs_template_budget height activation = workCall (\readField ->
  execute (Check (Exchange.TemplateBudget height activation (\step -> readField step 0 0))) Validate)

elements_hs_fee_free_selection :: Int64 -> FunPtr CursorEffect -> Ptr () -> IO Int32
elements_hs_fee_free_selection age = cursorCall (\readField ->
  execute (Check (Deposit.FeeFreeSelection age (\step -> readField step 0 0))) Validate)

elements_hs_bmm_work_total :: Word32 -> Word64 -> Word64 -> Ptr Word64 -> FunPtr CursorEffect -> Ptr () -> IO Int32
elements_hs_bmm_work_total mode count initial = workCall (\readField ->
  execute (Check (Bmm.WorkTotal mode count initial (\index -> readField 0 index 0))) Validate)

elements_hs_source_package :: Word32 -> Word64 -> Ptr Word64 -> FunPtr CursorEffect -> Ptr () -> IO Int32
elements_hs_source_package enabled count = workCall (\readField ->
  execute (Check (Exchange.SourcePackage (enabled/=0) count (\step index -> readField step index 0))) Validate)

elements_hs_source_selection :: Word32 -> Word32 -> Word64 -> Ptr Word64 -> FunPtr CursorEffect -> Ptr () -> IO Int32
elements_hs_source_selection enabled modified count output callback context
  | enabled>1 || modified>1 = pure (-1)
  | otherwise = workCall (\readField -> execute (Check (Exchange.SourceSelection (modified/=0)
      (Exchange.SourcePackage (enabled/=0) count (\step index -> readField step index 0)))) Validate)
      output callback context

workCall :: ((Word32 -> Word64 -> Word64 -> IO Word64) -> IO (Int32,Word64))
  -> Ptr Word64 -> FunPtr CursorEffect -> Ptr () -> IO Int32
workCall run output callback context
  | output == nullPtr = pure (-1)
  | otherwise = cursorCall (\readField -> do
      (code,result) <- run readField
      if code < 0 then pure code else poke output result >> pure code) callback context

cursorCall :: ((Word32 -> Word64 -> Word64 -> IO Word64) -> IO Int32)
  -> FunPtr CursorEffect -> Ptr () -> IO Int32
cursorCall run = callbackCall callCursorEffect (\action -> allocaArray 1 $ \field ->
  run (\step witness index -> do
    poke field 0
    status <- action step witness index field
    if status == 1 then peekElemOff field 0 else ioError (userError "work budget read failed")))

elements_hs_usdd_block_resources :: Word64 -> Word64 -> Word64 -> Ptr Word64 -> FunPtr CursorEffect -> Ptr () -> IO Int32
elements_hs_usdd_block_resources count lane weight = workCall (\readField ->
  execute (Check (Usdd.BlockResources count lane weight (\step index -> readField step index 0))) Validate)

elements_hs_usdd_package_resources :: Word32 -> Word64 -> Word64 -> Word64 -> Ptr Word64 -> FunPtr CursorEffect -> Ptr () -> IO Int32
elements_hs_usdd_package_resources flags count initial lane = workCall (\readField ->
  execute (Check (Usdd.PackageResources flags count initial lane (\step index -> readField step index 0))) Validate)

elements_hs_usdd_policy_weight :: Word32 -> Word64 -> FunPtr CursorEffect -> Ptr () -> IO Int32
elements_hs_usdd_policy_weight flags count = cursorCall (\readField ->
  execute (Check (Usdd.PolicyWeight flags count (\step index -> readField step index 0))) Validate)

elements_hs_usdd_policy_weight_expanded :: Word32 -> Word64 -> FunPtr CursorEffect -> Ptr () -> IO Int32
elements_hs_usdd_policy_weight_expanded flags count = cursorCall (\readField ->
  execute (Check (Usdd.PolicyWithActivation flags count (\step index -> readField step index 0))) Validate)

elements_hs_exchange_derive_cursors :: Word64 -> Word32 -> Word64 -> Word64 -> Ptr Word64
  -> FunPtr CursorEffect -> Ptr () -> IO Int32
elements_hs_exchange_derive_cursors count flags forced deposits output callback context
  | output == nullPtr = pure (-1)
  | otherwise = callbackCall callCursorEffect (\action -> do
      let readStep step tx index = allocaArray 2 $ \fields -> do
            pokeArray fields [0,0]
            status <- action step tx index fields
            a <- peekElemOff fields 0
            b <- peekElemOff fields 1
            pure (status,a,b)
      result <- execute (Check (Exchange.CursorDerivation count flags forced deposits readStep)) Validate
      publishResult (\(f,d) -> evaluate f >> evaluate d >> pokeArray output [f,d]) result) callback context

type StateTransitionEffect = Ptr () -> Word32 -> Word64 -> IO Word64
foreign import ccall safe "dynamic" callStateTransitionEffect :: FunPtr StateTransitionEffect -> StateTransitionEffect
elements_hs_exchange_transition :: Word64 -> FunPtr StateTransitionEffect -> Ptr () -> IO Int32
elements_hs_exchange_transition count = callbackCall callStateTransitionEffect (\action ->
  execute (Check (Exchange.StateTransition count action)) Validate)

elements_hs_ctip_outputs :: Word64 -> Word64 -> FunPtr IndexedFact -> Ptr () -> IO Int32
elements_hs_ctip_outputs count maximumValue = callbackCall callIndexedFact (\action ->
  execute (Check (ParentReplay.CtipOutputs count maximumValue action)) Validate)

elements_hs_m5_deposit :: Int64 -> Int64 -> Word64 -> Word64 -> Word64 -> Word32 -> FunPtr IndexedFact -> Ptr () -> IO Int32
elements_hs_m5_deposit old new maximumValue output outputs flags = callbackCall callIndexedFact (\action ->
  execute (Check (ParentReplay.M5Deposit old new maximumValue output outputs flags action)) Validate)

elements_hs_ctip_spends :: Word64 -> FunPtr ProofBuildEffect -> Ptr () -> IO Int32
elements_hs_ctip_spends count = proofCall (\action ->
  execute (Check (ParentReplay.CtipSpends count action)) Validate)

elements_hs_ctip_owners :: Word64 -> Word64 -> FunPtr MatchFact -> Ptr () -> IO Int32
elements_hs_ctip_owners count maximumValue = callbackCall callMatchFact (\action ->
  execute (Check (ParentReplay.CtipOwners count maximumValue action)) Validate)

elements_hs_expire_proposals :: Word64 -> Word32 -> Word32 -> Word32 -> FunPtr MatchFact -> Ptr () -> IO Int32
elements_hs_expire_proposals count height threshold maxAge = callbackCall callMatchFact (\action ->
  execute (Check (ParentReplay.ExpireProposals count height threshold maxAge action)) Validate)

elements_hs_expire_withdrawals :: Word64 -> Word32 -> Word32 -> FunPtr MatchFact -> Ptr () -> IO Int32
elements_hs_expire_withdrawals count height maxAge = callbackCall callMatchFact (\action ->
  execute (Check (ParentReplay.ExpireWithdrawals count height maxAge action)) Validate)

elements_hs_deposit_match :: Int64 -> Int64 -> Int64 -> Word32 -> FunPtr MatchFact -> Ptr () -> IO Int32
elements_hs_deposit_match slot amount bound hasAddress = callbackCall callMatchFact (\action ->
  execute (Check (Deposit.RawMatch slot amount bound hasAddress action)) Validate)

elements_hs_deposit_verify :: Word64 -> Word64 -> Word64 -> FunPtr PolicyEffect -> Ptr () -> IO Int32
elements_hs_deposit_verify index inputs witnesses = policyCall (\action ->
  execute (Check (Deposit.LiveVerify index inputs witnesses action)) Validate)

publishResult :: Integral code => (value -> IO ()) -> Either code value -> IO Int32
publishResult publish = either (pure . fromIntegral) (\value -> publish value >> pure 0)

publishBytes :: Integral code => Int -> Ptr Word8 -> Either code B.ByteString -> IO Int32
publishBytes size output = publishResult (\value -> B.useAsCString value (\ptr -> copyBytes output (castPtr ptr) size))

foreign import ccall "dynamic" runPolicyEffect :: FunPtr PolicyEffect -> PolicyEffect
policyCall :: ((Word32 -> IO Int32) -> IO Int32) -> FunPtr PolicyEffect -> Ptr () -> IO Int32
policyCall = callbackCall runPolicyEffect

elements_hs_bmm_wait :: FunPtr PolicyEffect -> Ptr () -> IO Int32
elements_hs_bmm_wait = policyCall (\action -> execute (Check (Bmm.WaitForBmm action)) Validate)

elements_hs_bmm_submit :: Int64 -> Int64 -> FunPtr IndexedFact -> Ptr () -> IO Int32
elements_hs_bmm_submit bid limit = callbackCall callIndexedFact (\action ->
  execute (Bmm.SubmissionRequest action) (Bmm.submitBmm bid limit))

elements_hs_bmm_reward_address :: FunPtr PolicyEffect -> Ptr () -> IO Int32
elements_hs_bmm_reward_address = policyCall (\action -> execute (Check (Bmm.RewardAddress action)) Validate)

elements_hs_bmm_native_production :: FunPtr PolicyEffect -> Ptr () -> IO Int32
elements_hs_bmm_native_production = policyCall (\action -> execute (Check (Bmm.NativeProduction action)) Validate)

elements_hs_bmm_ecx_production :: FunPtr PolicyEffect -> Ptr () -> IO Int32
elements_hs_bmm_ecx_production = policyCall (\action -> execute (Check (Bmm.EcxProduction action)) Validate)

elements_hs_bmm_sync_tick :: FunPtr PolicyEffect -> Ptr () -> IO Int32
elements_hs_bmm_sync_tick = policyCall (\action -> execute (Check (Bmm.SyncTick action)) Validate)

elements_hs_parent_rpc_address :: Word32 -> Word32 -> Word32 -> Ptr Word8 -> IO Int32
elements_hs_parent_rpc_address family ipv4 size input = run `catch` handleFailure (-1)
  where
    check address = evaluate (if execute (Check address) Validate then 1 else 0)
    run = case family of
      4 | size == 0 -> check (Bmm.ParentRpcIPv4 ipv4)
      6 | size == 16 && input /= nullPtr ->
        B.packCStringLen (castPtr input,16) >>= check . Bmm.ParentRpcIPv6
      _ -> pure (-1)

elements_hs_bmm_work_quote :: Int64 -> Word64 -> Int64 -> Int64 -> Int64 -> Ptr Int64 -> IO Int32
elements_hs_bmm_work_quote fees work rate reserve bound = publishWorkQuote $
  execute (Check (Bmm.WorkQuote fees work rate reserve bound)) Validate

elements_hs_bmm_work_quote_display :: Int64 -> Word64 -> Int64 -> Int64 -> Int64 -> Ptr Int64 -> IO Int32
elements_hs_bmm_work_quote_display fees work rate reserve bound = publishWorkQuote $
  execute (Check (Bmm.WorkQuoteDisplay (Bmm.WorkQuote fees work rate reserve bound))) Validate

publishWorkQuote :: (Bool,[Int64]) -> Ptr Int64 -> IO Int32
publishWorkQuote quote output
  | output == nullPtr = pure (-1)
  | otherwise = (`catch` handleFailure (-1)) $ do
      let (accepted,fields) = quote
      pokeArray output fields
      pure (if accepted then 1 else 0)

elements_hs_bmm_work_bid :: Word32 -> Int64 -> Int64 -> Int64 -> Int64 -> Int64 -> Int64 -> Ptr Int64 -> FunPtr MatchFact -> Ptr () -> IO Int32
elements_hs_bmm_work_bid flags height fees work reserve requested bound output reader context
  | output == nullPtr || reader == nullFunPtr = pure (-1)
  | otherwise = (`catch` handleFailure (-1)) $ do
      (code,fields) <- execute (Check (Bmm.WorkBid flags height fees work reserve requested bound
        (callMatchFact reader context 0))) Validate
      pokeArray output fields
      pure code

elements_hs_bmm_selected_bid :: Int64 -> Int64 -> Int64 -> IO Int64
elements_hs_bmm_selected_bid configured fees moneyLimit =
  evaluate (execute (Check (Bmm.SelectedBid configured fees moneyLimit)) Validate) `catch` handleFailure (-3)

elements_hs_bmm_replacement_limit :: Int64 -> Int64 -> Int64 -> IO Int64
elements_hs_bmm_replacement_limit selected extra moneyLimit =
  evaluate (execute (Check (Bmm.ReplacementLimit selected extra moneyLimit)) Validate) `catch` handleFailure (-3)

elements_hs_next_block_height :: Word32 -> Int32 -> IO Int64
elements_hs_next_block_height present height =
  evaluate (execute (Check (Bmm.NextBlockHeight present height)) Validate) `catch` handleFailure (-2147483649)

elements_hs_tracker_height :: Word32 -> Int32 -> IO Int64
elements_hs_tracker_height mode height =
  evaluate (execute (Check (Exchange.TrackerHeight mode height)) Validate) `catch` handleFailure (-2147483649)

elements_hs_replay_distance :: Word32 -> Word32 -> IO Int64
elements_hs_replay_distance upper lower =
  evaluate (execute (Check (ParentReplay.Distance upper lower)) Validate) `catch` handleFailure (-1)

elements_hs_extra_nonce :: Word32 -> Word32 -> IO Int64
elements_hs_extra_nonce sameParent current =
  evaluate (execute (Check (Bmm.ExtraNonce sameParent current)) Validate) `catch` handleFailure (-1)

elements_hs_peer_strikes :: Word32 -> Word32 -> IO Int64
elements_hs_peer_strikes flags count =
  evaluate (execute (Check (Bmm.PeerStrikes flags count)) Validate) `catch` handleFailure (-1)

foreign import ccall "dynamic" callMoneyParser :: FunPtr MoneyParser -> MoneyParser
elements_hs_bmm_replacement :: Int64 -> Int64 -> Int64 -> Ptr Word8 -> Word32 -> FunPtr MoneyParser -> IO Int64
elements_hs_bmm_replacement current maximumBid moneyLimit input size parser = run `catch` handleFailure (-2)
  where
    run | input == nullPtr || parser == nullFunPtr = pure (-2)
        | otherwise = do
            message <- B.packCStringLen (castPtr input,fromIntegral size)
            result <- Bmm.replaceBid (Bmm.ReplacementBid current maximumBid moneyLimit message) $ \amount ->
              B.useAsCStringLen amount $ \(ptr,len) -> callMoneyParser parser (castPtr ptr) (fromIntegral len)
            pure (maybe (-1) id result)

foreign import ccall "dynamic" callWalletBundleEffect :: FunPtr WalletBundleEffect -> WalletBundleEffect
elements_hs_wallet_bundle :: Int64 -> Ptr Word8 -> FunPtr WalletBundleEffect -> Ptr () -> IO Int32
elements_hs_wallet_bundle maximumMoney input = walletBundle 25 maximumMoney input

elements_hs_wallet_bundle_context :: Int64 -> Ptr Word8 -> Word32 -> FunPtr WalletBundleEffect -> Ptr () -> IO Int32
elements_hs_wallet_bundle_context maximumMoney input size callback context
  | size /= 65 = pure (-1)
  | otherwise = walletBundle 65 maximumMoney input callback context

elements_hs_wallet_bundle_anchor :: Int64 -> Ptr Word8 -> Word32 -> FunPtr WalletBundleEffect -> Ptr () -> IO Int32
elements_hs_wallet_bundle_anchor maximumMoney input size callback context
  | size /= 161 = pure (-1)
  | otherwise = walletBundle 161 maximumMoney input callback context

walletBundle :: Int -> Int64 -> Ptr Word8 -> FunPtr WalletBundleEffect -> Ptr () -> IO Int32
walletBundle inputSize maximumMoney input callback context
  | input == nullPtr || callback == nullFunPtr = pure (-1)
  | otherwise = catch (do
      request <- B.packCStringLen (castPtr input,inputSize)
      let effect action payout bytes = B.useAsCStringLen bytes $ \(inputPtr,inputLength) ->
            allocaArray 1 $ \reply -> do
              poke reply nullPtr
              size <- callWalletBundleEffect callback context action payout
                (castPtr inputPtr) (fromIntegral inputLength) reply
              ptr <- peekElemOff reply 0
              if ptr==nullPtr || (if action==0 then size<4 || size>2147483644 else size/=32)
                then ioError (userError "invalid bundle effect reply")
                else B.packCStringLen (castPtr ptr,fromIntegral size)
          build plan = effect 0 (Withdrawal.bundlePayout plan)
            (Withdrawal.bundleLayout plan <> Withdrawal.bundleFeeScript plan <> Withdrawal.bundleInputs plan <> Withdrawal.bundleMarker plan)
          inputRequest = Withdrawal.WithdrawalRequest maximumMoney request
          operation = if inputSize==161 then Withdrawal.AnchoredBundleRequest inputRequest (\action -> effect action 0) build
            else Withdrawal.WalletBundleRequest inputRequest build
      result <- execute operation Withdrawal.buildWalletBundle
      case result of
        Left (Withdrawal.BundleRejection _) -> pure 1
        Left (Withdrawal.AnchorRejection message) -> B.useAsCStringLen (C.pack message) $ \(ptr,size) -> do
          code <- callWalletBundleEffect callback context 4 0 (castPtr ptr) (fromIntegral size) nullPtr
          if code==0 then pure 2 else ioError (userError "bundle error publication failed")
        Right (_,transport) -> B.useAsCStringLen transport $ \(ptr,size) -> do
          code <- callWalletBundleEffect callback context 1 0 (castPtr ptr) (fromIntegral size) nullPtr
          if code==0 then pure 0 else ioError (userError "bundle publication failed")) (handleFailure (-1))

type ClaimBlockEffect = Ptr () -> Word32 -> Word64 -> Word64 -> Word64 -> Ptr Word8 -> IO Int64

elements_hs_grpc_text :: Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> IO Int32
elements_hs_grpc_text addressSize address authoritySize authority
  | any (> fromIntegral (maxBound :: Int)) [addressSize,authoritySize] ||
      (addressSize/=0 && address==nullPtr) || (authoritySize/=0 && authority==nullPtr) = pure (-1)
  | otherwise = (do
      a <- bytes address addressSize
      b <- bytes authority authoritySize
      pure (validate (Bmm.GrpcTextAdmission a b))) `catch` handleFailure (-1)
  where bytes ptr size = if size==0 then pure B.empty else B.packCStringLen (castPtr ptr,fromIntegral size)

elements_hs_grpc_plan :: Word32 -> Ptr (Ptr Word8) -> Ptr Word32 -> Ptr Word8 -> Word32 -> IO Int32
elements_hs_grpc_plan count inputs lengths output capacity = run `catch` handleFailure (-1)
  where
    run | count `notElem` [1,2] || inputs==nullPtr || lengths==nullPtr = pure (-1)
        | otherwise = do
            pointers <- peekArray (fromIntegral count) inputs
            sizes <- peekArray (fromIntegral count) lengths
            if or (zipWith (\ptr size -> ptr==nullPtr && size/=0) pointers sizes) then pure (-1) else do
              fields <- sequence [if size==0 then pure B.empty else B.packCStringLen (castPtr ptr,fromIntegral size)
                                 | (ptr,size) <- zip pointers sizes]
              let plan = case fields of
                    [method] -> fmap (const []) (Bmm.grpcMethod method)
                    [method,payload] -> fmap (const []) (execute (Bmm.GrpcPlan method payload) Bmm.planGrpc)
                    _ -> error "invalid gRPC planner field count"
                  reply = either ((B.singleton 1 <>) . C.pack)
                    (\args -> B.singleton 0 <> B.concat [wordLE 4 (fromIntegral (B.length arg)) <> arg | arg <- args]) plan
              writeReply reply output capacity

foreign import ccall "dynamic" callClaimBlockEffect :: FunPtr ClaimBlockEffect -> ClaimBlockEffect
elements_hs_usdd_extract_block :: Word32 -> Word32 -> Word64 -> Word32 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> FunPtr ClaimBlockEffect -> Ptr () -> FunPtr Deposit.HashTransaction -> IO Int32
elements_hs_usdd_extract_block mode zero count prefix state emptyRoots profile effect context hasher = run `catch` handleFailure (-1)
  where
    run | mode>2 || zero > 1 || prefix>255 || profile == nullPtr || effect == nullFunPtr || hasher == nullFunPtr ||
          (mode/=0 && (state==nullPtr || emptyRoots==nullPtr)) = pure (-1)
        | otherwise = do
            config <- B.packCStringLen (castPtr profile,69)
            let action kind tx out cursor payload = allocaArray (max 216 (B.length payload)) $ \buffer -> do
                  B.useAsCStringLen payload $ \(ptr,size) -> copyBytes buffer (castPtr ptr) size
                  code <- callClaimBlockEffect effect context kind tx out cursor buffer
                  bytes <- case kind of
                    2 | code>=0 -> B.packCStringLen (castPtr buffer,2)
                    4 | code>=0 -> B.packCStringLen (castPtr buffer,216)
                    6 | code>=70 && code<=216 -> B.packCStringLen (castPtr buffer,fromIntegral code)
                      | code>=0 -> error "invalid checkpoint metadata size"
                    _ -> pure B.empty
                  pure (code,bytes)
                extraction = Usdd.ExtractBlock (zero/=0) config action (usddHash hasher)
            result <- if mode==0 then execute (Check extraction) Validate else do
              before <- B.packCStringLen (castPtr state,2080)
              empty <- B.packCStringLen (castPtr emptyRoots,2080)
              let application = Usdd.ApplyBlock count (fromIntegral prefix) before empty extraction
              if mode==1 then execute (Check application) Validate
                else execute (Check (Usdd.DeriveBlock application)) Validate
            pure (fromIntegral result)

elements_hs_usdd_claim_hashes :: Word32 -> Word64 -> Word64 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> FunPtr Deposit.HashTransaction -> IO Int32
elements_hs_usdd_claim_hashes mode index size profile input output hasher = run `catch` handleFailure (-1)
  where
    run | mode > 4 || any (==nullPtr) [profile,output] || (size/=0 && input==nullPtr) || hasher == nullFunPtr ||
          size > fromIntegral (maxBound :: Int) || (case mode of 3 -> size `mod` 200 /= 0; 4 -> size /= 216; _ -> size /= 168) = pure (-1)
        | otherwise = do
            config <- B.packCStringLen (castPtr profile,69)
            bytes <- if size==0 then pure B.empty else B.packCStringLen (castPtr input,fromIntegral size)
            result <- case mode of
              3 -> execute (Check (Usdd.ClaimPrefix index config bytes (usddHash hasher))) Validate
              4 -> execute (Check (Usdd.ExtractClaim config bytes (usddHash hasher))) Validate
              _ -> Right <$> execute (Check (Usdd.ClaimHashes mode config bytes (usddHash hasher))) Validate
            publishResult (\digest -> B.useAsCStringLen digest (\(ptr,n) -> copyBytes output (castPtr ptr) n)) result

elements_hs_usdd_checkpoint :: Word64 -> Word64 -> Word32 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Word32 -> Ptr Word8 -> FunPtr Deposit.HashTransaction -> IO Int32
elements_hs_usdd_checkpoint beforeCount afterCount prefix before after emptyRoots profile size output hasher = run `catch` handleFailure (-1)
  where
    run | prefix > 255 || size < 69 || any (==nullPtr) [before,after,emptyRoots,profile,output] || hasher == nullFunPtr = pure (-1)
        | otherwise = do
            prior <- B.packCStringLen (castPtr before,2080)
            following <- B.packCStringLen (castPtr after,2080)
            empty <- B.packCStringLen (castPtr emptyRoots,2080)
            config <- B.packCStringLen (castPtr profile,fromIntegral size)
            result <- execute (Check (Usdd.Checkpoint beforeCount afterCount (fromIntegral prefix) prior following empty config (usddHash hasher))) Validate
            publishBytes 32 output result

usddHash :: FunPtr Deposit.HashTransaction -> B.ByteString -> IO B.ByteString
usddHash hasher bytes
  | toInteger (B.length bytes) > toInteger (maxBound :: Word32) = error "USDD hash input too large"
  | otherwise = B.useAsCStringLen bytes $ \(ptr,size) -> allocaArray 32 $ \output -> do
      status <- Deposit.hashTransaction hasher (castPtr ptr) (fromIntegral size) output
      if status /= 1 then error "USDD hash failed" else B.packCStringLen (castPtr output,32)

elements_hs_usdd_accumulator_version :: Word32 -> IO Int32
elements_hs_usdd_accumulator_version version =
  evaluate (execute (Check (Usdd.AccumulatorVersion version)) Validate) `catch` handleFailure (-1)

elements_hs_usdd_accumulator :: Word32 -> Word64 -> Word32 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Word64 -> FunPtr Deposit.HashTransaction -> IO Int32
elements_hs_usdd_accumulator mode count prefix state emptyRoots leaf leafCount hasher =
  (allocaArray 1 $ \nextCount -> elements_hs_usdd_accumulator_count
    mode count prefix state emptyRoots leaf leafCount hasher nextCount) `catch` handleFailure (-1)

elements_hs_usdd_accumulator_count :: Word32 -> Word64 -> Word32 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Word64 -> FunPtr Deposit.HashTransaction -> Ptr Word64 -> IO Int32
elements_hs_usdd_accumulator_count mode count prefix state emptyRoots leaf leafCount hasher nextCount = run `catch` handleFailure (-1)
  where
    run | nextCount==nullPtr || mode > 5 || prefix > 255 || any (==nullPtr) [state,emptyRoots,leaf] || hasher == nullFunPtr ||
          leafCount > fromIntegral (maxBound :: Int) `div` 32 || (mode < 3 && leafCount /= 1) ||
          (mode == 5 && (count > 255 || leafCount /= 0)) = pure (-1)
        | mode == 3 && count >= leafCount = pure 1
        | mode == 5 = execute (Check (Usdd.EmptyRoots (fromIntegral count) (fromIntegral prefix) hash)) Validate >>= \output -> store (count,output) >> pure 0
        | otherwise = do
            bytes <- B.packCStringLen (castPtr state,2080)
            empty <- B.packCStringLen (castPtr emptyRoots,2080)
            item <- B.packCStringLen (castPtr leaf,fromIntegral leafCount * 32)
            if mode == 4 then do
              (complete,cursor,output) <- execute (Check (Usdd.AccumulatorBatch count (fromIntegral prefix) bytes empty item hash)) Validate
              store (cursor,output)
              pure (if complete then 0 else 1)
            else do
              result <- if mode == 3 then fmap (fmap (\output -> (count,output))) $
                  execute (Check (Usdd.InclusionProof count (fromIntegral prefix) empty item hash)) Validate
                else execute (Check (Usdd.Accumulator mode count (fromIntegral prefix) bytes empty item hash)) Validate
              case result of
                Nothing -> pure 1
                Just output -> store output >> pure 0
    store (cursor,output) = B.useAsCString output (\ptr -> copyBytes state (castPtr ptr) 2080) >> poke nextCount cursor
    hash = usddHash hasher

elements_hs_usdd_annex :: Word64 -> Word64 -> Ptr Word32 -> Ptr Word8 -> IO Int32
elements_hs_usdd_annex size limit profile input = run `catch` handleFailure (-1)
  where
    run | profile == nullPtr || (size /= 0 && input == nullPtr) = pure (-1)
        | otherwise = do
            fields <- peekArray 3 profile
            bytes <- if size == 0 then pure B.empty else B.packCStringLen (castPtr input, fromIntegral (min size 87))
            fromIntegral <$> evaluate (execute (Check (Usdd.Annex size limit fields bytes)) Validate)

elements_hs_usdd_legacy :: Word32 -> Ptr (Ptr Word8) -> Ptr Word64 -> Ptr Word32 -> Word64 -> Word32 -> Word32 -> Ptr Word64 -> FunPtr Deposit.HashTransaction -> IO Int32
elements_hs_usdd_legacy mode inputs sizes profile limit bmm active shape hasher = run `catch` handleFailure (-1)
  where
    run | mode > 2 || inputs == nullPtr || sizes == nullPtr || profile == nullPtr || shape == nullPtr ||
          bmm > 1 || active > 1 || hasher == nullFunPtr = pure (-1)
        | otherwise = do
            fields <- peekArray 5 profile
            usddLegacy mode inputs sizes fields limit bmm active shape hasher

usddLegacy :: Word32 -> Ptr (Ptr Word8) -> Ptr Word64 -> [Word32] -> Word64 -> Word32 -> Word32 -> Ptr Word64 -> FunPtr Deposit.HashTransaction -> IO Int32
usddLegacy mode inputs sizes fields limit bmm active shape hasher = do
            pointers <- peekArray 7 inputs
            lengths <- peekArray 7 sizes
            dimensions <- peekArray 4 shape
            let copy ptr size = if size == 0 then pure B.empty else B.packCStringLen (castPtr ptr, fromIntegral size)
                field n = copy (pointers !! n) (lengths !! n)
                identity guest journal = do
                  controller <- field 0
                  expectedController <- field 1
                  expectedGuest <- field 3
                  domain <- field 5
                  validate (Usdd.LegacyRequest (fields !! 0) (fromIntegral (fields !! 1))
                    (fromIntegral (fields !! 2)) controller expectedController guest expectedGuest journal domain (usddHash hasher))
            if any (> fromIntegral (maxBound :: Int)) lengths ||
               or (zipWith (\size ptr -> size /= 0 && ptr == nullPtr) lengths pointers) ||
               fields !! 1 > 255 || fields !! 2 > 255 || dimensions !! 2 > 255 || dimensions !! 3 > 1 then pure (-1)
            else fromIntegral <$> if mode == 0 then do
              guest <- field 2
              journal <- field 4
              identity guest journal
            else do
              prefix <- copy (pointers !! 6) (min (lengths !! 6) 87)
              let annex = Usdd.Annex (lengths !! 6) limit [fields !! 3, fields !! 4, fields !! 1] prefix
                  checkIdentity = do
                    let publicSize = B.foldl' (\n byte -> n * 256 + fromIntegral byte) 0 (B.take 4 (B.drop 15 prefix)) :: Word64
                    journal <- copy (pointers !! 6 `plusPtr` 55) publicSize
                    identity (B.take 32 (B.drop 23 prefix)) journal
              if mode == 1 then Usdd.admitResult 0 annex (bmm == 1) (active == 1) checkIdentity
              else validate (Usdd.Resource annex (dimensions !! 0) (lengths !! 0)
                (dimensions !! 1) (dimensions !! 2) (dimensions !! 3 == 1) checkIdentity)

type ReadUsddWitness = Ptr () -> Word64 -> IO Int32
foreign import ccall safe "dynamic" callUsddWitness :: FunPtr ReadUsddWitness -> ReadUsddWitness
elements_hs_usdd_resources :: Word64 -> Ptr (Ptr Word8) -> Ptr Word64 -> Ptr Word32 -> Word64 -> Ptr Word64 -> Ptr Word64 -> FunPtr Deposit.HashTransaction -> FunPtr ReadUsddWitness -> Ptr () -> IO Int32
elements_hs_usdd_resources count inputs sizes profile limit shape total hasher reader context = run `catch` handleFailure (-1)
  where
    run | inputs==nullPtr || sizes==nullPtr || profile==nullPtr || shape==nullPtr || total==nullPtr ||
          hasher==nullFunPtr || reader==nullFunPtr = pure (-1)
        | otherwise = do
            fields <- peekArray 5 profile
            (flags,used) <- execute (Check (Usdd.ResourceScan count (\index -> do
              status <- callUsddWitness reader context index
              if status/=1 then pure (-1)
              else fromIntegral <$> usddLegacy 2 inputs sizes fields limit 0 0 shape hasher))) Validate
            if flags<0 then pure (-1) else poke total used >> pure flags

elements_hs_usdd_resource_workflow :: Ptr Word64 -> Ptr (Ptr Word8) -> Ptr Word64 -> Ptr Word32 -> Word64 -> Ptr Word64 -> Ptr Word64 -> FunPtr Deposit.HashTransaction -> FunPtr CursorEffect -> Ptr () -> IO Int32
elements_hs_usdd_resource_workflow options inputs sizes profile limit shape output hasher callback context
  | options==nullPtr || inputs==nullPtr || sizes==nullPtr || profile==nullPtr || shape==nullPtr || hasher==nullFunPtr = pure (-1)
  | otherwise = workCall (\readField -> do
      [mode,flags,count,initial,lane,weight] <- peekArray 6 options
      fields <- peekArray 5 profile
      let package = mode==1
          classify index = do
            witnesses <- readField (if mode==2 then 7 else if package then 3 else 0) index 0
            validate (Usdd.ResourceScan witnesses (\witness -> do
              status <- readField 6 witness 0
              if status/=1 then pure (-1)
              else fromIntegral <$> usddLegacy 2 inputs sizes fields limit 0 0 shape hasher))
      if mode>2 || flags>fromIntegral (maxBound :: Word32) then pure (-1,0)
      else if mode==2 then execute (Check (Usdd.PolicyResources count (classify 0)
        (\step index -> readField step index 0))) Validate
      else execute (Check (Usdd.ResourceAdmission package (fromIntegral flags) count initial lane weight
        classify (\step index -> readField step index 0))) Validate) output callback context

elements_hs_usdd_admission :: Word32 -> Word64 -> Word64 -> Ptr Word32 -> Ptr Word8 -> Word32 -> Word32 -> FunPtr Deposit.ReadCtipOpcode -> Ptr () -> IO Int32
elements_hs_usdd_admission lane size limit profile input bmm active reader context = run `catch` handleFailure (-1)
  where
    run | lane < 1 || lane > 2 || bmm > 1 || active > 1 || profile == nullPtr ||
          (size /= 0 && input == nullPtr) || (lane /= 2 && reader == nullFunPtr) = pure (-1)
        | otherwise = do
            fields <- peekArray 3 profile
            bytes <- if size == 0 then pure B.empty else B.packCStringLen (castPtr input, fromIntegral (min size 87))
            fromIntegral <$> execute (Check (Usdd.Admission lane (Usdd.Annex size limit fields bytes)
              (bmm == 1) (active == 1) (fromIntegral <$> Deposit.readCtipOpcode reader context 0))) Validate

type WriteFingerprint = Ptr () -> Ptr Word8 -> Word64 -> IO Int32
foreign import ccall safe "dynamic" callReentrantPredicate :: FunPtr Deposit.ReadCtipOpcode -> Deposit.ReadCtipOpcode
elements_hs_identity_write :: FunPtr Deposit.ReadCtipOpcode -> Ptr () -> IO Int32
elements_hs_identity_write = callbackCall callReentrantPredicate (\action -> execute (Check (Exchange.IdentityWrite action)) Validate)

elements_hs_material_name :: Word32 -> Word64 -> Ptr Word8 -> IO Int32
elements_hs_material_name mode size input = run `catch` handleFailure (-1)
  where
    run | mode>1 || size>fromIntegral (maxBound :: Int) || input==nullPtr = pure (-1)
        | otherwise = do
            name <- B.packCStringLen (castPtr input,fromIntegral size)
            pure $ if execute (Check (Exchange.MaterialName (mode==1) name)) Validate then 1 else 0

type CustodyHash = Ptr () -> Word32 -> Word64 -> Ptr Word8 -> Ptr Word8 -> IO Int32
foreign import ccall "dynamic" callCustodyHash :: FunPtr CustodyHash -> CustodyHash

custodyDigest :: FunPtr CustodyHash -> Ptr () -> Word32 -> B.ByteString -> IO B.ByteString
custodyDigest callback context kind bytes = B.useAsCStringLen bytes $ \(ptr,size) -> allocaArray 32 $ \digest -> do
  code <- callCustodyHash callback context kind (fromIntegral size) (castPtr ptr) digest
  if code/=0 then ioError (userError "custody hash callback failed") else B.packCStringLen (castPtr digest,32)

elements_hs_configuration_identity :: Word64 -> Ptr Word8 -> Ptr Word8 -> FunPtr CustodyHash -> Ptr () -> Word64 -> Ptr Word8 -> Ptr Word64 -> IO Int32
elements_hs_configuration_identity size network identities callback context capacity output written = run `catch` handleFailure (-1)
  where
    run | size > fromIntegral (maxBound :: Int)-258 || capacity < size+258 ||
          network==nullPtr || identities==nullPtr || callback==nullFunPtr || output==nullPtr || written==nullPtr = pure (-1)
        | otherwise = do
            name <- B.packCStringLen (castPtr network,fromIntegral size)
            hashes <- B.packCStringLen (castPtr identities,64)
            result <- execute (Check (Exchange.IdentityRecord name hashes digest)) Validate
            case result of
              Nothing -> pure (-1)
              Just record -> B.useAsCStringLen record $ \(ptr,count) -> do
                copyBytes output (castPtr ptr) count
                poke written (fromIntegral count)
                pure 0
    digest = custodyDigest callback context 0

elements_hs_exchange_sources :: Ptr Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> Ptr Word8 -> Ptr Word64 -> IO Int32
elements_hs_exchange_sources fields hashes size input output written = run `catch` handleFailure (-1)
  where
    run | fields == nullPtr || hashes == nullPtr || input == nullPtr || output == nullPtr || written == nullPtr ||
          size < 8 || (size-8) `mod` 104 /= 0 || size > fromIntegral (maxBound :: Int)-104 = pure (-1)
        | otherwise = do
            values <- peekArray 4 fields
            identities <- B.packCStringLen (castPtr hashes,96)
            state <- B.packCStringLen (castPtr input,fromIntegral size)
            case execute (Check (Exchange.SourceTracking values identities state)) Validate of
              Left code -> pure (fromIntegral code)
              Right next -> do
                B.useAsCStringLen next (\(ptr,n) -> copyBytes output (castPtr ptr) n)
                poke written (fromIntegral (B.length next))
                pure 0

elements_hs_exchange_append_marker :: Ptr Word64 -> Ptr Word8 -> FunPtr CustodyHash -> Ptr () -> Ptr Word8 -> IO Int32
elements_hs_exchange_append_marker fields input callback context output = run `catch` handleFailure (-1)
  where
    run | fields == nullPtr || input == nullPtr || callback == nullFunPtr || output == nullPtr = pure (-1)
        | otherwise = do
            values <- peekArray 14 fields
            bytes <- B.packCStringLen (castPtr input,683)
            result <- execute (Check (Exchange.AppendMarker values bytes effect)) Validate
            publishBytes 48 output result
    effect kind bytes = B.useAsCStringLen bytes $ \(ptr,size) -> allocaArray 32 $ \digest -> do
      code <- callCustodyHash callback context kind (fromIntegral size) (castPtr ptr) digest
      if code /= 0 then ioError (userError "append callback failed")
      else if kind == 0 then pure B.empty else B.packCStringLen (castPtr digest,32)

elements_hs_exchange_custody_root :: Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> FunPtr CustodyHash -> Ptr () -> Ptr Word8 -> IO Int32
elements_hs_exchange_custody_root bundle identities size receipts callback context output = run `catch` handleFailure (-1)
  where
    run | bundle > 4294967295 || size > 690 || size `mod` 138 /= 0 || identities == nullPtr || receipts == nullPtr || callback == nullFunPtr || output == nullPtr = pure (-1)
        | otherwise = do
            fields <- B.packCStringLen (castPtr identities,192)
            bytes <- B.packCStringLen (castPtr receipts,fromIntegral size)
            result <- execute (Check (Exchange.CustodyRoot bundle fields bytes hash)) Validate
            case result of
              Just root -> B.useAsCString root (\ptr -> copyBytes output (castPtr ptr) 32) >> pure 0
              Nothing -> pure (-1)
    hash = custodyDigest callback context

elements_hs_exchange_annex_header :: Word64 -> Word64 -> Word64 -> Ptr Word8 -> Ptr Word64 -> IO Int32
elements_hs_exchange_annex_header expected limit size input output = run `catch` handleFailure (-1)
  where
    run | input == nullPtr || output == nullPtr = pure (-1)
        | otherwise = do
            bytes <- B.packCStringLen (castPtr input,fromIntegral (min size 15))
            publishResult (pokeArray output) (execute (Check (Exchange.AnnexHeader expected limit size bytes)) Validate)

elements_hs_exchange_receipts :: Word32 -> Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> IO Int32
elements_hs_exchange_receipts count size input capacity output = run `catch` handleFailure (-1)
  where
    run | count < 3 || count > 5 || size > fromIntegral (maxBound :: Int) ||
          capacity /= fromIntegral count * 138 + 1 || input == nullPtr || output == nullPtr = pure (-1)
        | otherwise = do
            bytes <- B.packCStringLen (castPtr input,fromIntegral (min size (fromIntegral count * 140 + 1)))
            case execute (Check (Exchange.CustodyReceipts (fromIntegral count) bytes)) Validate of
              Left code -> pure (fromIntegral code)
              Right encoded | B.length encoded == fromIntegral capacity ->
                B.useAsCString encoded (\ptr -> copyBytes output (castPtr ptr) (fromIntegral capacity)) >> pure 0
              _ -> pure (-1)

elements_hs_exchange_genesis_funding :: Word64 -> Word64 -> Word64 -> Ptr Word8 -> IO Int32
elements_hs_exchange_genesis_funding mtp price capacity output = run `catch` handleFailure (-1)
  where
    run | capacity /= 725 || output == nullPtr = pure (-1)
        | otherwise = do
            let bytes = execute (Check (Exchange.GenesisFunding mtp price)) Validate
            if B.length bytes /= 725 then pure (-1)
              else B.useAsCString bytes (\input -> copyBytes output (castPtr input) 725) >> pure 0

type ReadSpendCount = Ptr () -> Word64 -> IO Word64
elements_hs_exchange_source_admission :: FunPtr ReadSpendCount -> Ptr () -> IO Int32
elements_hs_exchange_source_admission = callbackCall callReadSpendCount (\action -> fromIntegral <$> execute (Check (Exchange.SourceAdmission action)) Validate)

elements_hs_exchange_genesis_state :: Word32 -> Word64 -> Word64 -> Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> IO Int32
elements_hs_exchange_genesis_state mode height price size input capacity output = run `catch` handleFailure (-1)
  where
    (expectedInput,expectedOutput) = case mode of
      0 -> (128,242); 1 -> (1223,1713); 2 -> (352,468); 3 -> (32,34); 4 -> (64,64); 5 -> (0,383); 6 -> (0,100); 7 -> (0,41)
      8 -> (1170,914); 9 -> (1947,914); 10 -> (684,914); 11 -> (488,914); _ -> (0,0)
    run | mode > 11 || size /= expectedInput || capacity /= expectedOutput || (size/=0 && input == nullPtr) || output == nullPtr = pure (-1)
        | otherwise = do
            bytes <- if size==0 then pure B.empty else B.packCStringLen (castPtr input, fromIntegral size)
            let value = if mode>=8 then Exchange.CapitalSnapshot (mode-8) height price bytes
                        else if mode>=5 then Exchange.FixedProfile mode
                        else if mode >= 3 then Exchange.TapPreimage (mode == 3) height bytes
                        else if mode == 2 then Exchange.GenesisCovenant height bytes else Exchange.GenesisState (mode == 1) height price bytes
            case execute (Check value) Validate of
              Just encoded | B.length encoded == fromIntegral capacity ->
                B.useAsCString encoded (\ptr -> copyBytes output (castPtr ptr) (fromIntegral capacity)) >> pure 0
              _ -> pure (-1)

elements_hs_exchange_genesis_roots :: Word64 -> Word64 -> Word64 -> Ptr Word8 -> FunPtr CustodyHash -> Ptr () -> Ptr Word8 -> IO Int32
elements_hs_exchange_genesis_roots height mtp price input callback context output = run `catch` handleFailure (-1)
  where
    run | input==nullPtr || callback==nullFunPtr || output==nullPtr = pure (-1)
        | otherwise = do
            bytes <- B.packCStringLen (castPtr input,384)
            result <- execute (Exchange.GenesisRequest height mtp price bytes hash) Exchange.buildGenesisRoots
            case result of
              Just roots | B.length roots==128 -> B.useAsCString roots (\ptr -> copyBytes output (castPtr ptr) 128) >> pure 0
              _ -> pure (-1)
    hash = custodyDigest callback context

elements_hs_exchange_frozen_configuration :: Word64 -> Ptr Word8 -> Ptr Word8 -> FunPtr CustodyHash -> Ptr () -> IO Int32
elements_hs_exchange_frozen_configuration size input market callback context = run `catch` handleFailure (-1)
  where
    run | size/=1977 = pure 1
        | input==nullPtr || market==nullPtr || callback==nullFunPtr = pure (-1)
        | otherwise = do
            bytes <- B.packCStringLen (castPtr input,1977)
            identity <- B.packCStringLen (castPtr market,16)
            fromIntegral <$> execute (Exchange.FrozenRequest identity bytes effect) Exchange.decodeFrozenRequest
    effect kind bytes = B.useAsCStringLen bytes $ \(ptr,count) -> allocaArray 32 $ \output -> do
      code <- callCustodyHash callback context kind (fromIntegral count) (castPtr ptr) output
      if code/=0 then ioError (userError "frozen configuration effect failed")
        else if kind>=4 then pure B.empty else B.packCStringLen (castPtr output,32)

type ConfigurationHashEffect = Ptr () -> Word32 -> Ptr Word8 -> IO Int32
foreign import ccall "dynamic" callConfigurationHashEffect :: FunPtr ConfigurationHashEffect -> ConfigurationHashEffect
elements_hs_configuration_hashes :: Word32 -> FunPtr ConfigurationHashEffect -> Ptr () -> IO Int32
elements_hs_configuration_hashes direct callback context
  | direct>1 || callback==nullFunPtr = pure (-1)
  | otherwise = (allocaArray 64 $ \buffer -> do
      let readText index = do
            code <- callConfigurationHashEffect callback context index buffer
            case code of
              0 -> B.packCStringLen (castPtr buffer,64)
              1 -> pure B.empty
              _ -> ioError (userError "hash argument read failed")
          publish index bytes = B.useAsCString bytes $ \ptr -> do
            code <- callConfigurationHashEffect callback context (22+index) (castPtr ptr)
            if code==0 then pure () else ioError (userError "hash argument publication failed")
      fromIntegral <$> execute (Check (Exchange.HashArguments (direct==1) readText publish)) Validate) `catch` handleFailure (-1)

elements_hs_fee_asset :: Word32 -> Word64 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO Int32
elements_hs_fee_asset flags size input pegged output = run `catch` handleFailure (-1)
  where
    run | flags > 3 || pegged == nullPtr || output == nullPtr = pure (-1)
        | not (testBit flags 0) && size /= 0 = pure (-1)
        | testBit flags 0 && size /= 64 = pure 1
        | testBit flags 0 && input == nullPtr = pure (-1)
        | otherwise = do
            configured <- if testBit flags 0 then Just <$> B.packCStringLen (castPtr input,64) else pure Nothing
            asset <- B.packCStringLen (castPtr pegged,32)
            publishBytes 32 output (execute (Check (Exchange.FeeAsset configured asset (testBit flags 1))) Validate)

elements_hs_activation_shape :: FunPtr MatchFact -> Ptr () -> IO Int32
elements_hs_activation_shape = callbackCall callMatchFact (\readFact ->
  execute (Check (ScriptPolicy.ActivationShape readFact)) Validate)

elements_hs_activation_budget :: Int64 -> Word32 -> Ptr Int64 -> FunPtr PolicyEffect -> Ptr () -> IO Int32
elements_hs_activation_budget ordinary input output = callbackCall callReentrantPredicate (\readFact ->
  if output == nullPtr then pure (-1) else do
    result <- execute (Check (ScriptPolicy.ActivationBudget ordinary input readFact)) Validate
    publishResult (\value -> evaluate value >>= poke output) result)

elements_hs_verifier_startup :: Word32 -> FunPtr PolicyEffect -> Ptr () -> IO Int32
elements_hs_verifier_startup active
  | active > 1 = \_ _ -> pure (-1)
  | otherwise = callbackCall runPolicyEffect (\readFact ->
      execute (Check (ScriptPolicy.VerifierStartup (active==1) readFact)) Validate)

type RustVerifierVersion = IO Word32
type RustVerifierIdentity = Ptr Word8 -> CSize -> IO Word32
foreign import ccall safe "dynamic" rustVerifierIdentity :: FunPtr RustVerifierIdentity -> RustVerifierIdentity

elements_hs_verifier_identity :: Word32 -> Word32 -> Word32 -> Ptr Word8 -> FunPtr RustVerifierVersion -> FunPtr RustVerifierVersion -> FunPtr RustVerifierIdentity -> IO Int32
elements_hs_verifier_identity active abi identityVersion expected version format identity
  | active > 1 = pure (-1)
  | active == 0 = pure 0
  | expected == nullPtr = pure (-1)
  | otherwise = (withArray (replicate 32 0) $ \actual -> do
      wanted <- B.packCStringLen (castPtr expected,32)
      let fact step = fmap (fromIntegral . fromEnum) $ case step of
            0 -> pure (B.any (/=0) wanted)
            1 -> pure (version/=nullFunPtr && format/=nullFunPtr && identity/=nullFunPtr)
            2 -> (==abi) <$> rustVerifierVersion version
            3 -> (==identityVersion) <$> rustVerifierVersion format
            4 -> (==0) <$> rustVerifierIdentity identity actual 32
            5 -> (==wanted) <$> B.packCStringLen (castPtr actual,32)
            _ -> pure False
      execute (Check (ScriptPolicy.VerifierStartup True fact)) Validate)
      `catch` handleFailure (-1)

type RustCustody = Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> IO CBool
foreign import ccall safe "dynamic" rustCustody :: FunPtr RustCustody -> RustCustody

rustBoolean :: IO CBool -> IO Int32
rustBoolean action = (fromIntegral . fromEnum . (/=0) <$> action) `catch` handleFailure (-1)

elements_hs_verify_custody :: FunPtr RustCustody -> Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> Word64 -> IO Int32
elements_hs_verify_custody verify bundle bundleSize registry registrySize receipts receiptSize count
  | verify==nullFunPtr || not (valid bundle bundleSize && valid registry registrySize && valid receipts receiptSize) ||
      receiptSize `mod` 138 /= 0 || count /= receiptSize `div` 138 = pure 0
  | otherwise = rustBoolean (rustCustody verify bundle (fromIntegral bundleSize)
      registry (fromIntegral registrySize) receipts (fromIntegral count))
  where valid pointer size = (size==0 || pointer/=nullPtr) && size <= fromIntegral (maxBound :: CSize)

type RustGroth16 = Ptr () -> Ptr Word8 -> CSize -> Ptr Word32 -> Ptr Word8 -> IO CBool
foreign import ccall safe "dynamic" rustGroth16 :: FunPtr RustGroth16 -> RustGroth16

type Groth16Hash = Ptr Word8 -> Ptr Word8 -> CSize -> IO CBool
foreign import ccall safe "dynamic" groth16Hash :: FunPtr Groth16Hash -> Groth16Hash

hashGroth16Bytes :: FunPtr Groth16Hash -> B.ByteString -> IO B.ByteString
hashGroth16Bytes hash bytes = B.useAsCStringLen bytes $ \(pointer,len) -> allocaArray 32 $ \output -> do
  ok <- groth16Hash hash output (castPtr pointer) (fromIntegral len)
  if ok==0 then pure B.empty else B.packCStringLen (castPtr output,32)

elements_hs_parse_groth16 :: Word32 -> Ptr Word8 -> Word64 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Word32 -> FunPtr Groth16Hash -> IO Int32
elements_hs_parse_groth16 kind input size program digest values capacity hash
  | kind<1 || kind>4 || size>2062 || Exchange.groth16Layout kind (fromIntegral size)==Nothing ||
    fromIntegral capacity+435/=size || input==nullPtr || program==nullPtr || digest==nullPtr ||
    values==nullPtr || hash==nullFunPtr = pure 0
  | otherwise = (do
      annex <- B.packCStringLen (castPtr input,fromIntegral size)
      accepted <- execute (Check (Exchange.Groth16Envelope kind annex (hashGroth16Bytes hash))) Validate
      if not accepted then pure 0 else mask_ $ do
        publish program (B.take 32 (B.drop 11 annex))
        publish digest (B.take 32 (B.drop 43 annex))
        publish values (B.drop 435 annex)
        pure 1) `catch` handleFailure (-1)
  where publish output bytes = B.useAsCStringLen bytes $ \(pointer,len) -> copyBytes output (castPtr pointer) len

elements_hs_groth16_proof :: Word32 -> Ptr Word8 -> Word64 -> Ptr Word8 -> Ptr Word8 -> FunPtr Groth16Hash -> FunPtr RustGroth16 -> Ptr () -> IO Int32
elements_hs_groth16_proof kind input size expectedProgram expectedDigest hash verify context
  | size>2062 || Exchange.groth16Layout kind (fromIntegral size)==Nothing ||
    input==nullPtr || expectedProgram==nullPtr || expectedDigest==nullPtr ||
    hash==nullFunPtr || verify==nullFunPtr = pure 0
  | otherwise = (do
      annex <- B.packCStringLen (castPtr input,fromIntegral size)
      program <- B.packCStringLen (castPtr expectedProgram,32)
      digest <- B.packCStringLen (castPtr expectedDigest,32)
      accepted <- execute (Check (Exchange.Groth16Proof kind annex program digest (hashGroth16Bytes hash) verifyBytes)) Validate
      pure (if accepted then 1 else 0)) `catch` handleFailure (-1)
  where
    verifyBytes proof words32 digest = B.useAsCStringLen proof $ \(pointer,len) ->
      withArray words32 $ \program -> B.useAsCString digest $ \digestPointer ->
        (/=0) <$> rustGroth16 verify context (castPtr pointer) (fromIntegral len) program (castPtr digestPointer)

elements_hs_verify_groth16 :: FunPtr RustGroth16 -> Ptr () -> Ptr Word8 -> Word64 -> Ptr Word32 -> Ptr Word8 -> IO Int32
elements_hs_verify_groth16 verify context proof size program digest
  | context/=nullPtr || verify==nullFunPtr || program==nullPtr || digest==nullPtr ||
      (size/=0 && proof==nullPtr) || size > fromIntegral (maxBound :: CSize) = pure 0
  | otherwise = rustBoolean (rustGroth16 verify context proof (fromIntegral size) program digest)

type RustVerifyAnnex = Word32 -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> IO Word32
type RustAnnexRead = Ptr () -> Ptr (Ptr Word8) -> Ptr CSize -> IO CBool
foreign import ccall safe "dynamic" rustAnnexRead :: FunPtr RustAnnexRead -> RustAnnexRead
foreign import ccall safe "dynamic" rustVerifierVersion :: FunPtr RustVerifierVersion -> RustVerifierVersion
foreign import ccall safe "dynamic" rustVerifyAnnex :: FunPtr RustVerifyAnnex -> RustVerifyAnnex

rustAvailable :: FunPtr RustVerifierVersion -> FunPtr RustVerifyAnnex -> IO Bool
rustAvailable version verify
  | version==nullFunPtr || verify==nullFunPtr = pure False
  | otherwise = (==1) <$> rustVerifierVersion version

elements_hs_verify_jet :: FunPtr RustVerifierVersion -> FunPtr RustVerifyAnnex -> FunPtr RustAnnexRead -> Ptr () -> Ptr Word8 -> Ptr Word8 -> IO Int32
elements_hs_verify_jet version verify reader context program digest =
  execute (Check (ScriptPolicy.JournalVerifier valid (rustAvailable version verify) verification)) Validate `catch` handleFailure (-1)
  where
    valid = reader/=nullFunPtr && program/=nullPtr && digest/=nullPtr
    verification = alloca $ \buffer -> alloca $ \size -> do
      poke buffer nullPtr
      poke size 0
      found <- rustAnnexRead reader context buffer size
      if found==0 then pure 1 else do
        annex <- peek buffer
        count <- peek size
        if annex==nullPtr || count==0 then pure 1 else do
          tag <- peek annex
          if tag/=0x50 then pure 1 else rustVerifyAnnex verify 1 annex count program 32 digest 32

elements_hs_verify_journal :: FunPtr RustVerifierVersion -> FunPtr RustVerifyAnnex -> Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> IO Int32
elements_hs_verify_journal version verify annex size program programSize digest digestSize =
  execute (Check (ScriptPolicy.JournalVerifier valid available verification)) Validate `catch` handleFailure (-1)
  where
    valid = programSize==32 && digestSize==32 && program/=nullPtr && digest/=nullPtr &&
      (size==0 || annex/=nullPtr) && size <= fromIntegral (maxBound :: CSize)
    available = rustAvailable version verify
    verification = rustVerifyAnnex verify 1 annex (fromIntegral size) program 32 digest 32

elements_hs_standardness_gate :: Word32 -> Word32 -> Word64 -> Word64 -> IO Int32
elements_hs_standardness_gate kind facts count limit = run `catch` handleFailure (-1)
  where
    run = case kind of
      0 | count==0 && limit==0 -> apply (ScriptPolicy.AnnexNetwork facts)
      1 | count==0 && limit==0 -> apply (ScriptPolicy.OutputExceptions facts)
      2 -> apply (ScriptPolicy.WitnessResources facts count limit)
      _ -> pure (-1)
    apply value = evaluate (execute (Check value) Validate)

elements_hs_ctv_admission :: Word32 -> Word64 -> IO Int32
elements_hs_ctv_admission flags size =
  evaluate (execute (Check (ScriptPolicy.TemplateAdmission flags size)) Validate) `catch` handleFailure (-1)

elements_hs_return_marker :: Word64 -> Ptr Word8 -> Ptr Word8 -> IO Int32
elements_hs_return_marker size input magic
  | magic == nullPtr || size > fromIntegral (maxBound :: Int) || (size /= 0 && input == nullPtr) = pure (-1)
  | otherwise = (do
      bytes <- if size == 0 then pure B.empty else B.packCStringLen (castPtr input,fromIntegral size)
      marker <- B.packCStringLen (castPtr magic,4)
      evaluate (if execute (Check (ScriptPolicy.ReturnMarker marker bytes)) Validate then 1 else 0)) `catch` handleFailure (-1)

elements_hs_bond_marker_policy :: Word32 -> Word64 -> Ptr Word8 -> IO Int32
elements_hs_bond_marker_policy exact size input
  | exact > 1 || size > fromIntegral (maxBound :: Int) || (size /= 0 && input == nullPtr) = pure (-1)
  | otherwise = (do
      bytes <- if size == 0 then pure B.empty else B.packCStringLen (castPtr input,fromIntegral size)
      evaluate (if execute (Check (ScriptPolicy.BondMarkerPolicy (exact==1) bytes)) Validate then 1 else 0)) `catch` handleFailure (-1)

elements_hs_transaction_weight :: Word32 -> Word64 -> Word64 -> Word64 -> Word64 -> IO Int32
elements_hs_transaction_weight bond total annex ordinary proof =
  evaluate (execute (Check (ScriptPolicy.TransactionWeight bond total annex ordinary proof)) Validate) `catch` handleFailure (-1)

elements_hs_taproot_witness_policy :: Word32 -> Word64 -> Word32 -> Word64 -> Word64 -> IO Int32
elements_hs_taproot_witness_policy flags count leaf scriptSize input =
  evaluate (execute (Check (ScriptPolicy.TaprootWitnessPolicy flags count leaf scriptSize input)) Validate) `catch` handleFailure (-1)

elements_hs_context_presence :: Word32 -> Word32 -> IO Int32
elements_hs_context_presence count required =
  evaluate (execute (Check (Exchange.ContextPresence count required)) Validate) `catch` handleFailure (-1)

elements_hs_payment_uri :: Word32 -> Word32 -> IO Int32
elements_hs_payment_uri flags scheme =
  evaluate (execute (Check (Exchange.PaymentUri flags scheme)) Validate) `catch` handleFailure (-1)

elements_hs_address_alias :: Word32 -> Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> IO Int32
elements_hs_address_alias flags networkSize network prefixSize prefix
  | flags>3 || any (> fromIntegral (maxBound :: Int)) [networkSize,prefixSize] ||
      (networkSize/=0 && network==nullPtr) || (prefixSize/=0 && prefix==nullPtr) = pure (-1)
  | otherwise = (do
      n <- bytes network networkSize
      p <- bytes prefix prefixSize
      evaluate (execute (Check (Exchange.AddressAlias flags n p)) Validate)) `catch` handleFailure (-1)
  where bytes ptr size = if size==0 then pure B.empty else B.packCStringLen (castPtr ptr,fromIntegral size)

elements_hs_network_selection :: Word32 -> Word32 -> Word64 -> Ptr Word8 -> IO Int32
elements_hs_network_selection mode flags size input = run `catch` handleFailure (-1)
  where
    run | mode>3 || flags>1 || (mode/=2 && flags/=0) || size>fromIntegral (maxBound::Int) ||
          (size/=0 && input==nullPtr) = pure (-1)
        | otherwise = do
            bytes <- if size==0 then pure B.empty else B.packCStringLen (castPtr input,fromIntegral size)
            pure (execute (Check (Exchange.NetworkSelection mode flags bytes)) Validate)

elements_hs_runtime_activation :: Word32 -> Int32 -> Int32 -> Ptr Int32 -> IO Int32
elements_hs_runtime_activation present activation privateHeight output = run `catch` handleFailure (-1)
  where
    run | present > 1 || output == nullPtr || (present == 0 && privateHeight /= 0) = pure (-1)
        | otherwise = do
            let (configured,first) = execute (Check (Exchange.RuntimeActivation activation
                  (if present == 0 then Nothing else Just privateHeight))) Validate
            poke output first
            pure (if configured then 1 else 0)

elements_hs_bounded_wait :: Int64 -> Int64 -> IO Int64
elements_hs_bounded_wait value maximumWait =
  evaluate (execute (Check (Bmm.BoundedWait value maximumWait)) Validate) `catch` handleFailure (-1)

elements_hs_bounded_append :: Word64 -> Word64 -> Int64 -> IO Int64
elements_hs_bounded_append limit used count =
  evaluate (execute (Check (Bmm.BoundedAppend limit used count)) Validate) `catch` handleFailure (-1)

elements_hs_approving_parent_height :: Int64 -> IO Int64
elements_hs_approving_parent_height height =
  evaluate (execute (Check (Bmm.ApprovingParentHeight height)) Validate) `catch` handleFailure (-2)

elements_hs_child_behind :: Int64 -> Int64 -> IO Int32
elements_hs_child_behind child parent = guardResult (-1)
  (if execute (Check (Bmm.ChildBehind child parent)) Validate then 1 else 0)

elements_hs_unsigned32_fields :: Word64 -> Ptr Word64 -> IO Int32
elements_hs_unsigned32_fields count input = run `catch` handleFailure (-1)
  where
    run | count > fromIntegral (maxBound :: Int) `div` 8 || (count /= 0 && input == nullPtr) = pure (-1)
        | otherwise = do
            fields <- peekArray (fromIntegral count) input
            evaluate (if execute (Check (Exchange.Unsigned32Fields fields)) Validate then 1 else 0)

elements_hs_export_range :: Word32 -> Int32 -> Int32 -> Int32 -> Int32 -> Ptr Int32 -> IO Int32
elements_hs_export_range mode start count activation tip output = run `catch` handleFailure (-1)
  where
    run | mode > 3 || output == nullPtr || (mode >= 2 && activation /= 0) ||
          (mode == 3 && (start /= 0 || count /= 0)) = pure (-1)
        | otherwise = case execute (Check (if mode == 3 then Exchange.PegEventStart tip
            else if mode == 2 then Exchange.PegEventRange start count tip
            else Exchange.ExportRange start count activation (if mode == 0 then Nothing else Just tip))) Validate of
            Left code -> pure code
            Right end -> poke output end >> pure 0

elements_hs_wide_decimal :: Word32 -> Ptr Word8 -> Word32 -> Ptr Word8 -> Word32 -> IO Int32
elements_hs_wide_decimal mode input size output capacity = run `catch` handleFailure (-1)
  where
    run | mode>1 || size/=16 || input==nullPtr || output==nullPtr = pure (-1)
        | otherwise = do
            bytes <- B.packCStringLen (castPtr input,16)
            case execute (Check (Exchange.WideDecimal (mode==1) bytes)) Validate of
              Nothing -> pure (-1)
              Just decimal -> writeReply decimal output capacity

elements_hs_evaluator_identity :: Word32 -> Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> IO Int32
elements_hs_evaluator_identity flags catalogueSize catalogue programSize program
  | flags > 3 = pure (-1)
  | catalogueSize /= 64 || programSize /= 64 = pure 0
  | catalogue == nullPtr || program == nullPtr = pure (-1)
  | otherwise = (do
      catalogueText <- B.packCStringLen (castPtr catalogue,64)
      programText <- B.packCStringLen (castPtr program,64)
      evaluate (execute (Check (Exchange.EvaluatorIdentity flags catalogueText programText)) Validate))
        `catch` handleFailure (-1)

elements_hs_configuration_field :: Word32 -> Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> IO Int32
elements_hs_configuration_field mode size input capacity output = run `catch` handleFailure (-1)
  where
    run | mode>9 || size>fromIntegral (maxBound::Int) || output==nullPtr || (size/=0 && input==nullPtr) = pure (-1)
        | mode==9 && (size<52 || size>65526) = pure (-2)
        | (mode==7 && size/=75) || (mode==8 && size>1024) = pure (-2)
        | mode==6 && size/=650 = pure (-2)
        | mode==5 && size>131072 = pure (-2)
        | otherwise = do
            bytes <- if size==0 then pure B.empty else B.packCStringLen (castPtr input,fromIntegral size)
            case execute (Check (Exchange.ConfigurationField mode bytes)) Validate of
              Left code -> pure (fromIntegral (-1-code))
              Right encoded | fromIntegral (B.length encoded)<=capacity -> do
                B.useAsCString encoded (\ptr -> copyBytes output (castPtr ptr) (B.length encoded))
                pure (fromIntegral (B.length encoded))
              _ -> pure (-1)

elements_hs_exchange_inbox_entry :: Word32 -> Ptr Word64 -> Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> IO Int32
elements_hs_exchange_inbox_entry mode fields size input capacity output = run `catch` handleFailure (-1)
  where
    shape = case mode of
      0 -> size >= 96 && size <= fromIntegral (maxBound :: Int) - 30 && capacity == size + 30
      1 -> size == 160 && capacity == 193
      2 -> size == 64 && capacity == 72
      3 -> size == 80 && capacity == 80
      4 -> size == 659 && capacity == 700
      5 -> size == 675 && capacity == 708
      6 -> size == 503 && capacity == 236
      7 -> size == 507 && capacity == 503
      8 -> size == 507 && capacity == 503
      9 -> size == 128 && capacity == 132
      10 -> size > 64 && size <= min 4294967359 (fromIntegral (maxBound :: Int)-12) && capacity == size+12
      11 -> size == 320 && capacity == 325
      12 -> size == 64 && capacity == 48
      13 -> size == 128 && capacity == 130
      14 -> size == 192 && capacity == 204
      15 -> size == 192 && capacity == 213
      16 -> size >= 11 && size <= 258 && capacity == size-3
      17 -> size == 75 && capacity == 73
      18 -> size <= 22 && capacity == 17
      _ -> False
    run | not shape ||
          fields == nullPtr || input == nullPtr || output == nullPtr = pure (-1)
        | otherwise = do
            values <- peekArray (if mode >= 4 then 7 else 5) fields
            bytes <- B.packCStringLen (castPtr input, fromIntegral size)
            if mode == 12 then publishBytes 48 output (execute (Check (Exchange.SourcePredecessor values bytes)) Validate)
            else do
             let value = if mode == 18 then Exchange.CursorPayload bytes
                        else if mode >= 16 then Exchange.LegacyMarkerFrame (mode == 16) bytes
                        else if mode == 15 then Exchange.DeploymentEncoding values bytes
                        else if mode >= 13 then Exchange.StagingEncoding (mode == 14) (head values) (values !! 1) bytes
                        else if mode == 11 then Exchange.RegistryEncoding bytes
                        else if mode >= 9 then Exchange.SourceAuthorization (mode == 10) (head values) bytes
                        else if mode >= 7 then Exchange.MarkerFrame (mode == 8) bytes
                        else if mode == 6 then Exchange.MarkerContext bytes
                        else if mode >= 4 then Exchange.BondEntry (mode == 5) values bytes
                        else if mode >= 2 then Exchange.InboxStep (mode == 3) (head values) bytes
                        else Exchange.InboxEntry (mode == 1) values bytes
             case execute (Check value) Validate of
              Just encoded | B.length encoded == fromIntegral capacity ->
                B.useAsCString encoded (\ptr -> copyBytes output (castPtr ptr) (fromIntegral capacity)) >> pure 0
              _ -> pure (-1)

elements_hs_exchange_bond_marker :: Word64 -> Word64 -> Ptr Word8 -> Ptr Word8 -> IO Int32
elements_hs_exchange_bond_marker limit size payload identities = run `catch` handleFailure (-1)
  where
    run | size /= 503 || payload == nullPtr || identities == nullPtr = pure (-1)
        | otherwise = do
            bytes <- B.packCStringLen (castPtr payload,503)
            expected <- B.packCStringLen (castPtr identities,128)
            evaluate (fromIntegral (execute (Check (Exchange.BondMarker limit bytes expected)) Validate))

foreign import ccall "dynamic" callReadSpendCount :: FunPtr ReadSpendCount -> ReadSpendCount
elements_hs_exchange_spend_scan :: Word32 -> Word64 -> Word64 -> FunPtr ReadSpendCount -> Ptr () -> Ptr Word64 -> IO Int32
elements_hs_exchange_spend_scan mode start end reader context output = run `catch` handleFailure (-1)
  where
    run | mode > 2 || start > end || reader == nullFunPtr || output == nullPtr = pure (-1)
        | otherwise = do
            result <- if mode==2
              then execute (Check (Exchange.DeploymentOutputs start end (callReadSpendCount reader context))) Validate
              else execute (Check (Exchange.SpendScan (mode == 1) start end (callReadSpendCount reader context))) Validate
            case result of
              Left code -> pure (fromIntegral code)
              Right Nothing -> pure 0
              Right (Just index) -> poke output index >> pure 1

elements_hs_exchange_registry_decode :: Word64 -> Ptr Word8 -> Ptr Word8 -> Ptr Word64 -> IO Int32
elements_hs_exchange_registry_decode size input output count = run `catch` handleFailure (-1)
  where
    run | size /= 325 || input == nullPtr || output == nullPtr || count == nullPtr = pure (-1)
        | otherwise = do
            bytes <- B.packCStringLen (castPtr input,325)
            let (code,decoded) = execute (Check (Exchange.RegistryDecoding bytes)) Validate
            B.useAsCString decoded (\ptr -> copyBytes output (castPtr ptr) (B.length decoded))
            poke count (fromIntegral (B.length decoded `div` 64))
            pure (fromIntegral code)

elements_hs_exchange_registry :: Ptr Word8 -> Ptr Word8 -> IO Int32
elements_hs_exchange_registry encryption attestation = run `catch` handleFailure (-1)
  where
    run | encryption == nullPtr || attestation == nullPtr = pure (-1)
        | otherwise = do
            a <- B.packCStringLen (castPtr encryption,160)
            b <- B.packCStringLen (castPtr attestation,160)
            let chunks bytes = [B.take 32 (B.drop offset bytes) | offset <- [0,32..128]]
            guardResult (-1) (fromIntegral (execute (Check (Exchange.CustodianRegistry (zip (chunks a) (chunks b)))) Validate))

elements_hs_exchange_distinct :: Word32 -> Ptr Word8 -> IO Int32
elements_hs_exchange_distinct = elements_hs_exchange_identity_relation 0

elements_hs_exchange_identity_relation :: Word32 -> Word32 -> Ptr Word8 -> IO Int32
elements_hs_exchange_identity_relation mode count input = run `catch` handleFailure (-1)
  where
    run | mode > 12 || count > 45 || (mode==12 && count/=16) || (mode==11 && count/=40) || (mode==4 && count/=3) || (mode `elem` [5,6,9,10] && count/=22) ||
          (mode `elem` [7,8] && count/=15) || (count /= 0 && input == nullPtr) = pure (-1)
        | otherwise = do
            bytes <- if count == 0 then pure B.empty else B.packCStringLen (castPtr input,fromIntegral count*32)
            let identities = [B.take 32 (B.drop offset bytes) | offset <- [0,32 .. B.length bytes-1]]
                rule = case mode of 0 -> Exchange.IdentitySet; 1 -> Exchange.AbsentIdentities; _ -> Exchange.IsolatedIdentity
            guardResult (-1) (case mode of
              3 -> fromIntegral (execute (Check (Exchange.ProofIdentities identities)) Validate)
              4 -> fromIntegral (execute (Check (Exchange.BlinderIdentities identities)) Validate)
              11 -> fromIntegral (execute (Check (Exchange.ActivationFacts identities)) Validate)
              12 -> if execute (Check (Exchange.RuntimeIdentities identities)) Validate then 0 else 1
              kind | kind>=9 -> fromIntegral (execute (Check (Exchange.FrozenIdentityGroups (kind==10) identities)) Validate)
              kind | kind>=7 -> if execute (Check (Exchange.CarryIdentities (kind==8) identities)) Validate then 0 else 1
              kind | kind>=5 -> fromIntegral (execute (Check (Exchange.DeploymentIdentities (kind==6) identities)) Validate)
              _ -> if execute (Check (rule identities)) Validate then 0 else 1)

elements_hs_exchange_frozen_profile :: Word32 -> Word32 -> Word64 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO Int32
elements_hs_exchange_frozen_profile mode confirmations size input truth output = run `catch` handleFailure (-1)
  where
    run | mode>10 || size /= (case mode of 0 -> 221; 1 -> 390; 4 -> 178; 5 -> 71; 6 -> 85; 7 -> 100; 8 -> 260; 9 -> 485; 10 -> 1977; _ -> 73) || input==nullPtr ||
          (mode `elem` [6,8,10] && confirmations>1) ||
          (mode `elem` [0,3,4,5,9] && truth==nullPtr) || output==nullPtr = pure (-1)
        | mode==8 = do
            bytes <- B.packCStringLen (castPtr input,260)
            guardResult (-1) (fromIntegral (execute (Check (Exchange.FrozenTail (confirmations==1) bytes)) Validate))
        | mode==10 = do
            bytes <- B.packCStringLen (castPtr input,1977)
            guardResult (-1) (fromIntegral (execute (Check (Exchange.ConfigurationIdentities (confirmations==1) bytes)) Validate))
        | otherwise = do
            bytes <- B.packCStringLen (castPtr input,fromIntegral size)
            encoded <- case mode of
              0 -> do
                hashes <- B.packCStringLen (castPtr truth,128)
                pure $ (\(ecx,usdd) -> wordBE 8 ecx <> wordBE 8 usdd) <$>
                  execute (Check (Exchange.HybridOracleProfile confirmations hashes bytes)) Validate
              1 -> pure (execute (Check (Exchange.TruthcoinProfile bytes)) Validate)
              6 -> pure (execute (Check (Exchange.MatcherProfile (confirmations==1) bytes)) Validate)
              7 -> pure (execute (Check (Exchange.AccumulatorProfile bytes)) Validate)
              9 -> do
                codec <- B.packCStringLen (castPtr truth,32)
                pure (execute (Check (Exchange.BondProfile codec bytes)) Validate)
              kind | kind>=4 -> do
                expected <- B.packCStringLen (castPtr truth,if kind==4 then 16 else 32)
                pure (execute (Check (Exchange.IdentityProfile (kind==5) expected bytes)) Validate)
              _ -> do
                policy <- if mode==3 then B.packCStringLen (castPtr truth,32) else pure B.empty
                pure (execute (Check (Exchange.CheckpointProfile (mode==3) policy bytes)) Validate)
            case encoded of
              Nothing -> pure 1
              Just value -> B.useAsCString value (\ptr -> copyBytes output (castPtr ptr) (B.length value)) >> pure 0

elements_hs_exchange_frozen_bounds :: Word32 -> Ptr Word64 -> IO Int32
elements_hs_exchange_frozen_bounds count input = run `catch` handleFailure (-1)
  where
    run | count `notElem` [1,2,3,5,9,16,17] || input == nullPtr = pure (-1)
        | otherwise = do
            fields <- peekArray (fromIntegral count) input
            let accepted = if count == 17 then execute (Check (Exchange.HybridOracleBounds fields)) Validate
                           else execute (Check (Exchange.FrozenBounds fields)) Validate
            guardResult (-1) (if accepted then 0 else 1)

elements_hs_exchange_capital_identity :: Word32 -> Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> IO Int32
elements_hs_exchange_capital_identity profile program size values count expected =
  elements_hs_exchange_capital profile program size values count expected 0 nullPtr

elements_hs_exchange_capital :: Word32 -> Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> IO Int32
elements_hs_exchange_capital profile program size values count expected capacity output = run `catch` handleFailure (-1)
  where
    identitySize=case profile of 0 -> 160; 1 -> 224; _ -> 240
    run | profile > 2 || size /= (case profile of 0 -> 850; 1 -> 1627; _ -> 364) ||
          capacity `notElem` [0,914] || (capacity/=0 && (profile==2 || output==nullPtr)) ||
          count /= identitySize+(if capacity==0 then 0 else 96) || any (== nullPtr) [program,values,expected] = pure (-1)
        | otherwise = do
            p <- B.packCStringLen (castPtr program,32)
            v <- B.packCStringLen (castPtr values,fromIntegral size)
            e <- B.packCStringLen (castPtr expected,fromIntegral count)
            let identity=Exchange.CapitalIdentity profile p v (B.take (fromIntegral identitySize) e)
                context=if capacity==0 then Nothing else Just (B.drop (fromIntegral identitySize) e)
            case execute (Exchange.CapitalRequest identity context) Exchange.bindAndProject of
              Left code -> pure (fromIntegral code)
              Right encoded | B.length encoded/=fromIntegral capacity -> pure (-1)
                            | capacity==0 -> pure 0
                            | otherwise -> B.useAsCString encoded (\ptr -> copyBytes output (castPtr ptr) 914) >> pure 0

elements_hs_exchange_successor_binding :: Word32 -> Word64 -> Ptr Word8 -> Ptr Word8 -> Ptr Word64 -> IO Int32
elements_hs_exchange_successor_binding profile size values hashes context = run `catch` handleFailure (-1)
  where
    run | profile>1 || size/=(if profile==1 then 1627 else 850) ||
          values==nullPtr || hashes==nullPtr || context==nullPtr = pure (-1)
        | otherwise = do
            v <- B.packCStringLen (castPtr values,fromIntegral size)
            h <- B.packCStringLen (castPtr hashes,128)
            c <- peekArray 3 context
            guardResult (-1) . fromIntegral $ execute (Check (Exchange.SuccessorBinding (profile==1) v h c)) Validate

elements_hs_exchange_envelope_payload :: Word32 -> Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> IO Int32
elements_hs_exchange_envelope_payload height checkpoint size input capacity output = run `catch` handleFailure (-1)
  where
    run | size == 0 || size > 100000 = pure 1
        | capacity /= size+45 || any (== nullPtr) [checkpoint,input,output] = pure (-1)
        | otherwise = do
            hash <- B.packCStringLen (castPtr checkpoint,32)
            body <- B.packCStringLen (castPtr input,fromIntegral size)
            case execute (Check (Exchange.EnvelopePayload height hash body)) Validate of
              Nothing -> pure (-1)
              Just encoded -> B.useAsCString encoded (\ptr -> copyBytes output (castPtr ptr) (B.length encoded)) >> pure 0

elements_hs_exchange_envelope_header :: Word64 -> Word8 -> Word32 -> IO Int32
elements_hs_exchange_envelope_header size version bodySize = guardResult (-1) $
  fromIntegral (execute (Check (Exchange.EnvelopeHeader size version bodySize)) Validate)

elements_hs_exchange_envelope_requirement :: Word32 -> IO Int32
elements_hs_exchange_envelope_requirement flags
  | flags > 15 = pure (-1)
  | otherwise = guardResult (-1) $ either fromIntegral (\required -> if required then 4 else 0) $
      execute (Check (Exchange.EnvelopeRequirement (testBit flags 0) (testBit flags 1)
        (testBit flags 2) (testBit flags 3))) Validate

elements_hs_exchange_m6 :: Word64 -> Ptr Word8 -> Ptr Word8 -> IO Int32
elements_hs_exchange_m6 size input output = run `catch` handleFailure (-1)
  where
    run | size > 100000 || output == nullPtr || (size /= 0 && input == nullPtr) = pure (-1)
        | otherwise = do
            bytes <- if size == 0 then pure B.empty else B.packCStringLen (castPtr input, fromIntegral size)
            publishBytes 64 output (execute (Check (Exchange.M6Preimage bytes)) Validate)

elements_hs_exchange_source_marker :: Word32 -> Word32 -> Word32 -> Ptr Word32 -> IO Int32
elements_hs_exchange_source_marker seen kind present output = run `catch` handleFailure (-1)
  where
    run | present > 1 || output == nullPtr = pure (-1)
        | otherwise = publishResult (\value -> evaluate value >>= poke output)
            (execute (Check (Exchange.SourceMarker seen kind (present == 1))) Validate)

type ReadExchangeWord = Ptr () -> Word32 -> IO Word64
foreign import ccall "dynamic" readExchangeWord :: FunPtr ReadExchangeWord -> ReadExchangeWord
elements_hs_exchange_parent_target :: Word32 -> Word64 -> FunPtr ReadExchangeWord -> Ptr () -> Ptr Word64 -> IO Int32
elements_hs_exchange_parent_target present height reader context output = run `catch` handleFailure (-1)
  where
    run | present > 1 || output == nullPtr || (present == 0 && reader == nullFunPtr) = pure (-1)
        | otherwise = do
            result <- execute (Check (Exchange.ParentTarget
              (if present == 1 then Just height else Nothing) (readExchangeWord reader context))) Validate
            publishResult (\value -> evaluate value >>= poke output) result

elements_hs_exchange_header :: Word32 -> FunPtr Deposit.ReadCtipOpcode -> Ptr () -> IO Int32
elements_hs_exchange_header = exchangeAdmission 2 Exchange.HeaderPhase

elements_hs_exchange_connection :: Word32 -> FunPtr Deposit.ReadCtipOpcode -> Ptr () -> IO Int32
elements_hs_exchange_connection = exchangeAdmission 1 (Exchange.Connection . (== 1))

elements_hs_exchange_disconnect :: Word32 -> FunPtr Deposit.ReadCtipOpcode -> Ptr () -> IO Int32
elements_hs_exchange_disconnect = exchangeAdmission 3 Exchange.DisconnectPhase

elements_hs_exchange_availability :: Word32 -> FunPtr Deposit.ReadCtipOpcode -> Ptr () -> IO Int32
elements_hs_exchange_availability = exchangeAdmission 3 Exchange.Availability

elements_hs_exchange_configuration :: FunPtr Deposit.ReadCtipOpcode -> Ptr () -> IO Int32
elements_hs_exchange_configuration = exchangeAdmission 0 (const Exchange.Configuration) 0

elements_hs_production_identity :: FunPtr Deposit.ReadCtipOpcode -> Ptr () -> IO Int32
elements_hs_production_identity = exchangeAdmission 0 (const Exchange.ProductionIdentity) 0

elements_hs_pegin_confirmation_policy :: Word32 -> Int64 -> Word32 -> FunPtr PolicyEffect -> Ptr () -> IO Int64
elements_hs_pegin_confirmation_policy mode height configured = callbackCall runPolicyEffect (\readFact ->
  execute (Check (Deposit.ConfirmationPolicy mode height configured readFact)) Validate)

elements_hs_exchange_checkpoint :: FunPtr Deposit.ReadCtipOpcode -> Ptr () -> IO Int32
elements_hs_exchange_checkpoint = exchangeAdmission 0 (const Exchange.Checkpoint) 0

-- Tracker reads reenter Haskell; use the safe policy callback transport.
elements_hs_exchange_snapshot :: FunPtr PolicyEffect -> Ptr () -> IO Int32
elements_hs_exchange_snapshot = policyCall (\action -> fromIntegral <$>
  execute (Check (Exchange.SnapshotContext (\step -> (== 1) <$> action (fromIntegral step)))) Validate)

elements_hs_exchange_envelope_scan :: FunPtr PolicyEffect -> Ptr () -> IO Int32
elements_hs_exchange_envelope_scan = policyCall (\action -> execute (Check (Exchange.EnvelopeScan action)) Validate)

elements_hs_exchange_genesis_initialization :: Word32 -> FunPtr Deposit.ReadCtipOpcode -> Ptr () -> IO Int32
elements_hs_exchange_genesis_initialization = exchangeAdmission maxBound Exchange.GenesisInitialization

elements_hs_exchange_deployment :: Word32 -> FunPtr Deposit.ReadCtipOpcode -> Ptr () -> IO Int32
elements_hs_exchange_deployment = exchangeAdmission maxBound Exchange.Deployment

elements_hs_exchange_required_identities :: Word32 -> FunPtr Deposit.ReadCtipOpcode -> Ptr () -> IO Int32
elements_hs_exchange_required_identities = exchangeAdmission 3 Exchange.RequiredIdentities

elements_hs_exchange_physical_inputs :: Word32 -> FunPtr Deposit.ReadCtipOpcode -> Ptr () -> IO Int32
elements_hs_exchange_physical_inputs = exchangeAdmission 1 (Exchange.PhysicalInputs . (==1))

elements_hs_exchange_transaction_shape :: Word32 -> FunPtr Deposit.ReadCtipOpcode -> Ptr () -> IO Int32
elements_hs_exchange_transaction_shape =
  exchangeAdmission (fromIntegral (length Exchange.transactionShapePhases-1)) Exchange.TransactionShape

elements_hs_exchange_tracker :: Word32 -> FunPtr Deposit.ReadCtipOpcode -> Ptr () -> IO Int32
elements_hs_exchange_tracker = exchangeAdmission 2 Exchange.TrackerPhase

elements_hs_exchange_tranche :: Word64 -> Ptr Word8 -> Ptr Word32 -> IO Int32
elements_hs_exchange_tranche count input output = run `catch` handleFailure (-1)
  where
    run | output == nullPtr || (count /= 0 && input == nullPtr) || count > fromIntegral (maxBound :: Int) = pure (-1)
        | otherwise = do
            (code,work) <- execute (Check (Exchange.Tranche count (peekElemOff input . fromIntegral))) Validate
            evaluate work >>= poke output
            pure (fromIntegral code)

elements_hs_exchange_profile :: Word32 -> FunPtr Deposit.ReadCtipOpcode -> Ptr () -> IO Int32
elements_hs_exchange_profile = exchangeAdmission 1 (Exchange.OutputProfile . (== 1))

elements_hs_exchange_forced_body :: Word32 -> Word64 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO Int32
elements_hs_exchange_forced_body kind size body chain market = run `catch` handleFailure (-1)
  where
    run | kind > 2 || size /= [201,208,193] !! fromIntegral kind = pure 1
        | body == nullPtr || chain == nullPtr || market == nullPtr = pure (-1)
        | otherwise = do
            b <- B.packCStringLen (castPtr body, fromIntegral size)
            c <- B.packCStringLen (castPtr chain, 32)
            m <- B.packCStringLen (castPtr market, 16)
            guardResult (-1) $ fromIntegral $ execute (Check (Exchange.ForcedBody (fromIntegral kind) b c m)) Validate

elements_hs_exchange_authority :: Word32 -> FunPtr Deposit.ReadCtipOpcode -> Ptr () -> IO Int32
elements_hs_exchange_authority = exchangeAdmission 1 (Exchange.Authority . (== 1))

exchangeAdmission :: Word32 -> (Word32 -> (Int -> IO Bool) -> Exchange.Admission)
  -> Word32 -> FunPtr Deposit.ReadCtipOpcode -> Ptr () -> IO Int32
exchangeAdmission maximumMode constructor mode reader context
  | mode > maximumMode || reader == nullFunPtr = pure (-1)
  | otherwise = (fromIntegral <$> execute (Check (constructor mode
      (\step -> (== 1) <$> callReentrantPredicate reader context (fromIntegral step)))) Validate)
      `catch` handleFailure (-1)

elements_hs_exchange_cursors :: Word32 -> Ptr Word64 -> Ptr Word64 -> IO Int32
elements_hs_exchange_cursors flags input output = run `catch` handleFailure (-1)
  where
    run | flags > 15 || input == nullPtr || output == nullPtr = pure (-1)
        | otherwise = do
            previousForced <- peekElemOff input 0
            previousDeposit <- peekElemOff input 1
            forced <- peekElemOff input 2
            deposit <- peekElemOff input 3
            result <- evaluate $ execute (Check (Exchange.Cursors
              (testBit flags 0) (testBit flags 1) (testBit flags 2) (testBit flags 3)
              previousForced previousDeposit forced deposit)) Validate
            case result of
              Left code -> pure (fromIntegral code)
              Right (f,d) -> evaluate f >> evaluate d >> pokeArray output [f,d] >> pure 0

-- Fields: prior counts/cursors, next counts/cursors, appends, oldest, height.
elements_hs_exchange_inbox :: Word32 -> Word32 -> Ptr Word64 -> Ptr Word64 -> IO Int32
elements_hs_exchange_inbox mode count input output = run `catch` handleFailure (-1)
  where
    run | input == nullPtr || output == nullPtr ||
          not ((mode == 0 && count == 4) || (mode == 1 && count == 12) || (mode == 2 && count == 6) || (mode == 3 && count == 11) || (mode == 4 && count == 3) || (mode == 5 && count == 4)) = pure (-1)
        | mode == 5 = do
            [f,fc,d,dc] <- peekArray 4 input
            case Exchange.pending (Exchange.Backlog f fc d dc) of
              Nothing -> pure 1
              Just (forced,deposits) -> do
                _ <- evaluate forced >> evaluate deposits
                pokeArray output [forced,deposits]
                pure 0
        | mode == 3 = do
            fields <- peekArray 11 input
            let (code,result) = execute (Check (Exchange.MarkerBounds fields)) Validate
            if code < 0 then pure (-1) else pokeArray output result >> pure (fromIntegral code)
        | mode == 2 = do
            [w,t,aw,at,mw,mt] <- peekArray 6 input
            let (code,totals) = execute (Check (Exchange.SourceBytes w t aw at mw mt)) Validate
            mapM_ evaluate totals
            pokeArray output totals
            pure (fromIntegral code)
        | otherwise = do
            fields <- peekArray (fromIntegral count) input
            let rule = case fields of
                  [active,f,d] | active<=1 -> Exchange.ActivationCounts (active==1) f d
                  [f,fc,d,dc] -> Exchange.AppendBudget (Exchange.Backlog f fc d dc)
                  [f,fc,d,dc,nf,nfc,nd,ndc,fa,da,old,height] ->
                    Exchange.Liveness (Exchange.Backlog f fc d dc) (Exchange.Backlog nf nfc nd ndc) fa da old height
                  _ -> error "invalid exchange projection"
            (err,value) <- evaluate $ execute (Check rule) Validate
            code <- evaluate $ maybe 0 ((+1) . fromIntegral . fromEnum) err
            wordsOut <- case value of
              Nothing -> pure [0,0]
              Just n -> evaluate n >> pure [1,n]
            pokeArray output wordsOut
            pure code

-- Caller provides two fields and count vote cells; count bounds every write.
elements_hs_parent_message :: Word32 -> Ptr Word8 -> Ptr Word32 -> Ptr Word16 -> IO Int32
elements_hs_parent_message count input fields output = run `catch` handleFailure (-1)
  where
    run | count > 0x7fffffff || (count /= 0 && input == nullPtr) || fields == nullPtr || output == nullPtr = pure (-1)
        | otherwise = do
            bytes <- peekArray (fromIntegral count) input
            (kind,encoding,votes) <- evaluate $ execute (Check (ParentReplay.Message bytes)) Validate
            mapM_ evaluate votes
            mapM_ evaluate [kind,encoding]
            pokeArray fields [kind,encoding]
            pokeArray output votes
            pure (fromIntegral (length votes))

elements_hs_parent_replay_record :: Word32 -> Word32 -> Int64 -> Word64 -> Word64 -> IO Int32
elements_hs_parent_replay_record kind flags value first second = guardResult (-1) $
  execute (Check (ParentReplay.Record kind flags value first second)) Validate

elements_hs_parent_replay_tip :: Word32 -> Word32 -> IO Int32
elements_hs_parent_replay_tip phase result = guardResult (-2) $
  execute (Check (ParentReplay.TipFlow phase result)) Validate

elements_hs_wallet_balance :: Int64 -> Int64 -> Int64 -> IO Int64
elements_hs_wallet_balance trusted pending immature = guardResult (-1) $
  execute (Check (Withdrawal.WalletBalance [trusted,pending,immature])) Validate

elements_hs_parent_replay_store_checked :: Word32 -> Word32 -> Word32 -> IO Int32
elements_hs_parent_replay_store_checked kind phase result
  | phase == maxBound = pure (if result==0 then ParentReplay.storeMaximum kind else -1)
  | otherwise = elements_hs_parent_replay_store kind phase result
elements_hs_parent_replay_store :: Word32 -> Word32 -> Word32 -> IO Int32
elements_hs_parent_replay_store kind phase result = guardResult (-1) $
  replayStoreRule (\rule -> execute (Check rule) Validate) kind phase result

elements_hs_parent_replay_run :: Word32 -> FunPtr MatchFact -> Ptr () -> IO Int32
elements_hs_parent_replay_run kind = callbackCall callMatchFact (\action ->
  execute (Check (CommandFlow (ParentReplay.storeMaximum kind) (replayStoreRule validate kind) action)) Validate)

elements_hs_private_file_admission :: FunPtr MatchFact -> Ptr () -> IO Int32
elements_hs_private_file_admission = callbackCall callMatchFact (\action ->
  execute (Check (Bmm.PrivateFileAdmission action)) Validate)

predicateCall :: Bool -> Word32 -> Int64 -> (Word32 -> Word32 -> Int64) -> FunPtr MatchFact -> Ptr () -> IO Int32
predicateCall acceptZero start maximumStep transition = callbackCall callMatchFact (\action ->
  execute (Check (PredicateFlow acceptZero start maximumStep transition action)) Validate)

elements_hs_parent_replay_tip_run :: FunPtr MatchFact -> Ptr () -> IO Int32
elements_hs_parent_replay_tip_run = predicateCall True 0 51 (\phase result -> fromIntegral (validate (ParentReplay.TipFlow phase result)))

elements_hs_deposit_run :: Word32 -> Word32 -> FunPtr MatchFact -> Ptr () -> IO Int32
elements_hs_deposit_run kind start callback context
  | kind /= 0 && start /= 0 = pure (-1)
  | otherwise = case kind of
      0 -> run True 82 (\phase result -> fromIntegral (validate (Deposit.DepositVerification phase result)))
      1 -> run False 17 (\phase result -> validate (Deposit.WithdrawalStatusFlow phase result))
      2 -> run False 34 (\phase result -> validate (Deposit.L1Normalization phase result))
      3 -> run False 27 (\phase result -> validate (Deposit.SidechainEvents phase result))
      4 -> run False 6 (\phase result -> validate (Deposit.L1Location phase result))
      _ -> pure (-1)
  where run acceptZero maximumStep transition = predicateCall acceptZero start maximumStep transition callback context

replayStoreRule :: (forall rule. (Typeable rule, Validation rule, ValidationResult rule ~ Int32) => rule -> Int32)
  -> Word32 -> Word32 -> Word32 -> Int32
replayStoreRule apply kind phase result =
  if kind == 129 then -1 -- Retired: inherited genesis connection stays native.
  else if kind == 130 then apply (Usdd.AccumulatorConnection phase result)
  else if kind == 131 then apply (Usdd.CheckpointConnection phase result)
  else if kind == 132 then apply (DestinationFlow phase result)
  else if kind == 133 then -1 -- Retired wallet bundle flow; preserve later ABI IDs.
  else if kind == 134 then apply (EventFlow phase result)
  else if kind == 135 then apply (SubmissionFlow phase result)
  else if kind == 136 then apply (OutputFlow phase result)
  else if kind == 137 then apply (Deposit.BroadcastFlow phase result)
  else if kind == 138 then apply (Deposit.SatoshiFlow phase result)
  else if kind == 139 then apply (Deposit.SponsorshipFlow phase result)
  else if kind == 140 then apply (Deposit.ImportFlow phase result)
  else if kind == 141 then apply (Deposit.NativeImportFlow phase result)
  else if kind == 142 then apply (Deposit.DefaultWalletFlow phase result)
  else if kind == 143 then apply (PreflightFlow phase result)
  else if kind == 144 then apply (Bmm.GrpcConfigFlow phase result)
  else if kind == 145 then apply (Bmm.GrpcRequestFlow phase result)
  else if kind == 146 then apply (Bmm.GrpcExecutableFlow phase result)
  else if kind == 147 then apply (Bmm.RpcServerFlow phase result)
  else if kind == 148 then apply (Bmm.CredentialFlow phase result)
  else if kind == 149 then apply (Exchange.SourceTransactionFlow phase result)
  else if kind == 150 then apply (Exchange.BlockSourcesFlow phase result)
  else if kind == 151 || kind == 152 then apply (Exchange.IssuanceFlow (kind==152) phase result)
  else if kind == 153 then apply (Exchange.PublicIssuanceFlow phase result)
  else if kind == 154 then apply (Exchange.ExplicitCreationsFlow phase result)
  else if kind == 155 then apply (Exchange.ActivationPredecessorFlow phase result)
  else if kind == 156 || kind == 157 then apply (Exchange.CapitalContextFlow (kind==157) phase result)
  else if kind >= 158 && kind <= 160 then apply (Exchange.HeaderFlow (kind-158) phase result)
  else if kind == 161 then apply (Exchange.SuccessorScanFlow phase result)
  else if kind == 162 then apply (Exchange.GenesisAdmissionFlow phase result)
  else if kind == 163 then apply (Exchange.CapitalProjectionFlow phase result)
  else if kind == 164 then apply (Exchange.FrozenAdmissionFlow phase result)
  else if kind == 165 then apply (Exchange.StartupDeploymentFlow phase result)
  else if kind == 166 then apply (Exchange.ConfigurationBindingFlow phase result)
  else if kind == 167 || kind == 168 then apply (Exchange.IdentityFileFlow (kind==168) phase result)
  else if kind == 169 then apply (Exchange.IdentityBindingFlow phase result)
  else if kind == 170 then apply (Exchange.IdentityAuditFlow phase result)
  else if kind == 171 || kind == 172 then apply (Exchange.IdentityHistoryFlow (kind==172) phase result)
  else if kind == 173 then apply (Exchange.IdentityCoinsFlow phase result)
  else if kind == 174 then apply (Exchange.IdentityWriteFlow phase result)
  else if kind == 175 then apply (Exchange.MaterialScanFlow phase result)
  else if kind == 176 then apply (Exchange.MaterialLocationsFlow phase result)
  else if kind == 177 then apply (JournalReadFlow phase result)
  else if kind == 178 || kind == 179 then apply (JournalPersistFlow (kind==179) phase result)
  else if kind == 180 then apply (RpcBurnFlow phase result)
  else if kind == 181 then apply (RpcClaimFlow phase result)
  else if kind == 182 then apply (RpcVerifyFlow phase result)
  else if kind == 184 || kind == 185 then apply (Bmm.ChildMonitorFlow (kind == 185) phase result)
  else if kind == 186 then apply (Bmm.ChildReapFlow phase result)
  else if kind == 187 then apply (Bmm.ChildDrainFlow phase result)
  else if kind == 188 then apply (Exchange.ConfigurationTransactions phase result)
  else if kind == 189 then apply (Exchange.ConfigurationCovenants phase result)
  else if kind == 190 then apply (Bmm.RecoveryPeerFlow phase result)
  else if kind == 191 then apply (Bmm.RecoveryBodyFlow phase result)
  else if kind == 192 || kind == 193 then apply (Bmm.RecoveryReplyFlow (kind==192) phase result)
  else if kind == 194 then apply (Bmm.RecoveryHeaderFlow phase result)
  else if kind == 195 then apply (Bmm.RecoveryPeerReplyFlow phase result)
  else if kind == 196 then apply (Bmm.CredentialFileFlow phase result)
  else if kind == 197 then apply (Bmm.GrpcRequestAdmission phase result)
  else if kind >= 198 && kind <= 200 then -1 -- Retired LWK dialog; reserve ABI IDs.
  else if kind == 201 then apply (Withdrawal.WalletIssueFlow False phase result)
  else if kind == 202 then apply (Withdrawal.WalletIssueFlow True phase result)
  else if kind == 203 then apply (Bmm.PeerBlockFlow phase result)
  else if kind == 204 then apply (Bmm.PeerTimerFlow phase result)
  else if kind == 205 then apply (Bmm.PeerHeadersFlow phase result)
  else if kind == 206 then apply (Bmm.PeerDispatchFlow phase result)
  else if kind == 207 then apply (ParentReplay.IndexDerivedFlow phase result)
  else if kind == 208 then apply (ParentReplay.IndexContinuityFlow phase result)
  else if kind == 209 then apply (ParentReplay.IndexCapitalFlow phase result)
  else if kind == 210 || kind == 211 then apply (Bmm.HeaderAdmissionFlow (kind==211) phase result)
  else if kind == 212 then apply (Exchange.ActivationPolicyFlow phase result)
  else if kind == 213 then apply (Bmm.TemplateParentFlow phase result)
  else if kind == 214 then apply (Bmm.TemplateAdmissionFlow phase result)
  else if kind == 215 then apply (Bmm.TemplateSelectionFlow phase result)
  else if kind == 216 || kind == 217 then apply (Bmm.TemplateCommitmentFlow (kind==217) phase result)
  else if kind == 218 then apply (Deposit.FeeFreeSelectionFlow phase result)
  else if kind == 228 then apply (Bmm.ChildPreflightFlow phase result)
  else if kind == 229 then apply (Bmm.ReverificationFlow phase result)
  else if kind == 230 then apply (Bmm.SyncPreflightFlow phase result)
  else if kind == 231 then apply (Bmm.SyncLoopFlow phase result)
  else if kind == 232 then apply (Bmm.BidParentFlow phase result)
  else if kind == 233 then apply (Withdrawal.WalletCommandFlow phase result)
  else if kind == 234 then apply (Bmm.MinedPreflightFlow phase result)
  else if kind == 235 then apply (ParentReplay.ConfiguredSlotFlow phase result)
  else if kind == 236 then apply (Bmm.CacheRoutingFlow phase result)
  else if kind == 237 || kind == 238 then apply (ParentReplay.RequiredFactsFlow (if kind==237 then 3 else 2) phase result)
  else if kind == 239 then apply (Bmm.ConfiguredBidFlow phase result)
  else if kind == 240 then apply (Bmm.ParsedBidFlow phase result)
  else if kind == 241 then apply (Bmm.FundedSubmissionFlow phase result)
  else if kind == 242 then apply (Bmm.CommitmentProbe phase result)
  else if kind == 243 then apply (Bmm.SuccessorProbe phase result)
  else if kind == 244 then apply (Bmm.TemplateCreationFlow phase result)
  else if kind == 245 then apply (Bmm.RewardWalletFlow phase result)
  else if kind == 246 then apply (Exchange.FrozenProfileFlow phase result)
  else if kind == 247 then apply (Exchange.CapitalDecodeFlow phase result)
  else if kind == 248 then apply (ParentReplay.RequiredFactsFlow 4 phase result)
  else if kind == 249 then apply (Exchange.ConnectionPreflightFlow phase result)
  else if kind == 250 then apply (Exchange.DisconnectPreflightFlow phase result)
  else if kind == 251 then apply (Exchange.SingletonRecoveryFlow phase result)
  else if kind == 252 || kind == 253 then apply (Exchange.HeaderLifecycleFlow (kind==253) phase result)
  else if kind == 254 then apply (Exchange.ExpectedContextFlow phase result)
  else if kind == 255 then apply (Exchange.IncrementalScanFlow phase result)
  else if kind == 256 then apply (ParentReplay.ParentRequestFlow phase result)
  else if kind == 257 then apply (Withdrawal.BundleEventFlow False phase result)
  else if kind == 258 then apply (Withdrawal.BundleEventFlow True phase result)
  else if kind == 259 then apply (Exchange.CapitalReportFlow phase result)
  else if kind == 260 then apply (Exchange.ParentReportFlow phase result)
  else if kind == 261 then apply (Exchange.ExportReconstructFlow phase result)
  else if kind == 262 then apply (Exchange.AuthenticatedHeightFlow phase result)
  else if kind == 263 then apply (ScriptPolicy.WitnessAnnexFlow phase result)
  else if kind == 264 || kind == 265 then apply (Bmm.PeerAdmissionFlow (kind==265) phase result)
  else if kind == 266 then apply (Exchange.ReservedInputsFlow phase result)
  else if kind == 267 then apply (ParentReplay.RequiredFactsFlow 7 phase result)
  else if kind == 268 then apply (Deposit.NativeAdmissionFlow phase result)
  else if kind == 269 then apply (Exchange.EvaluatorSourceFlow phase result)
  else if kind == 270 then apply (Withdrawal.NativeSubmissionFlow phase result)
  else if kind == 271 then apply (Exchange.BondContextFlow phase result)
  else if kind == 272 then apply (Exchange.ActivationAnchorFlow phase result)
  else if kind == 273 then apply (Bmm.CredentialRecordFlow phase result)
  else if kind == 274 then apply (Bmm.AnnexAccountingFlow phase result)
  else if kind == 275 then apply (Bmm.PeerBlockDispatchFlow phase result)
  else if kind == 276 then apply (Exchange.CapitalConnectionFlow phase result)
  else if kind == 277 then apply (Deposit.MempoolWitnessFlow phase result)
  else if kind == 278 then -1 -- Retired: inherited witness checks remain native.
  else if kind == 279 then apply (Bmm.CanonicalMatchFlow phase result)
  else if kind == 280 then apply (ParentReplay.ExplicitVoteFlow phase result)
  else if kind == 281 then apply (Exchange.ParentContextFlow phase result)
  else if kind == 282 then apply (Deposit.BlockPreflightFlow phase result)
  else if kind == 283 then apply (ParentReplay.BranchReplayFlow phase result)
  else if kind == 284 then apply (ParentReplay.RecoveryAncestorFlow phase result)
  else if kind == 285 then apply (ParentReplay.RecoveryAdmissionFlow phase result)
  else if kind == 286 then apply (ParentReplay.EphemeralHeaderFlow phase result)
  else if kind == 287 then apply (ParentReplay.ConnectionAnchorFlow phase result)
  else if kind == 288 then apply (ParentReplay.ConnectionStateFlow phase result)
  else if kind == 289 then apply (Exchange.LegacyMarkerFlow phase result)
  else if kind == 290 then apply (Exchange.MarkerAuthenticationFlow phase result)
  else if kind == 291 then apply (ParentReplay.StartupParentFlow ParentReplay.ParentServe phase result)
  else if kind == 292 then apply (Exchange.ExportInitialize phase result)
  else if kind == 293 then apply (Exchange.ExportRecheck phase result)
  else if kind == 294 then apply (ParentReplay.RequiredPairFlow phase result)
  else if kind == 295 then apply (Usdd.RpcProofFlow phase result)
  else if kind == 296 then apply (Bmm.ConnectionContextFlow phase result)
  else if kind == 297 then apply (Bmm.SnapshotPrepareFlow phase result)
  else if kind == 298 then apply (Bmm.AnchorCacheFlow phase result)
  else if kind == 299 then apply (Bmm.AnchorPublishFlow phase result)
  else if kind == 300 then apply (Bmm.AnchorDisconnectFlow phase result)
  else if kind == 301 then apply (Bmm.CandidateAdmissionFlow phase result)
  else if kind == 302 then apply (Bmm.SnapshotBacklogFlow phase result)
  else if kind == 303 then apply (Bmm.AnchorReplacementFlow phase result)
  else if kind == 304 then apply (Bmm.ReconciliationGate phase result)
  else if kind == 305 then apply (Bmm.AnchorOrder phase result)
  else if kind == 306 then apply (Bmm.AnchorCollect phase result)
  else if kind == 307 then apply (Bmm.ProductionRoutingFlow phase result)
  else if kind == 308 then apply (Bmm.BlockPreparationFlow phase result)
  else if kind == 309 then apply (Bmm.BlockAcceptanceFlow phase result)
  else if kind == 310 then apply (ParentReplay.MempoolSweepPreflight phase result)
  else if kind == 311 then apply (ParentReplay.ParentRpcHostFlow phase result)
  else if kind == 312 then apply (Bmm.FullBlockPreflight phase result)
  else if kind == 313 then apply (Bmm.BlockAnchorAdmission phase result)
  else if kind == 314 then apply (Bmm.BlockAnchorPublication phase result)
  else if kind == 315 || kind == 316 then apply (ParentReplay.StartupParentFlow
    (if kind == 315 then ParentReplay.ParentLoad else ParentReplay.ParentVerify) phase result)
  else if kind == 317 then apply (ParentReplay.StartupBundleFlow phase result)
  else if kind >= 318 && kind <= 320 then apply (ParentReplay.BlockValidationFlow
    (case kind of 318 -> ParentReplay.ContextualHeader; 319 -> ParentReplay.ContextualOutputs; _ -> ParentReplay.CandidateSelfCheck) phase result)
  else if kind >= 321 && kind <= 323 then apply (ParentReplay.BlockValidationFlow
    (case kind of 321 -> ParentReplay.BranchChoice; 322 -> ParentReplay.StartupReconcile; _ -> ParentReplay.ExchangeParent) phase result)
  else if kind == 324 || kind == 325 then apply (ParentReplay.BlockValidationFlow
    (if kind == 324 then ParentReplay.FinalBmm else ParentReplay.BmmFailure) phase result)
  else if kind == 326 then apply (Exchange.BondTreeFlow phase result)
  else apply (ParentReplay.StoreFlow kind phase result)

elements_hs_bmm_identity :: Ptr Word32 -> Ptr Word8 -> IO Int32
elements_hs_bmm_identity fields payload = run `catch` handleFailure (-1)
  where
    run | fields == nullPtr || payload == nullPtr = pure (-1)
        | otherwise = do
            (numbers,bytes) <- evaluate $ execute (Check Bmm.FixedIdentity) Validate
            mapM_ evaluate numbers
            mapM_ evaluate bytes
            pokeArray fields numbers
            pokeArray payload bytes
            pure 0

elements_hs_bmm_checkpoint :: Word32 -> Ptr Word32 -> Ptr Word8 -> IO Int32
elements_hs_bmm_checkpoint mode fields blockHash = run `catch` handleFailure (-1)
  where
    run | fields == nullPtr || blockHash == nullPtr = pure (-1)
        | otherwise = do
            (numbers,bytes) <- evaluate $ execute (Check (Bmm.CheckpointPreset mode)) Validate
            mapM_ evaluate numbers
            mapM_ evaluate bytes
            pokeArray fields numbers
            pokeArray blockHash bytes
            pure 0

elements_hs_bmm_preset :: Word32 -> Ptr Word64 -> Ptr Word8 -> Ptr Word8 -> IO Int32
elements_hs_bmm_preset mode fields powLimit challenge = run `catch` handleFailure (-1)
  where
    run | fields == nullPtr || powLimit == nullPtr || challenge == nullPtr = pure (-1)
        | otherwise = do
            (numbers,limit,script) <- evaluate $ execute (Check (Bmm.ConsensusPreset mode)) Validate
            mapM_ evaluate numbers
            mapM_ evaluate limit
            mapM_ evaluate script
            pokeArray fields numbers
            pokeArray powLimit limit
            pokeArray challenge script
            pure (fromIntegral (length script))

elements_hs_bmm_interval :: Int64 -> Int64 -> Ptr Int64 -> IO Int32
elements_hs_bmm_interval timespan spacing output = run `catch` handleFailure (-1)
  where
    run | output == nullPtr = pure (-1)
        | otherwise = do
            interval <- evaluate $ execute (Check (Bmm.DifficultyInterval timespan spacing)) Validate
            poke output interval
            pure 0

elements_hs_bmm_header_layout :: Word32 -> Word32 -> Word32 -> Ptr Word32 -> IO Int32
elements_hs_bmm_header_layout version flags count output
  | count /= 2 || output == nullPtr = pure (-1)
  | otherwise = run `catch` handleFailure (-1)
  where
    run = case execute (Check (Bmm.HeaderLayout version flags)) Validate of
      Nothing -> pure (-1)
      Just (encoded,fields) -> do
        values <- mapM evaluate [encoded,fields]
        pokeArray output values
        pure 0

elements_hs_bmm_commitment_bytes :: Word32 -> Word32 -> Ptr Word8 -> Ptr Word8 -> IO Int32
elements_hs_bmm_commitment_bytes kind count input output = run `catch` handleFailure (-1)
  where
    run | count > 37 || input == nullPtr || output == nullPtr = pure (-1)
        | otherwise = do
            bytes <- peekArray (fromIntegral count) input
            payload <- evaluate $ execute (Check (Bmm.CommitmentBytes kind bytes)) Validate
            mapM_ evaluate payload
            pokeArray output payload
            pure 0

elements_hs_bmm_signet_template :: Word32 -> Ptr Word32 -> IO Int32
elements_hs_bmm_signet_template count fields = run `catch` handleFailure (-1)
  where
    run | count /= 6 || fields == nullPtr = pure (-1)
        | otherwise = do
            values <- evaluate $ execute (Check Bmm.SignetTemplate) Validate
            mapM_ evaluate values
            pokeArray fields values
            pure 0

elements_hs_bmm_split_signature :: Word64 -> Ptr Word8 -> Ptr Word64 -> IO Int32
elements_hs_bmm_split_signature count bytes prefixSize = run `catch` handleFailure (-1)
  where
    run | count == 0 || count > fromIntegral (maxBound :: Int) || bytes == nullPtr || prefixSize == nullPtr = pure (-1)
        | otherwise = do
            signature <- peekArray (fromIntegral count) bytes
            (size, hashType) <- evaluate $ execute (Check (Bmm.SignatureBytes signature)) Validate
            result <- evaluate (fromIntegral hashType)
            poke prefixSize size
            pure result

elements_hs_bmm_preimage :: Word32 -> FunPtr Bmm.WriteState -> Ptr () -> IO Int32
elements_hs_bmm_preimage kind = bmmActions (execute (Check (Bmm.Preimage kind)) Validate)

elements_hs_bmm_signature_actions :: Word32 -> FunPtr Bmm.WriteState -> Ptr () -> IO Int32
elements_hs_bmm_signature_actions plan = bmmActions (execute (Check (Bmm.SignatureActions plan)) Validate)

elements_hs_bmm_signet_actions :: Word32 -> FunPtr Bmm.WriteState -> Ptr () -> IO Int32
elements_hs_bmm_signet_actions mode = bmmActions (execute (Check (Bmm.SignetActions mode)) Validate)

bmmActions :: [Word32] -> FunPtr Bmm.WriteState -> Ptr () -> IO Int32
bmmActions plan writer context = run `catch` handleFailure (-1)
  where
    run = do
      fields <- evaluate plan
      mapM_ (\field -> Bmm.stateAction (Bmm.StateWrite 0 writer context) field 0) fields
      pure 1

elements_hs_bmm_private_template :: Word32 -> Word32 -> Word32 -> Word32 -> Ptr Word8 -> Ptr Word32 -> Ptr Word8 -> IO Int32
elements_hs_bmm_private_template height time median slot critical fields commitment = run `catch` handleFailure (-1)
  where
    run | critical == nullPtr || fields == nullPtr || commitment == nullPtr = pure (-1)
        | otherwise = do
            bytes <- peekArray 32 critical
            (values, payload) <- evaluate $ execute (Check (Bmm.PrivateTemplate height time median slot bytes)) Validate
            mapM_ evaluate values
            mapM_ evaluate payload
            pokeArray fields values
            pokeArray commitment payload
            pure 0

elements_hs_bmm_encode_state :: FunPtr Bmm.WriteState -> Ptr () -> IO Int32
elements_hs_bmm_encode_state writer context =
  (execute (Bmm.StateEncode (Bmm.StateWrite 0 writer context)) Bmm.encodeState >> pure 1) `catch` handleFailure (-1)

elements_hs_bmm_store_state :: Int32 -> FunPtr Bmm.WriteState -> Ptr () -> IO Int32
elements_hs_bmm_store_state height writer context =
  (execute (Bmm.StateWrite height writer context) Bmm.replaceState >> pure 1) `catch` handleFailure (-1)

elements_hs_bmm_restore_state :: Int32 -> FunPtr Bmm.WriteState -> Ptr () -> IO Int32
elements_hs_bmm_restore_state height writer context =
  (execute (Bmm.StateRestore height writer context) Bmm.replaceState >> pure 1) `catch` handleFailure (-1)

elements_hs_bmm_scale_target :: Word32 -> Word64 -> Word64 -> Ptr Word8 -> Ptr Word8 -> IO Int32
elements_hs_bmm_scale_target count factor divisor target limit = run `catch` handleFailure (-1)
  where
    run | count /= 32 || target == nullPtr || limit == nullPtr = pure (-1)
        | otherwise = do
            old <- peekArray 32 target
            bound <- peekArray 32 limit
            result <- evaluate $ execute (Check (Bmm.TargetScale factor divisor old bound)) Validate
            mapM_ evaluate result
            pokeArray target result
            pure 0

foreign import ccall "dynamic" writeFingerprint :: FunPtr WriteFingerprint -> WriteFingerprint
elements_hs_bmm_fingerprint :: Word32 -> FunPtr Bmm.ReadFingerprint -> FunPtr WriteFingerprint -> Ptr () -> IO Int32
elements_hs_bmm_fingerprint profile reader writer context = run `catch` handleFailure (-1)
  where
    run | profile > 2 || writer == nullFunPtr = pure (-1)
        | otherwise = do
            bytes <- execute (Bmm.FingerprintRequest reader context)
              (Bmm.fingerprint (if profile == 0 then Bmm.BmmFormat else if profile == 1 then Bmm.ExchangeFormat else Bmm.ActivationFormat))
            withArrayLen bytes $ \size ptr -> writeFingerprint writer context ptr (fromIntegral size)

data DepositDepth = DepositDepth Word32 Word32 Word32
instance Validation DepositDepth where
  type ValidationResult DepositDepth = Int32
  validate (DepositDepth deposit tip required) =
    if required > 0 && deposit <= tip && tip - deposit >= required - 1 then 1 else 0

data TreasuryMatch = TreasuryMatch Int32 (IO Int32)
instance Validation TreasuryMatch where
  type ValidationResult TreasuryMatch = IO Bool
  validate (TreasuryMatch expected readSlot)
    | expected < 0 || expected > 255 = pure False
    | otherwise = (==expected) <$> readSlot

elements_hs_treasury_match :: Int32 -> Word32 -> Word64 -> Ptr Word8 -> IO Int32
elements_hs_treasury_match expected opcode size input = (do
    matches <- execute (Check (TreasuryMatch expected readSlot)) Validate
    pure (if matches then 1 else 0)) `catch` handleFailure (-1)
  where
    readSlot
      | size/=4 || input==nullPtr = pure (-1)
      | otherwise = do
          bytes <- B.packCStringLen (castPtr input,4)
          evaluate (execute (Check (TreasuryScript (fromIntegral (Withdrawal.readLE bytes)) opcode)) Validate)

data TreasuryScript = TreasuryScript Word32 Word32
instance Validation TreasuryScript where
  type ValidationResult TreasuryScript = Int32
  validate (TreasuryScript script opcode) =
    if (opcode == 0xb4 || opcode == 0xb7)
       && script .&. 0xff == opcode
       && (script `shiftR` 8) .&. 0xff == 1
       && script `shiftR` 24 == 0x51
    then fromIntegral ((script `shiftR` 16) .&. 0xff)
    else -1

-- Negative fault sentinels are distinct from every consensus rejection.
-- Never allow a Haskell exception to unwind through a C++ stack frame.
guardResult :: a -> a -> IO a
guardResult failure result = evaluate result `catch` handleFailure failure

handleFailure :: a -> SomeException -> IO a
handleFailure failure _ = pure failure

elements_hs_bmm_state :: Word32 -> Int64 -> Word32 -> Word32 -> Word32 -> Word32 -> Word32 -> Word64 -> Word32 -> IO Int32
elements_hs_bmm_state hash interval height time bits start startTime count latest = guardResult (-1) $
  execute (Check (Bmm.ParentState hash interval height time bits start startTime count latest)) Validate

elements_hs_signet_validation :: Word32 -> Word64 -> Word64 -> Word64 -> Word64 -> IO Int32
elements_hs_signet_validation phase a b c d = guardResult (-7) $
  execute (Check (Bmm.SignetValidation phase a b c d)) Validate

elements_hs_bmm_proof_run :: Word32 -> Word32 -> FunPtr ProofFacts -> Ptr () -> IO Int32
elements_hs_bmm_proof_run kind start = factsCall (peekArray 4) (\action ->
  execute (Check (Bmm.ProofExecution kind start action)) Validate)

factsCall :: (Ptr Word64 -> IO reply) -> ((Word32 -> IO reply) -> IO Int32) -> FunPtr ProofFacts -> Ptr () -> IO Int32
factsCall decode run callback context
  | callback == nullFunPtr = pure minBound
  | otherwise = (`catch` handleFailure minBound) $ allocaArray 4 $ \fields ->
      run (\phase -> do
        pokeArray fields [0,0,0,0]
        status <- callProofFacts callback context phase fields
        if status == 1 then decode fields else ioError (userError "fact callback failed"))

elements_hs_peg_read_run :: Word32 -> Word32 -> Word64 -> FunPtr ProofFacts -> Ptr () -> IO Int32
elements_hs_peg_read_run mode kind limit = factsCall (`peekElemOff` 0) (\action ->
  execute (Check (Deposit.ReadExecution mode kind limit action)) Validate)

elements_hs_bmm_state_flow :: Word32 -> Int32 -> IO Int32
elements_hs_bmm_state_flow phase reply = guardResult (-2) $
  execute (Check (Bmm.StateFlow phase reply)) Validate

elements_hs_bmm_state_run :: Word32 -> FunPtr MatchFact -> Ptr () -> IO Int32
elements_hs_bmm_state_run start = callbackCall callMatchFact (\action ->
  execute (Check (Bmm.StateExecution start action)) Validate)

elements_hs_bmm_lifecycle :: Word32 -> Word32 -> IO Int32
elements_hs_bmm_lifecycle phase facts = guardResult (-8) $
  execute (Check (Bmm.Lifecycle phase facts)) Validate

elements_hs_bmm_state_source :: Word32 -> Word32 -> IO Int32
elements_hs_bmm_state_source phase facts = guardResult (-4) $
  execute (Check (Bmm.StateSource phase facts)) Validate

elements_hs_bmm_advance :: Int64 -> Word32 -> Word32 -> Word32 -> Ptr Word32 -> IO Int32
elements_hs_bmm_advance interval time bits count fields
  | count /= 16 || fields == nullPtr = pure (-1)
  | otherwise = (do
      input <- peekArray 16 fields
      output <- mapM evaluate (execute (Check (Bmm.Advance interval time bits input)) Validate)
      pokeArray fields output
      pure 0) `catch` handleFailure (-1)

elements_hs_bmm_traversal :: Word32 -> Word64 -> Word64 -> IO Int32
elements_hs_bmm_traversal phase a b = guardResult (-3) $
  execute (Check (Bmm.Traversal phase a b)) Validate

elements_hs_bmm_codec :: Word32 -> Word32 -> Word64 -> Word64 -> IO Int32
elements_hs_bmm_codec phase facts a b = guardResult (-1) $
  execute (Check (Bmm.Codec phase facts a b)) Validate

elements_hs_bmm_sighash_plan :: Int32 -> Word32 -> Word64 -> IO Int32
elements_hs_bmm_sighash_plan hashType index outputs = guardResult (-1) $
  execute (Check (Bmm.HashPlan hashType index outputs)) Validate

elements_hs_bmm_signature_gate :: Word32 -> Word64 -> Word32 -> Word64 -> IO Int32
elements_hs_bmm_signature_gate witness size index inputs = guardResult (-1) $
  execute (Check (Bmm.SignatureGate witness size index inputs)) Validate

elements_hs_signet_extract :: FunPtr Deposit.ReadPegFields -> Ptr () -> IO Int32
elements_hs_signet_extract reader context =
  execute (Bmm.SignetRequest reader context) Bmm.extractSignetRequest `catch` handleFailure (-1)

elements_hs_bmm_retarget :: Word32 -> Int64 -> Int64 -> Word32 -> Word32 -> IO Int64
elements_hs_bmm_retarget height interval target time start = guardResult (-2) $
  execute (Check (Bmm.Retarget height interval target time start)) Validate

elements_hs_bmm_median :: Word32 -> Ptr Word32 -> IO Int64
elements_hs_bmm_median = bmmMedian Bmm.Median

elements_hs_bmm_parent_median :: Word32 -> Ptr Word32 -> IO Int64
elements_hs_bmm_parent_median = bmmMedian Bmm.ParentMedian

bmmMedian :: ([Word32] -> Bmm.Timing) -> Word32 -> Ptr Word32 -> IO Int64
bmmMedian operation count times = run `catch` handleFailure (-2)
  where
    run | count == 0 || times == nullPtr = pure (-2)
        | otherwise = do
            values <- peekArray (fromIntegral count) times
            guardResult (-2) $ execute (Check (operation values)) Validate

elements_hs_bmm_commitment :: Word32 -> Int32 -> Word32 -> FunPtr Bmm.ReadScript -> Ptr () -> IO Int64
elements_hs_bmm_commitment kind slot count reader context =
  execute (Check (Bmm.Commitment kind slot count reader context)) Validate `catch` handleFailure (-3)

elements_hs_bmm_header :: Word32 -> IO Int32
elements_hs_bmm_header facts = guardResult (-1) $ execute (Check (Bmm.Header facts)) Validate

elements_hs_bmm_activation :: Word32 -> Word32 -> Int64 -> Int64 -> IO Int32
elements_hs_bmm_activation phase facts height activation = guardResult (-1) $
  execute (Check (Bmm.Activation phase facts height activation)) Validate

elements_hs_bmm_proof :: Word32 -> Word32 -> Word64 -> Word64 -> Word64 -> IO Int32
elements_hs_bmm_proof phase facts a b c = guardResult (-1) $
  execute (Check (Bmm.Proof phase facts a b c)) Validate

elements_hs_peg_event :: Word32 -> Int64 -> Int64 -> Int64 -> IO Int64
elements_hs_peg_event kind a b c = guardResult (-6) $
  execute (Check (Deposit.PegEvent kind a b c)) Validate

elements_hs_withdrawal_status :: Int64 -> Ptr Word8 -> Word32 -> IO Int64
elements_hs_withdrawal_status state input size = run `catch` handleFailure (-6)
  where run = do
          status <- B.packCStringLen (castPtr input, fromIntegral size)
          guardResult (-6) $ execute (Check (Deposit.WithdrawalStatus state status)) Validate

foreign export ccall "elements_hs_live_begin_v2" elements_hs_live_begin :: Word32 -> IO (Ptr ())
elements_hs_live_begin :: Word32 -> IO (Ptr ())
elements_hs_live_begin phase =
  (evaluate (Deposit.liveEvidencePlan phase) >>= newIORef >>= newStablePtr >>= pure . castStablePtrToPtr)
    `catch` handleFailure nullPtr

foreign export ccall "elements_hs_live_resume_v2" elements_hs_live_resume :: Ptr () -> Ptr Int64 -> IO Int32
elements_hs_live_resume :: Ptr () -> Ptr Int64 -> IO Int32
elements_hs_live_resume handle fields = run `catch` handleFailure (-2)
  where run
          | handle == nullPtr = pure (-2)
          | otherwise = do
              ref <- deRefStablePtr (castPtrToStablePtr handle)
              snapshot <- if fields == nullPtr then pure Nothing else Just <$>
                ((,,,) <$> peekElemOff fields 0 <*> peekElemOff fields 1 <*>
                  peekElemOff fields 2 <*> peekElemOff fields 3)
              execute (Check (Deposit.ResumeEvidence ref snapshot)) Validate

foreign export ccall "elements_hs_live_free_v2" elements_hs_live_free :: Ptr () -> IO ()
elements_hs_live_free :: Ptr () -> IO ()
elements_hs_live_free handle =
  (if handle == nullPtr then pure () else freeStablePtr (castPtrToStablePtr handle))
    `catch` handleFailure ()

writeReply :: B.ByteString -> Ptr Word8 -> Word32 -> IO Int32
writeReply reply output capacity
  | B.length reply > fromIntegral capacity = pure (-1)
  | B.null reply = pure 0
  | otherwise = B.useAsCStringLen reply $ \(source,count) ->
      copyBytes output (castPtr source) count >> pure (fromIntegral count)

elements_hs_event_identity :: Word32 -> Ptr Word8 -> Word32 -> Word64 -> Word32 -> Ptr Word8 -> Word32 -> IO Int32
elements_hs_event_identity kind input size number status output capacity = run `catch` handleFailure (-1)
  where run
          | size > 64 = pure (-1)
          | otherwise = do
              hash <- B.packCStringLen (castPtr input, fromIntegral size)
              writeReply (execute (Check (Deposit.EventIdentity kind hash number status)) Validate) output capacity

elements_hs_event_layout :: Word32 -> Word32 -> Word32 -> Ptr Word8 -> Ptr Word8 -> Word32 -> Ptr Word32 -> IO Int32
elements_hs_event_layout kind index status keyBuffer valueBuffer capacity sizes = run `catch` handleFailure (-1)
  where run = case execute (Check (Deposit.EventLayout kind index status)) Validate of
          Nothing -> pure 0
          Just (key,value,terminal) -> do
            let literal = maybe B.empty id value
            if B.length key > fromIntegral capacity || B.length literal > fromIntegral capacity ||
                sizes == nullPtr || keyBuffer == nullPtr || (not (B.null literal) && valueBuffer == nullPtr)
              then pure (-1)
              else do
                _ <- writeReply key keyBuffer capacity
                _ <- writeReply literal valueBuffer capacity
                pokeArray sizes [fromIntegral (B.length key), fromIntegral (B.length literal)]
                pure (maybe 1 (const 2) value + if terminal then 256 else 0)

elements_hs_checkpoint :: Word32 -> Ptr Word8 -> Ptr Word8 -> Word32 -> Ptr Word8 -> Word32 -> IO Int32
elements_hs_checkpoint eligible txid previous vout output capacity =
  (execute (Check (Deposit.CheckpointLookup eligible txid previous vout)) Validate >>=
    \reply -> writeReply reply output capacity) `catch` handleFailure (-1)

elements_hs_legacy_claim :: Word32 -> Int64 -> Int64 -> IO Int32
elements_hs_legacy_claim facts actual expected = guardResult (-1) $
  execute (Check (Deposit.LegacyClaim facts actual expected)) Validate

elements_hs_treasury_delta :: Int64 -> Int64 -> Int64 -> Int64 -> IO Int32
elements_hs_treasury_delta previous current claimed maximumValue = guardResult (-1) $
  fromIntegral . fromEnum $ execute (Check (Deposit.TreasuryDelta previous current claimed maximumValue)) Validate

elements_hs_deposit_preflight :: Word32 -> Int64 -> Int64 -> IO Int32
elements_hs_deposit_preflight rule amount bound = guardResult (-1) $
  execute (Check (Deposit.Preflight rule amount bound)) Validate

elements_hs_deposit_broadcast_message :: Word32 -> Word64 -> Ptr Word8 -> IO Int32
elements_hs_deposit_broadcast_message kind size input
  | kind>2 || size>fromIntegral (maxBound :: Int) || (size/=0 && input==nullPtr) = pure (-1)
  | otherwise = (do
      message <- if size==0 then pure B.empty else B.packCStringLen (castPtr input,fromIntegral size)
      evaluate (execute (Check (Deposit.MessageMatches kind message)) Validate)) `catch` handleFailure (-1)

elements_hs_deposit_destination :: Word32 -> FunPtr Deposit.InspectDestination -> Ptr () -> IO Int64
elements_hs_deposit_destination count inspector context =
  execute (Check (Deposit.DepositDestination count inspector context)) Validate `catch` handleFailure (-3)

elements_hs_sidechain_events :: Word32 -> Word32 -> IO Int64
elements_hs_sidechain_events phase result = guardResult (-2) $
  execute (Check (Deposit.SidechainEvents phase result)) Validate

elements_hs_l1_location :: Word32 -> Word32 -> IO Int64
elements_hs_l1_location phase result = guardResult (-2) $
  execute (Check (Deposit.L1Location phase result)) Validate

elements_hs_peg_schema :: Word32 -> Word32 -> Word64 -> Word64 -> IO Int64
elements_hs_peg_schema kind phase value limit = guardResult (-2) $
  execute (Check (Deposit.PegSchema kind phase value limit)) Validate

elements_hs_l1_normalization :: Word32 -> Word32 -> IO Int64
elements_hs_l1_normalization phase result = guardResult (-2) $
  execute (Check (Deposit.L1Normalization phase result)) Validate

elements_hs_withdrawal_status_flow :: Word32 -> Word32 -> IO Int64
elements_hs_withdrawal_status_flow phase result = guardResult (-2) $
  execute (Check (Deposit.WithdrawalStatusFlow phase result)) Validate

elements_hs_deposit_projection :: Word32 -> Word64 -> IO Int32
elements_hs_deposit_projection phase value = guardResult (-1) $
  execute (Check (Deposit.DepositProjection phase value)) Validate

elements_hs_deposit_verification :: Word32 -> Word32 -> IO Int32
elements_hs_deposit_verification phase result = guardResult (-2) $
  execute (Check (Deposit.DepositVerification phase result)) Validate

elements_hs_deposit_state :: Word32 -> Word32 -> IO Int32
elements_hs_deposit_state phase facts = guardResult (-1) $
  execute (Check (Deposit.DepositStateRule phase facts)) Validate

elements_hs_ctip_script :: FunPtr Deposit.ReadCtipOpcode -> Ptr () -> IO Int32
elements_hs_ctip_script reader context =
  execute (Check (Deposit.CtipScript (Deposit.readCtipOpcode reader context))) Validate
    `catch` handleFailure (-1)

elements_hs_persisted_ctip :: Word32 -> Int64 -> Word32 -> FunPtr Deposit.DecodeCtip -> Ptr () -> IO Int32
elements_hs_persisted_ctip facts amount script decoder context =
  execute (Check (Deposit.PersistedCtip facts amount script decoder context)) Validate
    `catch` handleFailure (-1)

elements_hs_deposit_inclusion :: Word32 -> Word64 -> Word32 -> FunPtr Deposit.CheckParentHeader -> Ptr () -> IO Int32
elements_hs_deposit_inclusion facts matches count checker context =
  execute (Check (Deposit.DepositInclusion facts matches count checker context)) Validate
    `catch` handleFailure (-1)

elements_hs_deposit_ctip :: Word32 -> Word64 -> Int64 -> Int64 -> Int64 -> IO Int32
elements_hs_deposit_ctip facts matches current previous witnessed = guardResult (-1) $
  execute (Check (Deposit.DepositCtip facts matches current previous witnessed)) Validate

elements_hs_deposit_evidence :: Word32 -> Word32 -> Ptr Word32 -> Ptr (Ptr Word8) -> Ptr Word8
  -> FunPtr Deposit.HashTransaction -> FunPtr Deposit.DecodeEvidence -> Ptr () -> IO Int32
elements_hs_deposit_evidence maximumTx count sizes fields prevout hasher decoder context =
  execute (Check (Deposit.DeterministicEvidence maximumTx count sizes fields prevout hasher decoder context)) Validate
    `catch` handleFailure (-1)

elements_hs_authenticated_deposit :: Word64 -> Word64 -> Word64 -> Word32 -> Int64 -> Int64
  -> Word64 -> Ptr Word8 -> Ptr Int64 -> IO Int32
elements_hs_authenticated_deposit inputs index witnesses facts claimed witnessed count flags amounts =
  (Deposit.authenticatedRules inputs index witnesses facts claimed witnessed count flags amounts >>= evaluate)
    `catch` handleFailure (-1)

elements_hs_deposit_witness :: Int64 -> Word32 -> Word32 -> Word32 -> Ptr Word32 -> Ptr (Ptr Word8)
  -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> FunPtr Deposit.HashTransaction -> Ptr Int64 -> IO Int32
elements_hs_deposit_witness maximumMoney maximumTx mode count sizes fields asset genesis prevout hasher value =
  execute (Check (Deposit.DepositWitness maximumMoney maximumTx mode count sizes fields asset genesis prevout hasher value))
    Validate
    `catch` handleFailure (-1)

elements_hs_deposit_outputs :: Word32 -> Int64 -> Word32 -> Ptr Word8 -> Word32 -> Ptr Word8 -> Ptr Int64 -> IO Int32
elements_hs_deposit_outputs facts value inputCount inputs outputCount flags amounts =
  (Deposit.outputRules facts value inputCount inputs outputCount flags amounts >>= evaluate)
    `catch` handleFailure (-1)

elements_hs_deposit_depth :: Word32 -> Word32 -> Word32 -> IO Int32
elements_hs_deposit_depth deposit tip required = guardResult (-1) $
  execute (Check (DepositDepth deposit tip required)) Validate

-- Four script bytes packed little-endian by the C++ span adapter. Length is
-- checked there before any read; the script language predicate lives here.
elements_hs_treasury_slot :: Word32 -> Word32 -> IO Int32
elements_hs_treasury_slot script opcode = guardResult (-2) $
  execute (Check (TreasuryScript script opcode)) Validate

elements_hs_withdrawal_payout :: Int64 -> Int64 -> Int64 -> IO Int64
elements_hs_withdrawal_payout burn fee maximumMoney = guardResult (-4)
  (execute (Check (Withdrawal.WithdrawalPayout burn fee maximumMoney)) Validate)

-- Caller owns both buffers. Never retain a pointer, write past capacity, or
-- allow exceptions (including lazy evaluation/copy failures) across the ABI.
elements_hs_withdrawal_bytes :: Word32 -> Int64 -> Ptr Word8 -> Word32 -> Ptr Word8 -> Word32 -> IO Int32
elements_hs_withdrawal_bytes op maximumMoney input size output capacity = run `catch` handleFailure (-1)
  where run = do
          bytes <- B.packCStringLen (castPtr input, fromIntegral size)
          let reply = either ((B.singleton 1 <>) . C.pack) (B.singleton 0 <>) (withdrawal op maximumMoney bytes)
          writeReply reply output capacity
