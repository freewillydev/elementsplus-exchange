{-# LANGUAGE TypeFamilies #-}
-- Copyright (c) 2026 The Elements Core developers
-- Distributed under the MIT software license.
module ScriptPolicy where

import Control.Operation.Validation
import Workflow (orderedFacts)
import Data.Bits (testBit, (.&.))
import Data.Int (Int32, Int64)
import Data.Word (Word8, Word32, Word64)
import qualified Data.ByteString as B
import ParentReplay (transition)
import BmmConstants (activationBudget, ownedAnnexLimit)

data MerkleReplacement = MerkleReplacement Word32 Word32 Word32 Word32
instance Validation MerkleReplacement where
  type ValidationResult MerkleReplacement = Int32
  validate (MerkleReplacement mode index position flags)
    | mode==0 && flags==0 = result (index/=maxBound)
    | mode==1 && flags<=3 = result (flags==3 && index==position)
    | mode==2 && flags<=1 = result (index==maxBound || flags==1)
    | otherwise = -1
    where result accepted=if accepted then 1 else 0

data AnnexRetention = AnnexRetention Word64 Word64 Bool Bool (IO Word8) (IO Bool)
instance Validation AnnexRetention where
  type ValidationResult AnnexRetention = IO Bool
  validate (AnnexRetention fullSize bodySize fullPresent bodyPresent readTag matches)
    | not fullPresent || fullSize==0 || fullSize>fromIntegral ownedAnnexLimit = pure False
    | otherwise = do
        tag <- readTag
        if tag/=0x50 || bodySize/=fullSize-1 then pure False
        else if bodySize==0 then pure True
        else if not bodyPresent then pure False else matches

data StandardnessGate = AnnexNetwork Word32 | OutputExceptions Word32
                     | WitnessResources Word32 Word64 Word64
instance Validation StandardnessGate where
  type ValidationResult StandardnessGate = Int32
  validate (AnnexNetwork facts)
    | facts > 7 = -1
    | otherwise = if facts == 7 then 1 else 0
  validate (OutputExceptions facts)
    | facts > 7 = -1
    | otherwise = if facts /= 0 then 1 else 0
  validate (WitnessResources flags count limit) = if flags == 0 && count <= limit then 1 else 0

data ParameterGate = ParameterGate Word32 Int64 Int64
instance Validation ParameterGate where
  type ValidationResult ParameterGate = Int32
  validate (ParameterGate mode first second) = case mode of
    0 -> if first >= 0 && second >= first then 1 else 0
    1 | first `elem` [0,1] && second `elem` [0,1] -> if first == 1 && second == 1 then 1 else 0
    2 | second == 0 -> if first >= 0 then 1 else 0
    _ -> -1

data OptionalEnvironment = OptionalEnvironment Word32 Word32 Word32
instance Validation OptionalEnvironment where
  type ValidationResult OptionalEnvironment = Int32
  validate (OptionalEnvironment kind present fields)
    | present>1 = -1
    | otherwise = case kind of
        0 -> exact 1
        1 -> exact 7
        2 -> exact 255
        3 | fields<=7 -> accept (if present==1 then fields .&. 5 == 5 else fields==0)
        4 | fields<=7 -> accept (if present==1 then fields==7 else fields .&. 3 == 0)
        5 | fields<=15 -> accept (if present==1 then fields .&. 13 == 13 else fields==0)
        _ -> -1
    where
      accept valid = if valid then 1 else 0
      exact mask | fields>mask = -1
                 | otherwise = accept (fields==if present==1 then mask else 0)

data ReturnMarker = ReturnMarker B.ByteString B.ByteString
instance Validation ReturnMarker where
  type ValidationResult ReturnMarker = Bool
  validate (ReturnMarker magic bytes) = not (B.null bytes) && B.head bytes == 106 &&
    magic `B.isInfixOf` B.tail bytes

data BondMarkerPolicy = BondMarkerPolicy Bool B.ByteString
instance Validation BondMarkerPolicy where
  type ValidationResult BondMarkerPolicy = Bool
  validate (BondMarkerPolicy exact bytes)
    | exact = B.length bytes == 507 && B.take 2 bytes == B.pack [106,77]
    | otherwise = B.length bytes >= 8 &&
        validate (ReturnMarker (B.pack [69,67,88,66]) bytes)

-- Rust statuses other than ACCEPTED never authorize the journal.
data JournalVerifier = JournalVerifier Bool (IO Bool) (IO Word32)
instance Validation JournalVerifier where
  type ValidationResult JournalVerifier = IO Int32
  validate (JournalVerifier valid available verify)
    | not valid = pure 1
    | otherwise = do
        ready <- available
        if not ready then pure 2 else do
          status <- verify
          pure (if status == 0 then 0 else 1)

-- Outcomes: keep stack, reject, strip annex, strip and record USDD annex.
data WitnessAnnexFlow = WitnessAnnexFlow Word32 Word32
instance Validation WitnessAnnexFlow where
  type ValidationResult WitnessAnnexFlow = Int32
  validate (WitnessAnnexFlow phase result) = transition phase result
    [(1,(-10,2)),(2,(4,3)),(3,(4,-12)),(4,(-12,5)),
     (5,(-11,6)),(6,(-11,7)),(7,(8,-11)),(8,(-11,-13))]

-- Fork-only annex/Simplicity policy, after native witness/control-block checks.
-- Flags: annex present, canonical bond inbox. Outcomes: reject or accept.
data TaprootWitnessPolicy = TaprootWitnessPolicy Word32 Word64 Word32 Word64 Word64
instance Validation TaprootWitnessPolicy where
  type ValidationResult TaprootWitnessPolicy = Int32
  validate (TaprootWitnessPolicy flags count leaf scriptSize input)
    | flags > 3 || leaf > 255 || count == 0 = -1
    | count == 1 = if not annex || (testBit flags 1 && input == 0) then 1 else 0
    | leaf == 0xbe = if count == 4 && scriptSize == 32 then 1 else 0
    | otherwise = if annex then 0 else 1
    where annex = testBit flags 0

data TransactionWeight = TransactionWeight Word32 Word64 Word64 Word64 Word64
instance Validation TransactionWeight where
  type ValidationResult TransactionWeight = Int32
  validate (TransactionWeight bond total annex ordinary proof)
    | bond > 1 = -1
    | annex > total || (bond == 1 && annex /= 0) = 0
    | total - annex > ordinary && bond == 0 = 0
    | annex /= 0 && total > proof = 0
    | otherwise = 1

data VerifierStartup = VerifierStartup Bool (Word32 -> IO Int32)
instance Validation VerifierStartup where
  type ValidationResult VerifierStartup = IO Int32
  validate (VerifierStartup active readFact) =
    if active then orderedFacts readFact (zip [0..] [1,6,2,3,4,5]) 0 else pure 0

data ActivationShape = ActivationShape (Word32 -> IO Int64)
instance Validation ActivationShape where
  type ValidationResult ActivationShape = IO Int32
  validate (ActivationShape readFact) = foldr (\(step,accept) next -> readFact step >>= \value ->
    if value < 0 then pure (-1) else if accept value then next else pure 0) (pure 1)
    (zip [0..] [(==5),(==32),(==800),(==0x50),
      (\n -> n>=33 && n<=4129 && (n-33) `mod` 32==0),
      (\n -> n<=255 && n .&. 0xfe==0xbe)])

data ActivationBudget = ActivationBudget Int64 Word32 (Word32 -> IO Int32)
instance Validation ActivationBudget where
  type ValidationResult ActivationBudget = IO (Either Int32 Int64)
  validate (ActivationBudget ordinary input readFact)
    | ordinary < 0 || ordinary > activationBudget || input /= 0 = pure (Right ordinary)
    | otherwise = do
        credit <- orderedFacts readFact (zip [0..6] (repeat 0)) 1
        pure $ case credit of
          0 -> Right ordinary
          1 -> Right activationBudget
          _ -> Left (-1)

-- Flags: enabled, discourage CTV, discourage NOPs, discourage future sizes,
-- stack item present. Outcomes: ignore, discourage, empty stack, check hash.
data TemplateAdmission = TemplateAdmission Word32 Word64
instance Validation TemplateAdmission where
  type ValidationResult TemplateAdmission = Int32
  validate (TemplateAdmission flags size)
    | flags > 31 || (not (testBit flags 4) && size /= 0) = -1
    | testBit flags 1 = 1
    | not (testBit flags 0) = if testBit flags 2 then 1 else 0
    | not (testBit flags 4) = 2
    | size == 32 = 3
    | testBit flags 3 = 1
    | otherwise = 0
