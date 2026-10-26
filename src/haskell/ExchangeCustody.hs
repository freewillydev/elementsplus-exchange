{-# LANGUAGE ConstraintKinds, DataKinds, FlexibleContexts, FlexibleInstances, GADTs #-}
{-# LANGUAGE MultiParamTypeClasses, TypeApplications, TypeFamilies #-}
-- Standalone exact-ECX proof statement. No legacy bond accounting is inferred.
module ExchangeCustody where

import Control.Operation.Validation
import Control.Operation
import Control.Monad (when)
import CapabilityContext
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import qualified ExchangeForcedV3 as Forced
import BmmConstants (custodySuccessorValuesLength)
import Data.Word (Word8, Word32, Word64)
import Withdrawal (wordBE,wordLE)
import Workflow (NativeBytes)

forcedKindAllowed :: Word8 -> Bool
forcedKindAllowed kind = kind `elem` [3,4]

field :: Int -> Int -> B.ByteString -> B.ByteString
field offset width = B.take width . B.drop offset
number :: Int -> Int -> B.ByteString -> Integer
number offset width = Forced.integerBE . field offset width
nonzero :: Int -> B.ByteString -> Bool
nonzero offset = Forced.nonzeroHash . field offset 32

newtype CustodyValues = CustodyValues B.ByteString
instance Validation CustodyValues where
  type ValidationResult CustodyValues = Bool
  validate (CustodyValues b) = B.length b==custodySuccessorValuesLength &&
    field 0 4 b==B.pack [0,0,0,25] && all (`nonzero` b) [4,36..644] &&
    all (>0) [n 676,n 684,n 692,n 708,n 716,n 724,n 732,n 740] &&
    n 716<=n 708 && n 708<=n 724 && cursor<=count &&
    (cursor/=count || field 612 32 b==field 580 32 b) &&
    B.index b 780<=3 && B.index b 781<=1 && B.index b 782<=1 &&
    ((oldest==0)==(cursor==count)) && oldest<=n 676
    where
      n offset=number offset 8 b
      count=number 748 16 b
      cursor=number 764 16 b
      oldest=number 783 8 b

-- Actual annex program, pinned program, then seven independently pinned hashes:
-- composition, ECX config, clearing policy, source config, custodian registry,
-- physical vault asset and physical vault script.
data CustodyIdentity = CustodyIdentity B.ByteString B.ByteString
instance Validation CustodyIdentity where
  type ValidationResult CustodyIdentity = Bool
  validate (CustodyIdentity v expected) = validate (CustodyValues v) &&
    B.length expected==288 && nonzero 0 expected &&
    field 0 32 expected==field 32 32 expected &&
    B.concat [field offset 32 v | offset<-[4,260,292,324,420,484,516]]==B.drop 64 expected

-- Prior projection bytes: outer root, custody/history root, processed root,
-- u128 processed cursor, u64 sequence, insolvency byte (121 bytes).
-- The source is the complete authenticated prior 145-byte native inbox state.
data CustodyCarry = CustodyCarry B.ByteString B.ByteString
instance Validation CustodyCarry where
  type ValidationResult CustodyCarry = Bool
  validate (CustodyCarry previous source) =
    B.length previous==121 && B.length source==145 &&
    all (`nonzero` previous) [0,32,64] && B.index previous 120<=1 &&
    validate (Forced.ForcedV3State (field 1 32 source) source) &&
    field 64 32 previous==field 81 32 source &&
    field 96 16 previous==field 113 16 source

-- Native anchor: actual txid, prior header exchange root, authenticated BMM
-- hash, tagged hash of the complete prior inbox bytes, then parent height/MTP
-- and sidechain height. All hashes use raw consensus byte order.
data CustodyTransition = CustodyTransition B.ByteString B.ByteString B.ByteString B.ByteString
instance Validation CustodyTransition where
  type ValidationResult CustodyTransition = Bool
  validate (CustodyTransition v previous source anchor) =
    validate (CustodyValues v) && validate (CustodyCarry previous source) &&
    B.length anchor==152 && all (`nonzero` anchor) [0,32,64,96] &&
    field 36 32 v==field 0 32 previous && field 196 32 v==field 32 32 previous &&
    B.index v 781==B.index previous 120 &&
    number 740 8 v==number 112 8 previous+1 &&
    field 260 32 v==field 1 32 source && field 580 32 v==field 33 32 source &&
    field 748 16 v==field 65 16 source && number 764 16 v>=number 113 16 source &&
    B.concat [field offset 32 v | offset<-[100,132,164,548]]==B.take 128 anchor &&
    field 676 24 v==B.drop 128 anchor

-- Native previous/current inbox bytes, prior header oldest, proof-derived oldest
-- after consumption, authenticated parent, claimed next header oldest, receipt.
-- The source append code authenticates every new record before this rule runs.
newtype CustodyBacklog = CustodyBacklog B.ByteString
instance Validation CustodyBacklog where
  type ValidationResult CustodyBacklog = Bool
  validate (CustodyBacklog bytes) = B.length bytes==323 &&
    validate (Forced.ForcedV3State pin before) && validate (Forced.ForcedV3State pin after) &&
    parent>0 && countAfter>=countBefore && cursorAfter>=cursorBefore && cursorAfter<=countBefore &&
    ((oldestBefore==0)==(countBefore==cursorBefore)) && oldestBefore<=parent &&
    B.index bytes 322<=1 &&
    (if B.index bytes 322==0 then cursorAfter==cursorBefore && remaining==oldestBefore
     else ((remaining==0)==(cursorAfter==countBefore)) &&
       (remaining==0 || remaining>=oldestBefore) && remaining<=parent) &&
    claimed==expected && (expected==0 || parent-expected<6)
    where
      before=field 0 145 bytes; after=field 145 145 bytes;pin=field 1 32 before
      countBefore=number 65 16 before;cursorBefore=number 113 16 before
      countAfter=number 65 16 after;cursorAfter=number 113 16 after
      oldestBefore=number 290 8 bytes;remaining=number 298 8 bytes
      parent=number 306 8 bytes;claimed=number 314 8 bytes
      expected | cursorAfter<countBefore = remaining
               | countAfter>countBefore = parent
               | otherwise = 0

-- Template admission budget, bounded by the same persistent pending and
-- per-parent quotas as ForcedV3Append. A proposed budget may be conservative.
newtype CustodyBudget = CustodyBudget B.ByteString
instance Validation CustodyBudget where
  type ValidationResult CustodyBudget = Bool
  validate (CustodyBudget bytes) = B.length bytes==161 &&
    validate (Forced.ForcedV3State (field 1 32 bytes) state) &&
    parent>0 && parent>=number 129 8 state && pending<=448 &&
    budget<=min (448-pending) (64-used)
    where
      state=B.take 145 bytes;parent=number 145 8 bytes;budget=number 153 8 bytes
      pending=number 65 16 state-number 113 16 state
      used=if parent==number 129 8 state then number 137 4 state else 0

-- Early relay/template guard only. Exact proof execution remains mandatory.
-- Native facts: reserved input, exact pair, recreated vault, unconfirmed pair descendant.
newtype CustodyReservedSpend = CustodyReservedSpend B.ByteString
instance Validation CustodyReservedSpend where
  type ValidationResult CustodyReservedSpend = Bool
  validate (CustodyReservedSpend bytes) = B.length bytes==4 && B.all (<=1) bytes &&
    B.index bytes 3==0 && (B.index bytes 0==0 || (B.index bytes 1==1 && B.index bytes 2==1))

-- Maximum admissible count. Validate the zero-budget request first so malformed
-- headers and backwards parent clocks fail without publishing an output.
custodyBudget :: B.ByteString -> Maybe Word64
custodyBudget bytes
  | validate (CustodyBudget (bytes<>wordBE 8 0)) = Just . fromInteger $
      min (448-pending) (64-used)
  | otherwise = Nothing
  where
    pending=number 65 16 bytes-number 113 16 bytes
    used=if number 145 8 bytes==number 129 8 bytes then number 137 4 bytes else 0

class CustodyInputs op where
  custodyInputCount :: op -> IO Word64
  custodyInput :: op -> Word64 -> IO B.ByteString

  foldCustodyInputs :: op -> a -> (a -> Word64 -> B.ByteString -> IO a) -> IO a
  foldCustodyInputs value initial step = do
    count <- custodyInputCount value
    let loop i state | i==count = pure state
                     | otherwise = custodyInput value i >>= step state i >>= loop (i+1)
    loop 0 initial

  anyCustodyInput :: op -> (Word64 -> B.ByteString -> IO Bool) -> IO Bool
  anyCustodyInput value predicate = do
    count <- custodyInputCount value
    let loop i | i==count = pure False
               | otherwise = do
                   input <- custodyInput value i
                   found <- predicate i input
                   if found then pure True else loop (i+1)
    loop 0

class CustodyPolicyFacts op where
  custodyClock :: op -> IO (Bool,Maybe Integer,Integer)
  custodyHasProjection :: op -> Bool -> IO Bool
  custodySelectProjection :: op -> Bool -> IO ()
  custodyPriorPair :: op -> IO B.ByteString
  custodyOutputCount :: op -> IO Word64
  custodyVaultFlag :: op -> Word32 -> IO Bool
  custodyVaultBytes :: op -> Word32 -> Int -> IO B.ByteString
  custodyHasParentLookup :: op -> IO Bool
  custodyLookupParent :: op -> Word64 -> IO (Maybe (B.ByteString,Word64))
  custodyParentInput :: op -> Word64 -> IO B.ByteString

class CustodyPolicyEffects op where
  custodyPolicyError :: op -> String -> IO Bool
  custodyBudgetContext :: op -> IO B.ByteString
  publishCustodyBudget :: op -> Word64 -> IO ()

checkCustodyReserved :: (CustodyInputs op,CustodyPolicyFacts op,CustodyPolicyEffects op) => op -> IO Bool
checkCustodyReserved value = do
  (active,previous,height) <- custodyClock value
  case previous of
    Just priorHeight | active && priorHeight+1>=height -> do
      previousProjection <- custodyHasProjection value False
      genesisProjection <- if not previousProjection && priorHeight+1==height
        then custodyHasProjection value True else pure False
      if not (previousProjection || genesisProjection)
        then custodyPolicyError value "custody reserved-pair policy lacks authenticated predecessor"
        else do
          custodySelectProjection value (not previousProjection)
          prior <- custodyPriorPair value
          let state=B.take 36 prior; vault=B.take 32 prior<>wordBE 4 1
          (reserved,first,second) <- foldCustodyInputs value (0::Integer,False,False) $ \(count,a,b) i input ->
            pure (count+if input==state || input==vault then 1 else 0,
              a || (i==0 && input==state),b || (i==1 && input==vault))
          let pair=reserved==2 && first && second
          recreated <- checkVault value prior
          lookupAvailable <- custodyHasParentLookup value
          descendant <- if not lookupAvailable then pure False else anyCustodyInput value $ \i input ->
            if number 32 4 input>1 then pure False else do
              parent <- custodyLookupParent value i
              case parent of
                Just (hash,count) | hash==B.take 32 input && count>=2 -> do
                  a <- custodyParentInput value 0
                  if a/=state then pure False else (==vault) <$> custodyParentInput value 1
                _ -> pure False
          if not descendant && (reserved==0 || (pair && recreated)) then pure True
            else custodyPolicyError value "custody reserved singleton/vault spend must preserve the coupled pair"
    _ -> pure True

checkVault :: CustodyPolicyFacts op => op -> B.ByteString -> IO Bool
checkVault value prior = do
  count <- custodyOutputCount value
  let both first second = do ok <- first; if ok then second else pure False
  if count<2 then pure False else
    custodyVaultFlag value 7 `both`
    ((==field 36 32 prior) <$> custodyVaultBytes value 8 32) `both`
    custodyVaultFlag value 9 `both` do
      amount <- custodyVaultBytes value 10 8
      if number 0 8 amount>=2^(63::Int) || amount/=field 68 8 prior then pure False else
        custodyVaultFlag value 11 `both`
        ((==field 76 32 prior) <$> custodyVaultBytes value 12 32)

prepareCustodyBudget :: CustodyPolicyEffects op => op -> IO Bool
prepareCustodyBudget value = do
  bytes <- custodyBudgetContext value
  case custodyBudget bytes of
    Nothing -> pure False
    Just budget -> publishCustodyBudget value budget >> pure True

newtype CustodyPolicySession = CustodyPolicySession NativeBytes
policyRead :: CustodyPolicySession -> Word32 -> Word64 -> B.ByteString -> IO B.ByteString
policyRead (CustodyPolicySession native) = native
exactPolicyBytes :: Int -> B.ByteString -> IO B.ByteString
exactPolicyBytes size bytes = do
  when (B.length bytes/=size) (ioError (userError "invalid custody policy frame"))
  pure bytes
policyField :: CustodyPolicySession -> Word32 -> Word64 -> Int -> IO B.ByteString
policyField value step index size = policyRead value step index B.empty >>= exactPolicyBytes size
policyBool :: CustodyPolicySession -> Word32 -> Word64 -> IO Bool
policyBool value step index = do
  bytes <- policyField value step index 1
  when (B.head bytes>1) (ioError (userError "invalid custody policy flag"))
  pure (B.head bytes==1)
policyEffect :: CustodyPolicySession -> Word32 -> Word64 -> B.ByteString -> IO ()
policyEffect value step index bytes = do
  result <- policyRead value step index bytes
  when (result/=B.singleton 1) (ioError (userError "custody policy effect failed"))

instance CustodyInputs CustodyPolicySession where
  custodyInputCount value = fromInteger . number 0 8 <$> policyField value 4 0 8
  custodyInput value index = policyField value 5 index 36

instance CustodyPolicyFacts CustodyPolicySession where
  custodyClock value = do
    bytes <- policyField value 0 0 18
    when (B.any (>1) (B.take 2 bytes)) (ioError (userError "invalid custody policy context"))
    let signed at=let n=number at 8 bytes in if n>=2^(63::Int) then n-2^(64::Int) else n
    pure (B.index bytes 0==1,if B.index bytes 1==1 then Just (signed 2) else Nothing,signed 10)
  custodyHasProjection value genesis = policyBool value (if genesis then 2 else 1) 0
  custodySelectProjection value genesis = policyEffect value 3 (if genesis then 1 else 0) B.empty
  custodyPriorPair value = policyField value 19 0 108
  custodyOutputCount value = fromInteger . number 0 8 <$> policyField value 6 0 8
  custodyVaultFlag value step = policyBool value step 0
  custodyVaultBytes value step size = policyField value step 0 size
  custodyHasParentLookup value = policyBool value 13 0
  custodyLookupParent value index = do
    bytes <- policyRead value 14 index B.empty
    if B.null bytes then pure Nothing else do
      _ <- exactPolicyBytes 40 bytes
      pure (Just (B.take 32 bytes,fromInteger (number 32 8 bytes)))
  custodyParentInput value index = policyField value 15 index 36

instance CustodyPolicyEffects CustodyPolicySession where
  custodyPolicyError value message = policyEffect value 16 0 (C.pack message) >> pure False
  custodyBudgetContext value = policyField value 17 0 153
  publishCustodyBudget value budget = policyEffect value 18 0 (wordBE 8 budget)

type CustodyPolicyCapabilities = '[CustodyInputs,CustodyPolicyFacts,CustodyPolicyEffects]
instance Operation CustodyPolicySession CustodyPolicyCapabilities where
  type Context CustodyPolicySession = CapabilityContext CustodyPolicyCapabilities CustodyPolicySession
  type Outcome CustodyPolicySession = IO Bool
  data DSL CustodyPolicySession where
    CheckReservedPolicy :: Context CustodyPolicySession => DSL CustodyPolicySession
    PrepareSourceBudget :: Context CustodyPolicySession => DSL CustodyPolicySession
  interpret operation request = withOperation @CustodyPolicySession operation $ \value -> case request of
    CheckReservedPolicy -> Just (checkCustodyReserved value)
    PrepareSourceBudget -> Just (prepareCustodyBudget value)

-- A projected CustodyProjection keeps its existing native disk layout: little-
-- endian scalar fields, raw hashes and big-endian uint128 cursor/count bytes.
numberLE :: Int -> Int -> B.ByteString -> Integer
numberLE at width = Forced.integerBE . B.reverse . field at width

newtype QualifiedCustody = QualifiedCustody B.ByteString
data CustodyIdentityHash = EconomicsIdentity | ForcedGenesisIdentity deriving Enum

class CustodyIdentityFacts op where
  identityFrozen :: op -> IO Bool
  identityPins :: op -> IO B.ByteString
  identityAlternatives :: op -> IO B.ByteString
  identityEconomics :: op -> IO B.ByteString
  identityRoot :: op -> IO B.ByteString
  identityProjection :: op -> IO B.ByteString
  identityHasGenesis :: op -> IO Bool
  identityLegacyActive :: op -> IO Bool
  identityGenesisOutpoint :: op -> IO B.ByteString
  identityGenesisSource :: op -> IO B.ByteString

class CustodyIdentityEffects op where
  identityHash :: op -> CustodyIdentityHash -> B.ByteString -> IO B.ByteString
  identityParseAnnex :: op -> IO (Maybe (B.ByteString,B.ByteString))
  identityPublish :: op -> B.ByteString -> IO ()
  identityDiagnostic :: op -> String -> IO Bool

qualifyCustody :: (CustodyIdentityFacts op,CustodyIdentityEffects op) => op -> IO (Maybe QualifiedCustody)
qualifyCustody value = do
  frozen <- identityFrozen value
  if not frozen then pure Nothing else do
    pins <- identityPins value
    if not (all (`nonzero` pins) [0,32..320]) then pure Nothing else do
      alternatives <- identityAlternatives value
      if or [field at 32 pins==field other 32 alternatives | (at,other)<-[(0,0),(0,32),(256,64),(256,96)]]
        then pure Nothing else do
          economics <- identityEconomics value
          digest <- identityHash value EconomicsIdentity economics
          pure $ if digest==field 64 32 pins && field 192 32 pins==field 50 32 economics
            then Just (QualifiedCustody pins) else Nothing

projectionIdentity :: QualifiedCustody -> B.ByteString -> B.ByteString -> Bool
projectionIdentity (QualifiedCustody pins) root s = B.length s==535 && B.length root==32 &&
  numberLE 0 2 s==6 && Forced.nonzeroHash root && field 2 32 s==root &&
  nonzero 34 s && numberLE 66 4 s==0 && nonzero 70 s && nonzero 102 s &&
  and [field at 32 s==field pin 32 pins | (at,pin)<-
    [(134,0),(166,256),(198,32),(230,64),(262,96),(294,128),(326,160),(358,192),(390,224)]] &&
  nonzero 422 s && nonzero 454 s && number 502 16 s<=number 486 16 s &&
  (field 502 16 s/=field 486 16 s || field 454 32 s==field 422 32 s) && B.index s 534<=1

checkCustodyIdentity :: (CustodyIdentityFacts op,CustodyIdentityEffects op) => op -> IO Bool
checkCustodyIdentity value = do
  qualified <- qualifyCustody value
  case qualified of
    Nothing -> pure False
    Just profile -> projectionIdentity profile <$> identityRoot value <*> identityProjection value

checkCustodyGenesis :: (CustodyIdentityFacts op,CustodyIdentityEffects op) => op -> IO Bool
checkCustodyGenesis value = do
  qualified <- qualifyCustody value
  case qualified of
    Nothing -> pure False
    Just profile@(QualifiedCustody pins) -> do
      present <- identityHasGenesis value
      legacy <- if present then identityLegacyActive value else pure True
      if legacy then pure False else do
        root <- identityRoot value
        s <- identityProjection value
        if not (projectionIdentity profile root s) then pure False else do
          point <- identityGenesisOutpoint value
          if field 34 36 s/=point || numberLE 518 8 s/=0 || B.index s 534/=0 ||
             number 486 16 s/=0 || number 502 16 s/=0 then pure False else do
            genesis <- identityHash value ForcedGenesisIdentity (field 320 32 pins<>field 64 32 pins)
            if field 422 32 s/=genesis then pure False else do
              source <- identityGenesisSource value
              let previous=field 70 64 s<>field 454 32 s<>field 502 16 s<>
                    wordBE 8 (fromInteger (numberLE 518 8 s))<>field 534 1 s
              pure (field 1 32 source==field 64 32 pins && field 33 32 source==field 422 32 s &&
                field 65 16 source==field 486 16 s && validate (CustodyCarry previous source))

projectionFromValues :: QualifiedCustody -> B.ByteString -> B.ByteString -> B.ByteString
projectionFromValues (QualifiedCustody pins) root v = wordLE 2 6<>root<>field 100 32 v<>wordLE 4 0<>
  field 68 32 v<>field 228 32 v<>field 0 32 pins<>field 256 32 pins<>
  B.concat [field at 32 v | at<-[4,260,292,324,420,484,516,580,612]]<>
  field 748 32 v<>wordLE 8 (fromInteger (number 740 8 v))<>
  wordLE 8 (fromInteger (number 700 8 v))<>field 782 1 v

decodeCustodyIdentity :: (CustodyIdentityFacts op,CustodyIdentityEffects op) => op -> IO Bool
decodeCustodyIdentity value = do
  qualified <- qualifyCustody value
  let unavailable=identityDiagnostic value "exact custody profile has no qualified deployment identity"
  case qualified of
    Nothing -> unavailable
    Just profile@(QualifiedCustody pins) -> do
      root <- identityRoot value
      if not (Forced.nonzeroHash root) then unavailable else do
        parsed <- identityParseAnnex value
        case parsed of
          Nothing -> identityDiagnostic value "exact custody requires canonical annex8/PublicValues25"
          Just (program,v) -> do
            let expected=program<>B.take 256 pins
            if not (validate (CustodyIdentity v expected))
              then identityDiagnostic value "custody statement does not match its independent deployment pins"
              else do
                let result=projectionFromValues profile root v
                if not (projectionIdentity profile root result)
                  then identityDiagnostic value "invalid exact custody projection"
                  else identityPublish value result >> pure True

newtype CustodyIdentitySession = CustodyIdentitySession NativeBytes
identityRead :: CustodyIdentitySession -> Word32 -> Word64 -> B.ByteString -> IO B.ByteString
identityRead (CustodyIdentitySession native)=native
identityField :: CustodyIdentitySession -> Word32 -> Int -> IO B.ByteString
identityField value step size=identityRead value step 0 B.empty >>= exactPolicyBytes size
identityBool :: CustodyIdentitySession -> Word32 -> IO Bool
identityBool value step=do
  bytes<-identityField value step 1
  when (B.head bytes>1) (ioError (userError "invalid custody identity flag"))
  pure (B.head bytes==1)
identityEffect :: CustodyIdentitySession -> Word32 -> B.ByteString -> IO ()
identityEffect value step bytes=do
  result<-identityRead value step 0 bytes
  when (result/=B.singleton 1) (ioError (userError "custody identity publication failed"))

instance CustodyIdentityFacts CustodyIdentitySession where
  identityFrozen value=identityBool value 0
  identityPins value=identityField value 1 352
  identityAlternatives value=identityField value 2 128
  identityEconomics value=identityField value 3 259
  identityRoot value=identityField value 5 32
  identityProjection value=identityField value 6 535
  identityHasGenesis value=identityBool value 7
  identityLegacyActive value=identityBool value 8
  identityGenesisOutpoint value=identityField value 9 36
  identityGenesisSource value=identityField value 10 145

instance CustodyIdentityEffects CustodyIdentitySession where
  identityHash value kind bytes=identityRead value 4 (fromIntegral (fromEnum kind)) bytes >>= exactPolicyBytes 32
  identityParseAnnex value=do
    bytes<-identityRead value 11 0 B.empty
    if B.null bytes then pure Nothing else do
      _<-exactPolicyBytes (32+custodySuccessorValuesLength) bytes
      pure (Just (B.take 32 bytes,B.drop 32 bytes))
  identityPublish value=identityEffect value 12
  identityDiagnostic value message=identityEffect value 13 (C.pack message) >> pure False

type CustodyIdentityCapabilities = '[CustodyIdentityFacts,CustodyIdentityEffects]
instance Operation CustodyIdentitySession CustodyIdentityCapabilities where
  type Context CustodyIdentitySession = CapabilityContext CustodyIdentityCapabilities CustodyIdentitySession
  type Outcome CustodyIdentitySession = IO Bool
  data DSL CustodyIdentitySession where
    CheckCustodyAvailability :: Context CustodyIdentitySession => DSL CustodyIdentitySession
    CheckProjectionIdentity :: Context CustodyIdentitySession => DSL CustodyIdentitySession
    CheckGenesisIdentity :: Context CustodyIdentitySession => DSL CustodyIdentitySession
    DecodeProjectionIdentity :: Context CustodyIdentitySession => DSL CustodyIdentitySession
  interpret operation request = withOperation @CustodyIdentitySession operation $ \value -> case request of
    CheckCustodyAvailability -> Just (maybe False (const True) <$> qualifyCustody value)
    CheckProjectionIdentity -> Just (checkCustodyIdentity value)
    CheckGenesisIdentity -> Just (checkCustodyGenesis value)
    DecodeProjectionIdentity -> Just (decodeCustodyIdentity value)
