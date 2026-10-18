{-# LANGUAGE ConstraintKinds, DataKinds, FlexibleContexts, GADTs, ScopedTypeVariables #-}
{-# LANGUAGE FlexibleInstances, MultiParamTypeClasses, TypeApplications, TypeFamilies #-}
-- Copyright (c) 2026 The Elements Core developers
-- Distributed under the MIT software license.
module Exchange where

import Control.Operation.Validation
import Control.Operation
import Workflow (runRequiredEffects)
import CapabilityContext
import Data.Word (Word8, Word32, Word64)
import Data.Bits ((.&.), testBit, setBit, popCount)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Char8 as C
import Data.ByteString.Builder (byteString, toLazyByteString, word8, word8HexFixed, word32BE, word32LE, word64BE)
import Withdrawal (readBE, readLE, wordBE)
import Data.List (nub)
import Control.Monad (foldM, forM, zipWithM, when, guard)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Except (ExceptT, runExceptT, throwE)
import Data.Int (Int32, Int64)
import ParentReplay (transition, RequiredFactsFlow(..))
import BmmConstants (bondRequiredArguments, bondGroupedArguments, exchangeIdentities, bondFixedSupply, capitalModes, oracleModes, forcedBodySizes, depositPayloadSize,
  forcedInclusionBlocks, maxCombinedUnconsumed, maxCombinedAppends, maxPendingWitnessEntries, maxTrancheWork,
  groth16ProofLength, publicValuesV4Length, publicValuesV5Length, activationValuesLength, successorValuesLength, productionChainName, pegEventCountLimit, pegEventDefaultCount, bondExportBlockLimit, exchangeScriptCacheRevision)

groth16Layout :: Word32 -> Int -> Maybe (Word8,Word32)
groth16Layout kind size = lookup (kind,size)
  [((0,435),(2,0)),((0,1044),(3,4)),((1,1044),(3,4)),
   ((2,1285),(4,5)),((3,799),(5,1)),((4,2062),(6,23))]

data Groth16Envelope = Groth16Envelope Word32 B.ByteString (B.ByteString -> IO B.ByteString)
instance Validation Groth16Envelope where
  type ValidationResult Groth16Envelope = IO Bool
  validate (Groth16Envelope kind annex hash) = case groth16Layout kind (B.length annex) of
    Just (wire,version) | validate (Groth16Header wire (B.take 79 annex)) && canonical version ->
      if B.null values then pure True else (==B.take 32 (B.drop 43 annex)) <$> hash values
    _ -> pure False
    where
      values=B.drop 435 annex
      canonical 0=True
      canonical 1=validate (CanonicalActivation values)
      canonical version=validate (CanonicalPublicValues version values)

data Groth16Proof = Groth16Proof Word32 B.ByteString B.ByteString B.ByteString
  (B.ByteString -> IO B.ByteString) (B.ByteString -> [Word32] -> B.ByteString -> IO Bool)
instance Validation Groth16Proof where
  type ValidationResult Groth16Proof = IO Bool
  validate (Groth16Proof kind annex expectedProgram expectedDigest hash verify)
    | B.length expectedProgram/=32 || B.length expectedDigest/=32 || (kind<=1 && not matches) = pure False
    | otherwise = do
        authenticated <- validate (Groth16Envelope kind annex hash)
        if authenticated && matches then verify (B.take groth16ProofLength (B.drop 79 annex)) program digest else pure False
    where
      programBytes=B.take 32 (B.drop 11 annex)
      digest=B.take 32 (B.drop 43 annex)
      matches=programBytes==expectedProgram && digest==expectedDigest
      program=[fromIntegral (readBE (B.take 4 (B.drop offset programBytes))) | offset<-[0,4..28]]

data JetHeight = JetHeight Bool Word64
instance Validation JetHeight where
  type ValidationResult JetHeight = Bool
  validate (JetHeight present height) = present && height/=0

data TrackerHeight = TrackerHeight Word32 Int32
instance Validation TrackerHeight where
  type ValidationResult TrackerHeight = Int64
  validate (TrackerHeight mode height)
    | mode==0 = max 0 (fromIntegral height)
    | mode==1 && height/=minBound = fromIntegral height-1
    | otherwise = -2147483649

data BondInput = BondInput Word64 Word64 Word32 (IO Bool)
instance Validation BondInput where
  type ValidationResult BondInput = IO Bool
  validate (BondInput index current flags matches)
    | index<2 || index/=current || flags/=4 = pure False
    | otherwise = matches

data Groth16Header = Groth16Header Word8 B.ByteString
instance Validation Groth16Header where
  type ValidationResult Groth16Header = Bool
  validate (Groth16Header version header) = B.length header==79 &&
    B.take 11 header==C.pack "ECXSP1\0" <> B.pack [version,2,1,0] &&
    readBE (B.drop 75 header)==fromIntegral groth16ProofLength && any (/=0) program && all (<0x7f000001) program
    where program=[readBE (B.take 4 (B.drop offset header)) | offset<-[11,15..39]]

data CanonicalPublicValues = CanonicalPublicValues Word32 B.ByteString
instance Validation CanonicalPublicValues where
  type ValidationResult CanonicalPublicValues = Bool
  validate (CanonicalPublicValues version bytes) =
    version `elem` [4,5,23] && B.length bytes==expectedSize &&
    number (if successor then 0 else 32) 4==toInteger version &&
    all (B.any (/=0) . (`field` 32)) hashOffsets &&
    all (>0) [height,mtp,lower,upper] && outstanding<=toInteger bondFixedSupply &&
    reserve<signedLimit && deficit<signedLimit &&
    target==deficit+(deficit+3) `div` 4 &&
    nav==(if outstanding==0 then 0 else reserve*100000000 `div` outstanding) &&
    coverage==(if deficit==0 then 12500 else reserve*10000 `div` deficit) &&
    mode==(if reserve>=target then 0 else if reserve>=deficit then 1 else 2) &&
    queued<=outstanding && redemptionHead<=redemptionTail &&
    (redemptionHead==redemptionTail)==(queued==0) &&
    fundingRate>=(-10000) && fundingRate<=10000 && specific
    where
      successor=version==23
      expectedSize=case version of 4 -> publicValuesV4Length; 5 -> publicValuesV5Length; _ -> successorValuesLength
      field offset width=B.take width (B.drop offset bytes)
      number offset width=B.foldl' (\value byte -> value*256+toInteger byte) 0 (field offset width)
      scalar offset=number offset 8
      wide offset=number offset 16
      at legacy current=if successor then current else legacy
      signedLimit=2^(127::Int)
      hashOffsets=if successor then [4,36..1252] else
        [0,36,68,100,132,164,196,244,276,308,340,372,404,436] ++
        (if version==5 then [609,650,682,722,762,802] else [])
      height=scalar (at 228 1284)
      mtp=scalar (at 236 1292)
      reserve=wide (at 468 1460)
      outstanding=scalar (at 484 1340)
      nav=wide (at 492 1508)
      deficit=wide (at 508 1428)
      target=wide (at 524 1444)
      coverage=wide (at 540 1524)
      lower=scalar (at 557 1316)
      upper=scalar (at 565 1324)
      fundingRate=fromIntegral (fromInteger (number (at 581 1620) 4)::Word32)::Int32
      redemptionHead=number (at 585 1540) (if successor then 16 else 8)
      redemptionTail=number (at 593 1556) (if successor then 16 else 8)
      queued=scalar (at 601 1356)
      mode=number (at 556 1624) 1
      specific
        | successor = let mark=scalar 1308; lowerDeficit=wide 1396; upperDeficit=wide 1412 in
            scalar 1300>0 && mark>0 && lower<=mark && mark<=upper &&
            scalar 1332==toInteger bondFixedSupply && scalar 1348==toInteger bondFixedSupply-outstanding &&
            all (<signedLimit) [lowerDeficit,upperDeficit,target] &&
            deficit==max lowerDeficit upperDeficit && scalar 1364==mtp `div` 28800 &&
            scalar 1372>0 && number 1625 1<=3 && number 1626 1<=1 && wide 1588<=wide 1572
        | version==5 = upper>lower && number 649 1<=3 && scalar 641>=mtp &&
            scalar 754<=scalar 714 && scalar 794==scalar 754 &&
            (scalar 754/=scalar 714 || field 682 32==field 722 32) && scalar 842>=scalar 834
        | otherwise = upper>lower

newtype CanonicalActivation = CanonicalActivation B.ByteString
instance Validation CanonicalActivation where
  type ValidationResult CanonicalActivation = Bool
  validate (CanonicalActivation bytes) = B.length bytes==activationValuesLength &&
    field 0 4==B.pack [0,0,0,1] && all (B.any (/=0)) identities &&
    all (>0) scalars && lower<=mark && mark<=upper &&
    length (nub [identities !! 0,identities !! 1,identities !! 3])==3
    where
      field offset width=B.take width (B.drop offset bytes)
      identities=[field (4+32*i) 32 | i<-[0..9]]
      scalars=[readBE (field offset 8) | offset<-[324,332,340,348,356]]
      mark=scalars !! 2
      lower=scalars !! 3
      upper=scalars !! 4

data MulDiv128 = MulDiv128 Word64 Word64 Word64 Word64 Word64
instance Validation MulDiv128 where
  type ValidationResult MulDiv128 = Maybe [Word64]
  validate (MulDiv128 high low multiplier divisorHigh divisorLow)
    | divisor == 0 || quotient >= radix*radix = Nothing
    | otherwise = Just [fromInteger (quotient `quot` radix),fromInteger quotient]
    where
      radix = 18446744073709551616
      divisor = toInteger divisorHigh*radix + toInteger divisorLow
      quotient = (toInteger high*radix + toInteger low)*toInteger multiplier `quot` divisor

data AuthenticatedHeightFlow = AuthenticatedHeightFlow Word32 Word32
instance Validation AuthenticatedHeightFlow where
  type ValidationResult AuthenticatedHeightFlow = Int32
  validate (AuthenticatedHeightFlow phase result) = transition phase result
    [(1,(5,2)),(2,(3,4)),(3,(-1,-10)),(4,(-1,-11)),(5,(6,9)),
     (6,(8,7)),(7,(-1,-10)),(8,(-1,-10)),(9,(-1,10)),(10,(-10,-11))]

data ExportReconstructFlow = ExportReconstructFlow Word32 Word32
instance Validation ExportReconstructFlow where
  type ValidationResult ExportReconstructFlow = Int32
  validate (ExportReconstructFlow phase result)
    | phase == 1 = if result == 1 then 2 else 4
    | phase == 2 = if result == 0 then 3 else 5
    | otherwise = transition phase result
        [(3,(-1,5)),(4,(9,6)),(5,(9,6)),(6,(8,7)),(7,(8,-11)),(8,(-1,-1)),(9,(-1,-1))]

data LegacyMarkerFlow = LegacyMarkerFlow Word32 Word32
instance Validation LegacyMarkerFlow where
  type ValidationResult LegacyMarkerFlow = Int32
  validate (LegacyMarkerFlow phase result) = transition phase result
    [(1,(-11,2)),(2,(3,4)),(3,(-10,-10)),(4,(-10,5)),(5,(-10,6)),(6,(-1,-11))]

data MarkerAuthenticationFlow = MarkerAuthenticationFlow Word32 Word32
instance Validation MarkerAuthenticationFlow where
  type ValidationResult MarkerAuthenticationFlow = Int32
  validate (MarkerAuthenticationFlow phase result) = transition phase result
    [(1,(2,3)),(2,(-10,-10)),(3,(-11,4)),(4,(6,5)),(5,(6,-11)),(6,(-10,-10))]

data ParentContextFlow = ParentContextFlow Word32 Word32
instance Validation ParentContextFlow where
  type ValidationResult ParentContextFlow = Int32
  validate (ParentContextFlow phase result) = transition phase result
    [(1,(2,3)),(2,(-1,-11)),(3,(5,4)),(4,(7,6)),(5,(7,6)),
     (6,(-1,-11)),(7,(-1,-11))]

data BondContextFlow = BondContextFlow Word32 Word32
instance Validation BondContextFlow where
  type ValidationResult BondContextFlow = Int32
  validate (BondContextFlow phase result)
    | phase == 3 && result > 3 = -1
    | otherwise = validate (RequiredFactsFlow 16 phase
        (if phase == 3 then fromIntegral (fromEnum (result /= 0)) else result))

data ActivationAnchorFlow = ActivationAnchorFlow Word32 Word32
instance Validation ActivationAnchorFlow where
  type ValidationResult ActivationAnchorFlow = Int32
  validate (ActivationAnchorFlow phase result) = transition phase result
    ([(step,(-10,fromIntegral step+1)) | step <- [1..17]] ++
     [(18,(22,19)),(19,(22,20)),(20,(22,21)),(21,(-1,22)),(22,(-1,23)),
      (23,(-10,24)),(24,(-10,25)),(25,(-1,26)),(26,(-10,27)),
      (27,(-10,28)),(28,(-1,-11))])

data FrozenProfileFlow = FrozenProfileFlow Word32 Word32
instance Validation FrozenProfileFlow where
  type ValidationResult FrozenProfileFlow = Int32
  validate (FrozenProfileFlow phase result) = transition phase result
    [(1,(-11,2)),(2,(3,4)),(3,(-1,-1)),(4,(-11,5)),
     (5,(8,6)),(6,(7,8)),(7,(-1,-1)),(8,(-1,4))]

boundedRangeEnd :: Int32 -> Int32 -> Int32 -> Int32
boundedRangeEnd start count height = fromInteger (min (toInteger height) (toInteger start + toInteger count - 1))

data ExportRange = ExportRange Int32 Int32 Int32 (Maybe Int32) | PegEventRange Int32 Int32 Int32 | PegEventStart Int32
instance Validation ExportRange where
  type ValidationResult ExportRange = Either Int32 Int32
  validate (PegEventStart tip) = Right (fromInteger (max 0 (toInteger tip - toInteger pegEventDefaultCount + 1)))
  validate (ExportRange start count activation tip)
    | start < activation || count < 1 || count > fromIntegral bondExportBlockLimit = Left 1
    | otherwise = case tip of
        Nothing -> Right start
        Just height
          | height < 0 || start > height -> Left 2
          | otherwise -> Right (boundedRangeEnd start count height)
  validate (PegEventRange start count tip)
    | start < 0 || start > tip = Left 1
    | count < 1 || count > fromIntegral pegEventCountLimit = Left 2
    | otherwise = Right (boundedRangeEnd start count tip)

data WideDecimal = WideDecimal Bool B.ByteString
instance Validation WideDecimal where
  type ValidationResult WideDecimal = Maybe B.ByteString
  validate (WideDecimal signed bytes)
    | B.length bytes /= 16 = Nothing
    | otherwise = Just (C.pack (show value))
    where
      unsigned = B.foldl' (\n byte -> n*256 + toInteger byte) 0 bytes
      value = if signed && unsigned >= 2^(127::Int) then unsigned - 2^(128::Int) else unsigned

-- Raw hashes retain byte order; display hashes/outpoint txids reverse it.
data SourceSelection = SourceSelection Bool SourcePackage
instance Validation SourceSelection where
  type ValidationResult SourceSelection = IO (Int32,Word64)
  validate (SourceSelection modified package@(SourcePackage _ _ action)) = do
    result@(code,_) <- validate package
    if code/=1 || not modified then pure result else do
      cleaned <- runRequiredEffects (\step -> action step 0) [7,8]
      pure (if cleaned==0 then 1 else -1,0)

data SourcePackage = SourcePackage Bool Word64 (Word32 -> Word64 -> IO Word64)
instance Validation SourcePackage where
  type ValidationResult SourcePackage = IO (Int32,Word64)
  validate (SourcePackage enabled count action) = if enabled then scan 0 0 else admit 0
    where
      rejected = pure (1,0)
      scan index total
        | index==count = admit total
        | otherwise = action 0 index >>= \parsed -> if parsed/=1 then rejected else do
            forced <- action 1 index
            deposit <- action 2 index
            let next = total + toInteger forced + toInteger deposit
            if next>toInteger (maxBound :: Word64) then rejected else scan (index+1) next
      admit total = do
        selected <- action 3 0
        budget <- action 4 0
        let next = toInteger selected + total
        if next>toInteger budget then rejected else publish 0 (fromInteger next)
      publish index next
        | index==count = pure (0,next)
        | otherwise = do
            added <- action 5 index
            erased <- if added==1 then action 6 index else pure 0
            if erased==1 then publish (index+1) next else pure (-1,0)

data IdentityRecord = IdentityRecord B.ByteString B.ByteString (B.ByteString -> IO B.ByteString)
instance Validation IdentityRecord where
  type ValidationResult IdentityRecord = IO (Maybe B.ByteString)
  validate (IdentityRecord network identities digest)
    | B.length identities/=64 = pure Nothing
    | otherwise = do
        checksum <- digest prefix
        pure $ if B.length checksum/=32 then Nothing
          else Just (prefix <> C.pack "checksum=" <> display checksum <> C.pack "\n")
    where
      display = L.toStrict . toLazyByteString . B.foldr ((<>) . word8HexFixed) mempty . B.reverse
      prefix = C.pack "ecx-consensus-datadir-v3\nnetwork=" <> network <>
        C.pack "\ngenesis=" <> display (B.take 32 identities) <>
        C.pack "\nfingerprint=" <> display (B.drop 32 identities) <> C.pack "\n"

data ContextPresence = ContextPresence Word32 Word32
instance Validation ContextPresence where
  type ValidationResult ContextPresence = Int32
  validate (ContextPresence count required)
    | required == 0 || count > required = -1
    | count == 0 = 0
    | count == required = 1
    | otherwise = 2

-- Native serializers provide presence bytes and little-endian scalars; only the
-- fork's cache layout is defined here. Hashing and the inherited key stay native.
data ScriptCacheEncoding = ScriptCacheEncoding Bool B.ByteString
instance Validation ScriptCacheEncoding where
  type ValidationResult ScriptCacheEncoding = Maybe B.ByteString
  validate (ScriptCacheEncoding endpointOnly input) = do
    (authenticated, body) <- if endpointOnly then pure (0,input) else B.uncons input
    guard (authenticated <= 1)
    (fields, trailing) <- optionals (if endpointOnly then [80] else replicate 20 32 ++ replicate 7 8 ++ [80]) body
    guard (B.null trailing)
    let bytes n = snd (fields !! n)
        presence indices = B.singleton . fromIntegral . validate $
          ContextPresence (fromIntegral (length (filter (fst . (fields !!)) indices))) (fromIntegral (length indices))
        scalar n = B.reverse (bytes (20+n))
        endpoint n = B.pack
          [0x9f,0xa5,0xb4,0x11,0x85,0xf7,0x39,0x1f,0xfd,0xa6,0x3b,0x6b,0xb1,0x4b,0xa7,0x9b,
           0x13,0x8f,0x46,0x39,0x6b,0xca,0x42,0xb7,0x5e,0xfd,0xe5,0xdc,0x55,0x03,0xfe,0x26,0,1]
          <> presence [n] <> bytes n
    pure $ if endpointOnly then endpoint 0 else B.cons authenticated $ B.concat
      [wordBE 2 exchangeScriptCacheRevision,
       presence [0],bytes 0,presence [1,22],bytes 1,presence [2,23],bytes 2,
       presence [3,20,21],bytes 3,B.concat (map scalar [0..3]),
       presence [4..11],B.concat (map bytes [4..11]),
       presence [12..18],B.concat (map bytes [12..18]),
       presence [19,24,25],bytes 19,scalar 4,scalar 5,
       presence [26],scalar 6,endpoint 27]
    where
      optionals [] rest = Just ([],rest)
      optionals (width:widths) rest = do
        (tag,remaining) <- B.uncons rest
        guard (tag <= 1 && (tag == 0 || B.length remaining >= width))
        let (value,after) = if tag == 0 then (B.replicate width 0,remaining) else B.splitAt width remaining
        (values,end) <- optionals widths after
        pure ((tag == 1,value):values,end)

-- Scheme codes: Bitcoin, Elements, Liquid, Liquid testnet, select, unknown.
data PaymentUri = PaymentUri Word32 Word32
instance Validation PaymentUri where
  type ValidationResult PaymentUri = Int32
  validate (PaymentUri flags scheme)
    | flags>7 || scheme>5 = -1
    | scheme==4 = fromIntegral selected
    | scheme==5 = 0
    | scheme==selected || (selected>=2 && scheme>=2) = 1
    | otherwise = 0
    where
      selected | not (testBit flags 0) = 0
               | testBit flags 1 = 1
               | testBit flags 2 = 3
               | otherwise = 2

data AddressAlias = AddressAlias Word32 B.ByteString B.ByteString
instance Validation AddressAlias where
  type ValidationResult AddressAlias = Int32
  validate (AddressAlias flags network prefix)
    | flags > 3 = -1
    | testBit flags 0 || network /= C.pack "elements" = 0
    | prefix == C.pack (if testBit flags 1 then "el" else "ert") = 1
    | otherwise = 0

data NetworkSelection = NetworkSelection Word32 Word32 B.ByteString
instance Validation NetworkSelection where
  type ValidationResult NetworkSelection = Int32
  validate (NetworkSelection mode flags text)
    | mode > 3 || flags > 1 || (mode /= 2 && flags /= 0) = -1
    | mode == 3 = if text `elem` map C.pack [productionChainName,"liquidv1"] then 1 else 0
    | mode == 0 = if text == C.pack productionChainName then 0 else 1
    | mode == 1 = if text == C.pack "usdd" then 2 else 0
    | flags == 1 = 3
    | name == C.pack "simplicity" = 4
    | name == C.pack "dynafed" = 5
    | otherwise = 0
    where name = C.takeWhile (/= ':') text

data EvaluatorSourceFlow = EvaluatorSourceFlow Word32 Word32
instance Validation EvaluatorSourceFlow where
  type ValidationResult EvaluatorSourceFlow = Int32
  validate (EvaluatorSourceFlow phase result) = transition phase result
    [(1,(-11,2)),(2,(3,-11)),(3,(-1,-11))]

data EvaluatorIdentity = EvaluatorIdentity Word32 B.ByteString B.ByteString
instance Validation EvaluatorIdentity where
  type ValidationResult EvaluatorIdentity = Int32
  validate (EvaluatorIdentity flags catalogue program)
    | flags > 3 = -1
    | otherwise = case (validate (ConfigurationField 0 catalogue), validate (ConfigurationField 0 program)) of
        (Right _,Right _) -> if flags == 0 then 1 else 3
        _ -> 0

data ConfigurationField = ConfigurationField Word32 B.ByteString
instance Validation ConfigurationField where
  type ValidationResult ConfigurationField = Either Int B.ByteString
  validate (ConfigurationField mode text)
    | mode > 9 = Left (-1)
    -- Proposal payload is free text followed by manifest32 and source-id20.
    | mode == 9 = if B.length text < 52 || B.length text > 65526 then Left 1
        else Right (B.pack [0,8] <> C.pack "Elements" <> text)
    | mode == 7 = if B.length text==75 && C.pack "__cookie__:" `B.isPrefixOf` text
        then hex (B.drop 11 text) >> Right (B.singleton 1) else Left 1
    | mode == 8 = case C.split ':' text of
        [user,password] | B.length text<=1024 && not (B.null user) && not (B.null password) &&
          user/=C.pack "__cookie__" && B.all (\c -> c>=33 && c<=126) text -> Right (B.singleton 1)
        _ -> Left 1
    | mode == 6 = if B.length text==650 then hex text else Left 1
    | mode == 5 = if B.length text > 131072 then Left 1 else hex text
    | mode == 2 = do
        if B.length text <= 65 || B.index text 64 /= 58 then Left 1 else Right ()
        hash <- hex (B.take 64 text)
        let suffix = B.drop 65 text
            digits = if B.take 1 suffix == B.singleton 43 then B.drop 1 suffix else suffix
        if B.null digits || not (B.all (\c -> c>=48 && c<=57) digits) then Left 1 else Right ()
        let index = B.foldl' (\n c -> min 4294967296 (n*10+fromIntegral c-48)) (0 :: Word64) digits
        if index > 4294967295 then Left 1 else Right ()
        if B.all (==0) hash then Left 2 else
          Right (B.reverse hash <> L.toStrict (toLazyByteString (word32BE (fromIntegral index))))
    | mode == 3 && B.length text > 20000 =
        if even (B.length text) && B.all (either (const False) (const True) . nibble) text then Left 2 else Left 1
    | mode == 3 = do
        bytes <- hex text
        if B.length bytes > 10000 || B.head bytes == 106 then Left 2 else Right bytes
    | B.length text /= 64 = Left 1
    | otherwise = do
        bytes <- hex text
        if mode /= 0 && B.all (==0) bytes then Left 2
        else Right (if mode == 4 then B.reverse bytes else bytes)
    where
      hex bytes
        | B.null bytes || odd (B.length bytes) = Left 1
        | otherwise = B.pack <$> pairs (B.unpack bytes)
      pairs [] = Right []
      pairs (a:b:rest) = do
        high <- nibble a
        low <- nibble b
        ((high*16+low):) <$> pairs rest
      pairs _ = Left 1
      nibble :: Word8 -> Either Int Word8
      nibble c | c>=48 && c<=57 = Right (c-48)
               | c>=65 && c<=70 = Right (c-55)
               | c>=97 && c<=102 = Right (c-87)
               | otherwise = Left 1

data FeeAsset = FeeAsset (Maybe B.ByteString) B.ByteString Bool
instance Validation FeeAsset where
  type ValidationResult FeeAsset = Either Int B.ByteString
  validate (FeeAsset configured pegged canonical)
    | B.length pegged /= 32 = Left (-1)
    | otherwise = case configured of
        Nothing -> Right pegged
        Just text -> do
          requested <- B.reverse <$> validate (ConfigurationField 0 text)
          if canonical && requested /= pegged then Left 2 else Right requested

-- Encode a terminal diagnostic action with failure status 1.
flowFailure :: Int32 -> Int32
flowFailure action = 65536 + 256 + action

-- Issuance verification may itself use Haskell after this transition returns.
data ConsensusFlow
  = SuccessorScanFlow Word32 Word32
  | IncrementalScanFlow Word32 Word32
  | ExpectedContextFlow Word32 Word32
  | HeaderLifecycleFlow Bool Word32 Word32
  | HeaderFlow Word32 Word32 Word32
  | CapitalContextFlow Bool Word32 Word32
  | ActivationPredecessorFlow Word32 Word32
  | ActivationPolicyFlow Word32 Word32
  | GenesisAdmissionFlow Word32 Word32
  | SingletonRecoveryFlow Word32 Word32
  | DisconnectPreflightFlow Word32 Word32
  | ConnectionPreflightFlow Word32 Word32
instance Validation ConsensusFlow where
  type ValidationResult ConsensusFlow = Int32
  validate (SuccessorScanFlow phase result) = transition phase result
    [(1,(7,2)),(2,(6,3)),(3,(6,4)),(4,(6,5)),(5,(8,-11)),(6,(-1,1)),
     (7,(-12,9)),(8,(-1,6)),(9,(-12,10)),(10,(-13,11)),(11,(-13,12)),(12,(-13,-10))]

  validate (IncrementalScanFlow phase result) = transition phase result $
    [(step,(-11,fromIntegral step+1)) | step <- [1..8]] ++ [(9,(-11,10))] ++
    [(step,(20,fromIntegral step+1)) | step <- [10..13]] ++
    [(14,(18,15)),(15,(18,16)),(16,(18,19)),(18,(-1,20)),(19,(-1,20)),(20,(-1,9))]

  validate (ExpectedContextFlow phase result) = transition phase result
    [(1,(10,2)),(2,(-1,3)),(3,(-10,4)),(4,(-10,5)),(5,(9,6)),(6,(9,7)),
     (7,(-1,23)),(9,(-10,-10)),(10,(-10,11)),(11,(30,12)),(12,(30,13)),
     (13,(30,14)),(14,(-10,15)),(15,(-10,16)),(16,(-10,17)),(17,(-10,18)),
     (18,(29,19)),(19,(29,20)),(20,(29,21)),(21,(29,22)),(22,(29,-11)),
     (23,(28,24)),(24,(28,-11)),(28,(-10,-10)),(29,(-10,-10)),(30,(-10,-10))]

  validate (HeaderLifecycleFlow preparation phase result) = transition phase result
    [(1,(2,3)),(2,(-10,-11)),(3,(-10,4)),(4,(-10,5)),
     (5,(if preparation then -10 else -11,6)),(6,(-10,-11))]

  validate (HeaderFlow mode phase result)
    | mode>2 = -1
    | otherwise = transition phase result
        [(step,(-11,if step==count then -10 else fromIntegral step+1)) | step <- [1..count]]
    where count = [11,8,6] !! fromIntegral mode

  validate (CapitalContextFlow incremental phase result)
    | phase==0 = if incremental then 7 else 1
    | otherwise = transition phase result
        [(step,(failure step,next step)) | step <- [start..start+5] ++ [13..if incremental then 16 else 17]]
    where
      start = if incremental then 7 else 1
      failure step | step<=start+1 = -11
                   | step==start+2 = -12
                   | otherwise = -13
      next step | step==(if incremental then 16 else 17) = -10
                | step==start+5 = 13
                | otherwise = fromIntegral step+1

  validate (ActivationPredecessorFlow phase result) = transition phase result
    [(step,(if step<=8 then -11 else -12,if step==10 then -10 else fromIntegral step+1)) | step <- [1..10]]

  validate (ActivationPolicyFlow phase result) = transition phase result
    [(step,(-11,if step==14 then -10 else fromIntegral step+1)) | step <- [1..14]]

  -- Native actions run between resumptions, so nested Haskell validators are safe.
  validate (GenesisAdmissionFlow phase result) = transition phase result $
    [(1,(-11,2)),(2,(flowFailure 65,3)),(3,(5,4)),(4,(flowFailure 66,5)),(5,(-1,6))] ++
    checks 6 14 67 ++ checks 15 22 68 ++
    [(23,(flowFailure 69,24)),(24,(25,26))] ++ checks 25 40 70 ++
    [(41,(flowFailure 71,42)),(42,(-1,43))] ++ checks 43 53 72 ++
    [(54,(-11,55)),(55,(flowFailure 73,56))] ++ checks 56 63 74 ++ [(64,(-1,-10))]
    where
      checks first lastStep errorAction = [(step,(flowFailure errorAction,fromIntegral step+1)) | step <- [first..lastStep]]

  validate (SingletonRecoveryFlow phase result) = transition phase result
    [(1,(7,2)),(2,(6,3)),(3,(6,4)),(4,(9,5)),(5,(-1,7)),
     (6,(-1,1)),(7,(10,8)),(8,(11,-11)),(9,(-10,-10)),
     (10,(-10,-10)),(11,(-10,-10))]

  validate (DisconnectPreflightFlow phase result) = transition phase result
    [(1,(-11,2)),(2,(5,3)),(3,(6,4)),(4,(5,6)),(5,(-10,-10)),
     (6,(-1,7)),(7,(-10,8)),(8,(9,10)),(9,(-10,-10)),
     (10,(-10,11)),(11,(-10,12)),(12,(14,13)),(13,(14,15)),(14,(-10,-10)),
     (15,(-12,16)),(16,(-10,-11))]

  validate (ConnectionPreflightFlow phase result) = transition phase result
    [(1,(-10,2)),(2,(-11,3)),(3,(6,4)),(4,(5,-12)),(5,(-10,-10)),
     (6,(13,7)),(7,(8,17)),(8,(12,9)),(9,(12,10)),(10,(12,11)),
     (11,(12,17)),(12,(-10,-10)),(13,(14,17)),(14,(16,15)),
     (15,(-10,-10)),(16,(-10,-10)),(17,(-1,-12))]

data ParentReportFlow = ParentReportFlow Word32 Word32
instance Validation ParentReportFlow where
  type ValidationResult ParentReportFlow = Int32
  validate (ParentReportFlow phase result)
    | phase == 9 = if result == 0 then 10 else 11
    | phase == 12 = if result == 0 then 14 else 13
    | otherwise = transition phase result
        [(1,(5,2)),(2,(3,4)),(3,(-1,-1)),(4,(-1,12)),(5,(8,6)),
         (6,(7,12)),(7,(-1,-1)),(8,(7,9)),(10,(-1,-1)),(11,(-1,12)),
         (13,(14,-11)),(14,(-1,-1))]

data ExportSnapshotFlow = ExportInitialize Word32 Word32 | ExportRecheck Word32 Word32
instance Validation ExportSnapshotFlow where
  type ValidationResult ExportSnapshotFlow = Int32
  validate (ExportInitialize phase result) = transition phase result
    [(1,(3,2)),(2,(-1,-11)),(3,(4,5)),(4,(-1,-1)),(5,(-1,-11))]
  validate (ExportRecheck phase result) = transition phase result
    [(1,(-10,2)),(2,(3,-11)),(3,(-1,-1))]

data CapitalReportFlow = CapitalReportFlow Word32 Word32
instance Validation CapitalReportFlow where
  type ValidationResult CapitalReportFlow = Int32
  validate (CapitalReportFlow phase result)
    | phase == 4 = if result == 4 then 5 else 11
    | phase == 7 = if result < fromIntegral (length capitalModes) then 8 else 11
    | phase == 8 = if result < fromIntegral (length oracleModes) then 9 else 11
    | phase == 9 = if result <= 1 then 10 else 11
    | otherwise = transition phase result
        [(1,(-10,2)),(2,(3,4)),(3,(-1,-1)),
         (5,(11,6)),(6,(11,7)),(10,(11,-11)),(11,(-1,-1))]

data CapitalDecodeFlow = CapitalDecodeFlow Word32 Word32
instance Validation CapitalDecodeFlow where
  type ValidationResult CapitalDecodeFlow = Int32
  validate (CapitalDecodeFlow phase result) = transition phase result
    [(1,(-10,2)),(2,(3,4)),(3,(-10,-10)),(4,(5,6)),
     (5,(-10,-10)),(6,(7,8)),(7,(-10,-10)),(8,(-1,-11))]

data CapitalConnectionFlow = CapitalConnectionFlow Word32 Word32
instance Validation CapitalConnectionFlow where
  type ValidationResult CapitalConnectionFlow = Int32
  validate (CapitalConnectionFlow phase result) = transition phase result
    [(1,(-11,2)),(2,(-11,3)),(3,(4,5)),(4,(-10,-1)),
     (5,(10,6)),(6,(9,7)),(7,(9,8)),(8,(-1,9)),(9,(-1,5)),
     (10,(11,12)),(11,(-10,-1)),(12,(13,-11)),(13,(-1,-11))]

data CapitalProjectionFlow = CapitalProjectionFlow Word32 Word32
data BondTreeFlow = BondTreeFlow Word32 Word32
instance Validation BondTreeFlow where
  type ValidationResult BondTreeFlow = Int32
  validate (BondTreeFlow phase result) = transition phase result
    [(1,(-1,2)),(2,(6,3)),(3,(-1,4)),(4,(-1,5)),(5,(-1,-10)),(6,(-1,-10))]

instance Validation CapitalProjectionFlow where
  type ValidationResult CapitalProjectionFlow = Int32
  validate (CapitalProjectionFlow phase result) = transition phase result $
    [(1,(-11,2)),(2,(flowFailure 36,3)),(3,(7,4)),(4,(flowFailure 37,5)),(5,(-11,6)),(6,(-11,-10)),
     (7,(flowFailure 38,8)),(8,(12,9)),(9,(-1,10)),(10,(flowFailure 39,11)),(11,(-11,-10))] ++
    checks 12 14 40 ++ [(15,(-11,16)),(16,(30,17)),(17,(flowFailure 41,18))] ++
    checks 18 21 42 ++ [(22,(-11,23))] ++ checks 23 24 43 ++
    [(25,(flowFailure 44,26))] ++ checks 26 27 45 ++
    [(28,(-1,29)),(29,(-11,-10)),(30,(32,31)),(31,(-11,33)),(32,(-11,34)),
     (33,(-1,34)),(34,(-1,35)),(35,(-11,-10))]
    where
      checks first lastStep errorAction = [(step,(flowFailure errorAction,fromIntegral step+1)) | step <- [first..lastStep]]

data HashArguments = HashArguments Bool (Word32 -> IO B.ByteString) (Word32 -> B.ByteString -> IO ())
instance Validation HashArguments where
  type ValidationResult HashArguments = IO Int
  validate (HashArguments direct readText publish) = parse 0
    where
      parse 22 = pure 0
      parse index = do
        text <- readText index
        case validate (ConfigurationField (if direct && index>=13 && index<=18 then 0 else 1) text) of
          Left code -> pure (4*(fromIntegral index+1)+code)
          Right bytes -> publish index bytes >> parse (index+1)

data ConfigurationCovenants = ConfigurationCovenants Word32 Word32
instance Validation ConfigurationCovenants where
  type ValidationResult ConfigurationCovenants = Int32
  validate (ConfigurationCovenants phase result) = transition phase result $
    [(step,(failure,if step==18 then -10 else fromIntegral step+1)) | step <- [1..18],
      let failure | step `elem` [2,3] = flowFailure 19
                  | step `elem` [4,6,8,10] = flowFailure 20
                  | step==12 = flowFailure 21
                  | step==16 = flowFailure 22
                  | otherwise = if step==18 then -10 else fromIntegral step+1]

data ConfigurationTransactions = ConfigurationTransactions Word32 Word32
instance Validation ConfigurationTransactions where
  type ValidationResult ConfigurationTransactions = Int32
  validate (ConfigurationTransactions phase result)
    | phase == 4 = if result == 2 || result == 3 then 5 else flowFailure 11
    | otherwise = transition phase result
        [(1,(flowFailure 10,2)),(2,(flowFailure 10,3)),(3,(4,4)),
         (5,(flowFailure 12,6)),(6,(flowFailure 12,7)),(7,(8,8)),
         (8,(-10,9)),(9,(flowFailure 13,-10))]

data ConfigurationBindingFlow = ConfigurationBindingFlow Word32 Word32
instance Validation ConfigurationBindingFlow where
  type ValidationResult ConfigurationBindingFlow = Int32
  validate (ConfigurationBindingFlow phase result) = transition phase result
    [(step,(flowFailure (if step==1 then 9 else 10),if step==8 then -10 else fromIntegral step+1)) | step <- [1..8]]

data MaterialName = MaterialName Bool B.ByteString
instance Validation MaterialName where
  type ValidationResult MaterialName = Bool
  validate (MaterialName chainstates name)
    | chainstates = C.pack "chainstate" `B.isPrefixOf` name
    | otherwise = any (\prefix -> C.pack prefix `B.isPrefixOf` name) ["blk","rev"] &&
        C.pack ".dat" `B.isSuffixOf` name

data MaterialScanFlow = MaterialScanFlow Word32 Word32
instance Validation MaterialScanFlow where
  type ValidationResult MaterialScanFlow = Int32
  validate (MaterialScanFlow phase result) = transition phase result
    [(1,(-10,2)),(2,(-1,3)),(3,(-10,4)),(4,(7,5)),(5,(7,6)),(6,(7,-11)),(7,(-1,3))]

data MaterialLocationsFlow = MaterialLocationsFlow Word32 Word32
instance Validation MaterialLocationsFlow where
  type ValidationResult MaterialLocationsFlow = Int32
  validate (MaterialLocationsFlow phase result) = transition phase result
    [(step,(if step==5 then -10 else fromIntegral step+1,-11)) | step <- [1..5]]

newtype IdentityWrite = IdentityWrite (Word32 -> IO Int32)
instance Validation IdentityWrite where
  type ValidationResult IdentityWrite = IO Int32
  validate (IdentityWrite perform) = run 1
    where
      run action = do
        result <- perform action
        if result<0 || result>1 then pure (-1) else
          case validate (IdentityWriteFlow action (fromIntegral result)) of
            -10 -> pure 0
            -11 -> pure 1
            next | next>0 && next<=12 -> run (fromIntegral next)
                 | otherwise -> pure (-1)

data IdentityWriteFlow = IdentityWriteFlow Word32 Word32
instance Validation IdentityWriteFlow where
  type ValidationResult IdentityWriteFlow = Int32
  validate (IdentityWriteFlow phase result) = transition phase result
    [(1,(2,3)),(2,(-1,-10)),(3,(5,4)),(4,(5,7)),(5,(-1,6)),
     (6,(-1,-10)),(7,(8,9)),(8,(-1,-10)),(9,(10,11)),
     (10,(-1,-10)),(11,(-1,12)),(12,(-1,-11))]

data IdentityCoinsFlow = IdentityCoinsFlow Word32 Word32
instance Validation IdentityCoinsFlow where
  type ValidationResult IdentityCoinsFlow = Int32
  validate (IdentityCoinsFlow phase result) = transition phase result
    [(1,(-11,2)),(2,(3,4)),(3,(5,4)),(4,(-1,-10)),(5,(-10,6)),
     (6,(-1,7)),(7,(10,8)),(8,(-10,9)),(9,(-1,7)),(10,(-1,1))]

data IdentityHistoryFlow = IdentityHistoryFlow Bool Word32 Word32
instance Validation IdentityHistoryFlow where
  type ValidationResult IdentityHistoryFlow = Int32
  validate (IdentityHistoryFlow ancestry phase result)
    | phase==0 = if ancestry then 1 else 3
    | otherwise = transition phase result
        [(1,(2,-11)),(2,(10,3)),(3,(if ancestry then 8 else -11,4)),
         (4,(5,11)),(5,(if ancestry then 7 else 8,11)),(7,(-1,3)),
         (8,(if ancestry then -11 else 7,12)),(10,(-1,-10)),(11,(-1,-10)),(12,(-1,-10))]

data IdentityAuditFlow = IdentityAuditFlow Word32 Word32
instance Validation IdentityAuditFlow where
  type ValidationResult IdentityAuditFlow = Int32
  validate (IdentityAuditFlow phase result) = transition phase result
    [(1,(9,2)),(2,(8,3)),(3,(4,5)),(4,(-1,-10)),(5,(6,7)),
     (6,(-1,-10)),(7,(-1,8)),(8,(-1,1)),(9,(-1,-11))]

data IdentityBindingFlow = IdentityBindingFlow Word32 Word32
instance Validation IdentityBindingFlow where
  type ValidationResult IdentityBindingFlow = Int32
  validate (IdentityBindingFlow phase result) = transition phase result
    [(1,(-10,2)),(2,(-11,3)),(3,(4,-11)),(4,(7,5)),(5,(-10,6)),
     (6,(-10,-11)),(7,(8,10)),(8,(10,9)),(9,(-1,-10)),
     (10,(-10,11)),(11,(-10,13)),(12,(-10,-11)),(13,(-10,12))]

data IdentityFileFlow = IdentityFileFlow Bool Word32 Word32
instance Validation IdentityFileFlow where
  type ValidationResult IdentityFileFlow = Int32
  validate (IdentityFileFlow reset phase result)
    | phase == 0 = if reset then 1 else 3
    | otherwise = transition phase result
        [(1,(-11,2)),(2,(3,-11)),(3,(-10,4)),(4,(-11,5)),
         (5,(6,if reset then 14 else 9)),(6,if reset then (-11,15) else (8,7)),
         (7,(-11,13)),(8,(-10,-11)),(9,(10,11)),(10,(-1,-10)),
         (11,(12,-11)),(12,(-1,-10)),(13,(-1,-10)),(14,(-10,-11)),(15,(-1,-10))]

data StartupDeploymentFlow = StartupDeploymentFlow Word32 Word32
instance Validation StartupDeploymentFlow where
  type ValidationResult StartupDeploymentFlow = Int32
  validate (StartupDeploymentFlow phase result) = transition phase result $
    checks 1 5 54 ++ [(6,(-11,7))] ++ checks 7 9 55 ++ [(10,(-11,11)),(11,(12,18))] ++
    checks 12 17 56 ++ checks 18 23 57 ++ [(24,(-11,25))] ++ checks 25 30 58 ++
    [(31,(-11,32))] ++ checks 32 36 59 ++ checks 37 37 60 ++ [(38,(-11,39))] ++
    checks 39 39 61 ++ checks 40 44 62 ++ checks 45 52 63 ++ [(53,(flowFailure 64,-10))]
    where
      checks first lastStep errorAction=[(step,(flowFailure errorAction,fromIntegral step+1)) | step <- [first..lastStep]]

data FrozenAdmissionFlow = FrozenAdmissionFlow Word32 Word32
instance Validation FrozenAdmissionFlow where
  type ValidationResult FrozenAdmissionFlow = Int32
  validate (FrozenAdmissionFlow phase result) = transition phase result
    [(1,(-11,2)),(2,(7,3)),(3,(-11,4)),(4,(flowFailure 12,5)),(5,(7,6)),
     (6,(flowFailure 13,7)),(7,(-11,8)),(8,(flowFailure 14,9)),(9,(flowFailure 15,10)),
     (10,(-11,11)),(11,(-11,-10))]

data ReservedInputsFlow = ReservedInputsFlow Word32 Word32
instance Validation ReservedInputsFlow where
  type ValidationResult ReservedInputsFlow = Int32
  validate (ReservedInputsFlow phase result) = transition phase result
    [(1,(-10,2)),(2,(-10,3)),(3,(4,7)),(4,(5,-11)),
     (5,(6,-12)),(6,(7,-12)),(7,(-1,2))]

data ExplicitCreationsFlow = ExplicitCreationsFlow Word32 Word32
instance Validation ExplicitCreationsFlow where
  type ValidationResult ExplicitCreationsFlow = Int32
  validate (ExplicitCreationsFlow phase result) = transition phase result
    [(1,(6,2)),(2,(-11,3)),(3,(-11,4)),(4,(-11,5)),(5,(-1,1)),
     (6,(12,7)),(7,(8,9)),(8,(-11,9)),(9,(10,11)),(10,(-11,11)),(11,(-1,6)),
     (12,(16,13)),(13,(-11,14)),(14,(-11,15)),(15,(-1,12)),
     (16,(-10,17)),(17,(-11,18)),(18,(-11,19)),(19,(-1,16))]

data PublicIssuanceFlow = PublicIssuanceFlow Word32 Word32
instance Validation PublicIssuanceFlow where
  type ValidationResult PublicIssuanceFlow = Int32
  validate (PublicIssuanceFlow phase result) = transition phase result $
    [(step,(-11,fromIntegral step+1)) | step <- [1..23]] ++
    [(24,(-10,25)),(25,(28,26)),(26,(29,27)),(27,(-1,24)),
     (28,(-11,26)),(29,(-11,27))]

data IssuanceFlow = IssuanceFlow Bool Word32 Word32
instance Validation IssuanceFlow where
  type ValidationResult IssuanceFlow = Int32
  validate (IssuanceFlow opening phase result) = transition phase result
    [(step,(-11,if step==count then -10 else fromIntegral step+1)) | step <- [1..count]]
    where count = if opening then 17 else 8

-- Resume after each native action; marker verification may itself use Haskell.
data SourceTransactionFlow = SourceTransactionFlow Word32 Word32
instance Validation SourceTransactionFlow where
  type ValidationResult SourceTransactionFlow = Int32
  validate (SourceTransactionFlow phase result) = transition phase result
    [(1,(12,2)),(2,(11,3)),(3,(-10,4)),(4,(-10,5)),(5,(-10,6)),
     (6,(8,7)),(7,(-10,9)),(8,(-10,9)),(9,(-10,10)),(10,(-10,11)),
     (11,(-1,1)),(12,(-10,-11))]

data BlockSourcesFlow = BlockSourcesFlow Word32 Word32
instance Validation BlockSourcesFlow where
  type ValidationResult BlockSourcesFlow = Int32
  validate (BlockSourcesFlow phase result) = transition phase result
    [(1,(11,2)),(2,(10,3)),(3,(-10,4)),(4,(-10,5)),(5,(-10,6)),
     (6,(10,7)),(7,(9,8)),(8,(-10,9)),(9,(-1,6)),(10,(-1,1)),(11,(-1,-11))]

data SourcePredecessor = SourcePredecessor [Word64] B.ByteString
instance Validation SourcePredecessor where
  type ValidationResult SourcePredecessor = Either Int B.ByteString
  validate (SourcePredecessor [profile,proof,height,parent,_,_,_] input)
    | profile > 1 || B.length input /= 64 = Left (-1)
    | (profile == 1 && proof /= 1) || height == 0 || parent == 0 ||
      B.all (==0) (B.take 32 input) || B.take 16 (B.drop 32 input) < B.drop 48 input = Left 1
    | profile == 0 && B.any (/=0) (B.take 8 (B.drop 32 input)) = Left 2
    | otherwise = Right (B.take 48 input)
  validate _ = Left (-1)

-- Native effects are limited to publishing an entry and hashing byte strings.
-- In particular, source verification must finish before entering this workflow.
data AppendMarker = AppendMarker [Word64] B.ByteString (Word32 -> B.ByteString -> IO B.ByteString)
instance Validation AppendMarker where
  type ValidationResult AppendMarker = IO (Either Int B.ByteString)
  validate (AppendMarker fields input effect) = case fields of
    [profile,parent,_,_,_,_,_,_,count,tx,vout,height,txSize,witnessSize]
      | B.length input == 683 -> case validate (MarkerBounds (take 11 fields)) of
          (0,[_,deadline]) -> case validate (MarkerFrame wide (B.drop 176 input)) of
            Nothing -> pure (Left 4)
            Just payload -> case validate (BondEntry wide [count,height,parent,txSize,witnessSize,tx,vout]
                (B.take 160 input <> (if wide then counter else B.empty) <> B.drop 4 payload)) of
              Nothing -> pure (Left (-1))
              Just entry -> do
                _ <- effect 0 (encode deadline <> entry)
                entryHash <- digest 1 entry
                case validate (InboxStep wide count (B.take 32 input <> entryHash <> if wide then counter else B.empty)) of
                  Nothing -> pure (Left (-1))
                  Just step -> do
                    root <- digest 2 step
                    let next = if wide then increment (B.unpack counter) else Just (replicate 8 0 ++ B.unpack (encode (count+1)))
                    pure $ maybe (Left 5) (Right . (root <>) . B.pack) next
          (code,_) -> pure (Left code)
      where
        wide = profile == 1
        counter = B.take 16 (B.drop 160 input)
        encode = L.toStrict . toLazyByteString . word64BE
        digest tag bytes = do
          result <- effect tag bytes
          if B.length result == 32 then pure result else ioError (userError "invalid append digest")
        increment [] = Nothing
        increment bytes = let (front,lastByte) = (init bytes,last bytes) in
          if lastByte == 255 then (++ [0]) <$> increment front else Just (front ++ [lastByte+1])
    _ -> pure (Left (-1))

data CustodyRoot = CustodyRoot Word64 B.ByteString B.ByteString (Word32 -> B.ByteString -> IO B.ByteString)
class DigestEffects op where
  digestBytes :: op -> Word32 -> B.ByteString -> IO B.ByteString
instance DigestEffects CustodyRoot where
  digestBytes (CustodyRoot _ _ _ hashBytes) = hashBytes

checkedDigest :: DigestEffects op => op -> Word32 -> B.ByteString -> IO B.ByteString
checkedDigest value kind bytes = do
  digest <- digestBytes value kind bytes
  if B.length digest == 32 then pure digest else ioError (userError "invalid custody hash length")

instance Validation CustodyRoot where
  type ValidationResult CustodyRoot = IO (Maybe B.ByteString)
  validate value@(CustodyRoot bundle identities receipts _)
    | bundle > 4294967295 || B.length identities /= 192 || B.length receipts > 690 || B.length receipts `mod` 138 /= 0 = pure Nothing
    | otherwise = Just <$> do
        leaves <- forM (chunks 138 receipts) $ \receipt -> do
          binding <- hash 0 (B.take 128 identities <> be32 bundle <> B.drop 128 identities <> B.singleton (B.index receipt 73-1))
          hash 1 (binding <> be32 138 <> receipt)
        if null leaves then hash 2 B.empty else do
          nodes <- zipWithM (\index leaf -> hash 3 (encode (word64BE index) <> leaf)) [0..] leaves
          padding <- hash 4 B.empty
          let width = until (>= length nodes) (*2) 1
          tree (nodes ++ replicate (width-length nodes) padding)
    where
      encode = L.toStrict . toLazyByteString
      be32 = encode . word32BE . fromIntegral
      chunks n bytes | B.null bytes = []
                     | otherwise = let (front,rest) = B.splitAt n bytes in front : chunks n rest
      hash = checkedDigest value
      tree [root] = pure root
      tree nodes = pairs nodes >>= tree
      pairs [] = pure []
      pairs (left:right:rest) = (:) <$> hash 5 (left <> right) <*> pairs rest
      pairs _ = ioError (userError "invalid custody tree width")

data AnnexHeader = AnnexHeader Word64 Word64 Word64 B.ByteString
instance Validation AnnexHeader where
  type ValidationResult AnnexHeader = Either Int [Word64]
  validate (AnnexHeader expected limit size header)
    | size < 15 || B.length header /= 15 || B.take 10 header /= B.pack [80,69,67,88,66,73,78,50,0,1] = Left 1
    | bundle == 0 || bundle /= expected || bundle > limit || count < 3 || count > 5 || bundle > size-15 = Left 2
    | otherwise = Right [bundle,count]
    where
      bundle = readBE (B.take 4 (B.drop 10 header))
      count = fromIntegral (B.index header 14)

newtype SourceAdmission = SourceAdmission (Word64 -> IO Word64)
instance Validation SourceAdmission where
  type ValidationResult SourceAdmission = IO Int
  validate (SourceAdmission readFact) = go 0
    where
      expected = replicate 5 1 ++ [65536,8,589824,786432] ++ replicate 5 1
      go 16 = pure 0
      go step = do
        value <- readFact step
        let valid = if step < 14 then value == expected !! fromIntegral step
                    else value > 0 && value <= (if step == 14 then 786432 else 589824)
            failure = if step < 9 then 1 else if step < 14 then 2 else fromIntegral step-11
        if valid then go (step+1) else pure failure

data CustodyReceipts = CustodyReceipts Int B.ByteString
instance Validation CustodyReceipts where
  type ValidationResult CustodyReceipts = Either Int B.ByteString
  validate (CustodyReceipts count input)
    | count < 3 || count > 5 = Left (-1)
    | otherwise = walk count 0 0 input
    where
      walk 0 _ bitmap bytes = if B.null bytes then Right (B.singleton bitmap) else Left 4
      walk remaining previous bitmap bytes
        | B.length bytes < 2 = Left 1
        | B.take 2 bytes /= B.pack [0,138] || B.length bytes < 140 = Left 2
        | B.head receipt /= 1 || signer < 1 || signer > 5 || signer <= previous = Left 3
        | otherwise = (receipt <>) <$> walk (remaining-1) signer (setBit bitmap (fromIntegral signer-1)) (B.drop 140 bytes)
        where
          receipt = B.take 138 (B.drop 2 bytes)
          signer = B.index receipt 73

data BondMarker = BondMarker Word64 B.ByteString B.ByteString
instance Validation BondMarker where
  type ValidationResult BondMarker = Int
  validate (BondMarker limit payload identities)
    | B.length payload /= 503 || B.length identities /= 128 = -1
    | B.concat (map (part 32) [6,38,242,274]) /= identities || kind > 3 ||
      any zero [70,102,210,306,370,407] || bundle == 0 || bundle > limit || bitmap > 31 || popCount bitmap < 3 = 1
    | if kind == 1 then not hasStaging else not noStaging = 2
    | otherwise = 0
    where
      part n offset = B.take n (B.drop offset payload)
      zero = B.all (==0) . part 32
      kind = B.index payload 5
      bundle = readBE (part 4 402)
      bitmap = B.index payload 406
      sentinel = readBE (part 4 166) == 4294967295
      refund = readBE (part 8 202)
      hasStaging = not sentinel && not (zero 134) && not (zero 170) && refund /= 0
      noStaging = sentinel && zero 134 && zero 170 && refund == 0

data GenesisFunding = GenesisFunding Word64 Word64
data InboxEntry = InboxEntry Bool [Word64] B.ByteString | InboxStep Bool Word64 B.ByteString
               | BondEntry Bool [Word64] B.ByteString | MarkerContext B.ByteString | MarkerFrame Bool B.ByteString
               | LegacyMarkerFrame Bool B.ByteString
               | CursorPayload B.ByteString
               | SourceAuthorization Bool Word64 B.ByteString
               | RegistryEncoding B.ByteString
               | StagingEncoding Bool Word64 Word64 B.ByteString
               | DeploymentEncoding [Word64] B.ByteString
instance Validation InboxEntry where
  type ValidationResult InboxEntry = Maybe B.ByteString
  validate (InboxEntry deposit [count,height,parent,vout,extra] input)
    | B.length input < 96 || (deposit && B.length input /= 160) ||
      vout > 4294967295 || extra > (if deposit then 4294967295 else 255) = Nothing
    | otherwise = Just . L.toStrict . toLazyByteString $
        word8 1 <> field 0 <> word64BE count <> field 1 <>
        word64BE height <> word64BE parent <> field 2 <> word32BE (fromIntegral vout) <>
        (if deposit then word32BE (fromIntegral extra) else word8 (fromIntegral extra)) <>
        byteString (B.drop 96 input)
    where field n = byteString (B.take 32 (B.drop (n*32) input))
  validate (InboxStep wide count input)
    | B.length input /= (if wide then 80 else 64) = Nothing
    | otherwise = Just . L.toStrict . toLazyByteString $
        byteString (B.take 32 input) <>
        (if wide then byteString (B.drop 64 input) else word64BE count) <>
        byteString (B.take 32 (B.drop 32 input))
  validate (BondEntry wide [count,height,parent,txLength,witnessLength,txIndex,vout] input)
    | B.length input /= (if wide then 675 else 659) || any (>4294967295) [txLength,witnessLength,txIndex,vout] = Nothing
    | otherwise = Just . L.toStrict . toLazyByteString $
        word8 (if wide then 2 else 1) <>
        (if wide then byteString (B.take 16 (B.drop 160 input)) else word64BE count) <>
        field 0 <> word64BE height <> word64BE parent <> field 1 <> field 2 <> field 3 <>
        word32BE (fromIntegral txLength) <> field 4 <>
        foldMap (word32BE . fromIntegral) [witnessLength,txIndex,vout] <>
        byteString (B.drop (if wide then 176 else 160) input)
    where field n = byteString (B.take 32 (B.drop (32*n) input))
  validate (MarkerContext input)
    | B.length input /= 503 = Nothing
    | otherwise = Just (B.concat [part 6 64,part 102 140,part 407 32])
    where part offset size = B.take size (B.drop offset input)
  validate (MarkerFrame successor input)
    | B.length input == 507 && B.take 9 input == B.pack [106,77,247,1,69,67,88,66,if successor then 3 else 1] && B.index input 9 <= 3 = Just (B.drop 4 input)
    | otherwise = Nothing
  validate (LegacyMarkerFrame forced input)
    | forced && size >= 11 && size <= 258 &&
      B.take 7 input == B.pack [106,76,fromIntegral (size-3),69,67,88,70] = Just (B.drop 3 input)
    | not forced && size == depositPayloadSize+2 && B.take 6 input == B.pack [106,fromIntegral depositPayloadSize,69,67,88,68] = Just (B.drop 2 input)
    | otherwise = Nothing
    where size = B.length input
  validate (CursorPayload input)
    | B.take 4 input /= B.pack [69,67,88,67] = result 0
    | B.length input /= 21 || B.index input 4 /= 1 = result 2
    | otherwise = Just (B.cons 1 (B.drop 5 input))
    where result status = Just (B.cons status (B.replicate 16 0))
  validate (SourceAuthorization staged value input)
    | (not staged && B.length input /= 128) || (staged && (B.length input <= 64 || toInteger (B.length input)-64 > 4294967295)) = Nothing
    | otherwise = Just . L.toStrict . toLazyByteString $ if staged then
        word32BE (fromIntegral (B.length input-64)) <> byteString (B.drop 64 input) <>
        byteString (B.take 64 input) <> word64BE value
      else byteString input <> word32BE (fromIntegral value)
  validate (RegistryEncoding input)
    | B.length input /= 320 = Nothing
    | otherwise = Just (B.concat [B.singleton (fromIntegral (i+1)) <> part (32*i) <> part (160+32*i) | i <- [0..4]])
    where part offset = B.take 32 (B.drop offset input)
  validate (StagingEncoding hidden first second input)
    | B.length input /= (if hidden then 192 else 128) ||
      first > (if hidden then 4294967295 else 255) = Nothing
    | otherwise = Just . L.toStrict . toLazyByteString $ if hidden then
        byteString (B.take 160 input) <> word32BE (fromIntegral first) <>
        byteString (B.drop 160 input) <> word64BE second
      else word8 1 <> byteString (B.take 32 input) <> word8 (fromIntegral first) <>
        byteString (B.drop 32 input)
  validate (DeploymentEncoding [version,previous,inventory,burn,_,_,_] input)
    | version `notElem` [2,3] || B.length input/=192 || any (>4294967295) [previous,inventory,burn] = Nothing
    | otherwise = Just . L.toStrict . toLazyByteString $
        word8 (if version==3 then 3 else 1) <> byteString (B.take 64 input) <>
        word32BE (fromIntegral previous) <> byteString (B.take 64 (B.drop 64 input)) <>
        word64BE bondFixedSupply <> foldMap (word32BE . fromIntegral) [inventory,burn] <>
        byteString (B.drop 128 input)
  validate _ = Nothing

instance Validation GenesisFunding where
  type ValidationResult GenesisFunding = B.ByteString
  validate (GenesisFunding mtp price) = L.toStrict . toLazyByteString $
    word8 2 <> foldMap word64BE [mtp,price,price,price,mtp,maxBound] <>
    byteString (B.replicate 20 0) <> foldMap bucket [0..7]
    where
      bucket index = word64BE maxBound <> word8 index <> byteString (B.replicate 73 0)

data GenesisRequest = GenesisRequest Word64 Word64 Word64 B.ByteString (Word32 -> B.ByteString -> IO B.ByteString)
data GenesisPlan = GenesisPlan Word64 Word64 Word64 [B.ByteString]
class GenesisEncoding op where
  planGenesis :: op -> Maybe GenesisPlan
instance GenesisEncoding GenesisRequest where
  planGenesis (GenesisRequest height mtp price input _)
    | B.length input /= 384 = Nothing
    | otherwise = Just (GenesisPlan height mtp price [B.take 32 (B.drop (32*i) input) | i <- [0..11]])
instance DigestEffects GenesisRequest where
  digestBytes (GenesisRequest _ _ _ _ hashBytes) = hashBytes

type GenesisCapabilities = '[GenesisEncoding,DigestEffects]

buildGenesisRoots :: DSL GenesisRequest
buildGenesisRoots = BuildGenesisRoots

instance Operation GenesisRequest GenesisCapabilities where
  type Context GenesisRequest = CapabilityContext GenesisCapabilities GenesisRequest
  type Outcome GenesisRequest = IO (Maybe B.ByteString)
  data DSL GenesisRequest where
    BuildGenesisRoots :: Context GenesisRequest => DSL GenesisRequest
  interpret operation request = withOperation @GenesisRequest operation $ \value -> case request of
    BuildGenesisRoots -> Just (case planGenesis value of
      Nothing -> pure Nothing
      Just plan -> Just <$> deriveGenesis value plan)

-- Hash effects are deterministic upstream digests. Retain zero-root failure
-- gates, while sharing common empty/inbox roots between the two state encodings.
deriveGenesis :: DigestEffects op => op -> GenesisPlan -> IO B.ByteString
deriveGenesis value (GenesisPlan height mtp price fields) = do
  queue <- hash 0 B.empty
  bond <- encode (GenesisState False 0 0 (B.concat (take 3 fields) <> queue))
  bondRoot <- hash 1 bond
  let funding = validate (GenesisFunding mtp price)
  fundingRoot <- hash 2 funding
  let failed = B.concat [zero,bondRoot,fundingRoot,zero]
  if B.all (==0) bondRoot || B.all (==0) fundingRoot then pure failed else do
    empty <- hash 3 B.empty
    forced <- hash 4 (field 6 <> field 3)
    deposits <- hash 5 (field 7 <> field 3)
    inbox <- hash 6 (field 8 <> field 3 <> field 9)
    outcome <- hash 7 (field 8 <> field 3 <> field 9)
    private <- encode (GenesisState True height price
      (B.concat [field 3,field 4,forced,deposits,empty,field 5,inbox,outcome,bond,funding]))
    privateRoot <- hash 8 private
    if B.all (==0) privateRoot then pure failed else do
      covenant <- encode (GenesisCovenant height
        (B.concat [field 10,privateRoot,field 11,forced,deposits,field 9,bondRoot,fundingRoot,empty,inbox,outcome]))
      covenantRoot <- hash 9 covenant
      pure (B.concat [privateRoot,bondRoot,fundingRoot,covenantRoot])
  where
    hash = checkedDigest value
    field = (fields !!)
    zero = B.replicate 32 0
    encode = maybe (ioError (userError "invalid genesis encoding")) pure . validate

-- Packed inputs: four hashes for bond state; eight hashes then 242/725-byte
-- bond/funding encodings for private state. Hashing stays in the native adapter.
data GenesisState = GenesisState Bool Word64 Word64 B.ByteString | GenesisCovenant Word64 B.ByteString
                  | TapPreimage Bool Word64 B.ByteString | FixedProfile Word32
                  | CapitalSnapshot Word32 Word64 Word64 B.ByteString
instance Validation GenesisState where
  type ValidationResult GenesisState = Maybe B.ByteString
  validate (GenesisState private height price input)
    | B.length input /= (if private then 1223 else 128) = Nothing
    | otherwise = Just . L.toStrict . toLazyByteString $ if private then
        word8 2 <> word8 4 <> field 0 <> byteString (C.pack "ECX-USDD-PERP\0\0\0") <>
        words64 [0,height,price] <> zero 88 <> field 1 <>
        foldMap (\i -> field i <> zero 8 <> field i <> zero 8) [2,3] <>
        mconcat (replicate 5 (field 4)) <> field 5 <> byteString (B.drop 256 input) <>
        words64 [0,height] <> field 6 <> zero 8 <> field 6 <> zero 8 <> field 7 <>
        zero 8 <> field 4 <> field 4
      else word8 2 <> byteString (B.take 96 input) <> zero 16 <>
        words64 [bondFixedSupply,0,bondFixedSupply] <> zero 48 <> field 3 <> zero 25
    where
      field i = byteString (B.take 32 (B.drop (i*32) input))
      zero n = byteString (B.replicate n 0)
      words64 = foldMap word64BE
  validate (GenesisCovenant height input)
    | B.length input /= 352 = Nothing
    | otherwise = Just . L.toStrict . toLazyByteString $
        field 0 <> word32BE 4 <> word64BE 0 <> byteString (B.take 224 (B.drop 32 input)) <>
        field 8 <> field 8 <> field 9 <> word64BE 0 <> field 9 <> word64BE 0 <>
        field 10 <> word64BE 0 <> word64BE 0 <> word64BE height
    where field i = byteString (B.take 32 (B.drop (i*32) input))
  validate (TapPreimage leaf version input)
    | B.length input /= (if leaf then 32 else 64) || (leaf && version > 255) = Nothing
    | leaf = Just (B.pack [fromIntegral version,32] <> input)
    | otherwise = let (left,right) = B.splitAt 32 input
                  in Just (if left < right then input else right <> left)
  validate (CapitalSnapshot profile height mtp input)
    | profile>3 || B.length input/=320+(case profile of 0 -> 850; 1 -> 1627; 2 -> 364; _ -> 168) = Nothing
    | otherwise = Just . B.concat $ B.pack [4,0,if profile==0 || profile==3 then 0 else 1] : layout
    where
      values=B.drop 320 input
      field offset width=B.take width (B.drop offset values)
      hash offset=field offset 32
      context index=B.take 32 (B.drop (32*index) input)
      zero width=B.replicate width 0
      little offset width=B.reverse (field offset width)
      scalar value=B.reverse (L.toStrict (toLazyByteString (word64BE value)))
      wide offset=zero 8 <> field offset 8
      supply=bondFixedSupply
      outstanding=readBE (field 484 8)
      initialBalances=[zero 16,scalar supply,zero 8,scalar supply,zero 48,
        zero 14 <> B.pack [0x30,0xd4],zero 1,zero 16]
      emptyInbox inbox outcome receipt=[inbox,zero 16,inbox,zero 16,outcome,zero 16,inbox,zero 16,receipt]
      layout=case profile of
        0 -> [context 0,hash 36,hash 276,hash 308,context 4,context 5,hash 100,hash 340,hash 404,context 6,
              field 468 16,scalar supply,little 484 8,scalar (supply-outstanding),
              field 492 64,field 556 1,zero 16,little 557 8,little 565 8,little 573 8,little 581 4,zero 16,
              hash 372,wide 585,wide 593,little 601 8,hash 609,little 641 8,field 649 1,hash 650,
              hash 682,wide 714,hash 722,wide 754,hash 762,wide 794,hash 682,wide 714,hash 802,
              wide 834,wide 842,zero 8,zero 1,zero 16]
        1 -> [context 0,hash 4,hash 452,hash 484,context 4,context 5,hash 68,hash 548,hash 580,hash 516,
              field 1460 16,little 1332 8,little 1340 8,little 1348 8,
              field 1508 16,field 1428 16,field 1444 16,field 1524 16,field 1624 1,field 1476 16,
              little 1308 8,little 1324 8,little 1364 8,little 1620 4,field 1380 16,
              hash 612,field 1540 16,field 1556 16,little 1356 8,hash 644,little 1372 8,field 1625 1,hash 228,
              hash 708,field 1572 16,hash 740,field 1588 16,hash 772,field 1604 16,hash 708,field 1572 16,
              hash 676,zero 16,field 1492 16,zero 8,field 1626 1,zero 16]
        2 -> [B.take 192 input,hash 132,hash 260,hash 292,context 6] ++ initialBalances ++ [
              little 348 8,little 356 8,scalar (mtp `div` 28800),zero 4,zero 16,
              context 7,zero 32,zero 8,zero 32,zero 8,zero 1,zero 32] ++
              emptyInbox (context 8) (context 9) (zero 32) ++ [zero 32,scalar height,B.singleton 1,zero 16]
        _ -> [B.take 320 input] ++ initialBalances ++ [
              little 160 8,little 160 8,scalar (mtp `div` 28800),zero 4,zero 16,
              hash 0,zero 32,zero 8,zero 32,scalar mtp,zero 1,hash 32] ++
              emptyInbox (hash 64) (hash 96) (hash 128) ++ [zero 32,scalar height,zero 1,zero 16]
  validate (FixedProfile mode) = case mode of
    5 -> Just . L.toStrict . toLazyByteString $
      byteString (C.pack "ECXWIT1\0") <> byteString (B.pack [0,1,3,5]) <> word64BE 16777216 <>
      foldMap (\name -> let bytes=C.pack name in word32BE (fromIntegral (B.length bytes)) <> byteString bytes)
        ["XChaCha20-Poly1305","HKDF-SHA256","X25519","Ristretto255-Feldman","Ed25519",
         "ECX/witness-bundle-root/v1","ECX/witness-bundle-header/v1","ECX/witness-payload-aad/v1",
         "ECX/witness-share-aad/v1","ECX/witness-payload-key/v1","ECX/witness-share-key/v1",
         "ECX/witness-custodian-attestation/v1","ECX/witness-custody-receipt/v1","ECX/witness-share-hash/v1"]
    6 -> Just (C.pack "version:u8|bundle_root:32|context:32|witness_len:u64be|custodian_index:u8(1..5)|ed25519_signature:64")
    7 -> Just . L.toStrict . toLazyByteString $
      foldMap word32BE [1000,600,100,0,5,10000] <>
      foldMap word64BE [100000000000000,1000000000000000] <> word8 0
    _ -> Nothing

-- The reader counts matching inputs in one transaction, without interpreting policy.
data DeploymentOutputs = DeploymentOutputs Word64 Word64 (Word64 -> IO Word64)
instance Validation DeploymentOutputs where
  type ValidationResult DeploymentOutputs = IO (Either Int (Maybe Word64))
  validate (DeploymentOutputs skipped count readFacts)
    | skipped>=count = pure (Left (-1))
    | otherwise = validate (SpendScan False 0 count (\index -> if index==skipped then pure 0 else do
        facts <- readFacts index
        pure $ if facts<=255 && facts .&. 7==7 && not (testBit facts 3) &&
          (not (testBit facts 4) || testBit facts 7) && (not (testBit facts 5) || not (testBit facts 6)) then 0 else 1))

data SpendScan = SpendScan Bool Word64 Word64 (Word64 -> IO Word64)
instance Validation SpendScan where
  type ValidationResult SpendScan = IO (Either Int (Maybe Word64))
  validate (SpendScan unique start end readCount)
    | start > end = pure (Left (-1))
    | otherwise = scan start Nothing
    where
      scan index found
        | index == end = pure (Right found)
        | otherwise = do
            count <- readCount index
            if count == 0 then scan (index+1) found
            else if unique && count == 1 && found == Nothing
              then scan (index+1) (Just index)
              else pure (Left 2)

data StateTransition = StateTransition Word64 (Word32 -> Word64 -> IO Word64)
instance Validation StateTransition where
  type ValidationResult StateTransition = IO Int32
  validate (StateTransition count action) = do
    selected <- validate (SpendScan True 0 count (action 1))
    case selected of
      Left code -> pure (if code == 2 then 1 else -1)
      Right Nothing -> runRequiredEffects (\step -> action step 0) [2]
      Right (Just index) -> do
        shape <- validate (TransactionShape 0 (\field -> fact (3+fromIntegral field) index))
        if shape /= 0 then pure (fromIntegral shape+1) else do
          authority <- fact 6 index
          if not authority then pure 4 else do
            published <- runRequiredEffects (\step -> action step index) [7]
            if published /= 0 then pure published else do
              remaining <- validate (SpendScan False (index+1) count (action 8))
              pure $ case remaining of
                Left 2 -> 5
                Right Nothing -> 0
                _ -> -1
    where
      fact step index = action step index >>= \value -> case value of
        0 -> pure False
        1 -> pure True
        _ -> fail "invalid state transition fact"

data IdentitySet = IdentitySet [B.ByteString] | AbsentIdentities [B.ByteString] | IsolatedIdentity [B.ByteString]
instance Validation IdentitySet where
  type ValidationResult IdentitySet = Bool
  validate rule = all ((==32) . B.length) identities && predicate identities
    where
      (identities,predicate) = case rule of
        IdentitySet values -> (values, \xs -> length (nub xs) == length xs)
        AbsentIdentities values -> (values, all (B.all (==0)))
        IsolatedIdentity values -> (values, \xs -> case xs of [] -> False; first:rest -> first `notElem` rest)

data CarryIdentities = CarryIdentities Bool [B.ByteString]
instance Validation CarryIdentities where
  type ValidationResult CarryIdentities = Bool
  validate (CarryIdentities incremental identities) =
    length identities==15 && all ((==32) . B.length) identities &&
    take 3 identities==take 3 (drop (if incremental then 9 else 6) identities) &&
    take 3 (drop 3 identities)==drop 12 identities

data DeploymentIdentities = DeploymentIdentities Bool [B.ByteString]
instance Validation DeploymentIdentities where
  type ValidationResult DeploymentIdentities = Int
  validate (DeploymentIdentities direct identities)
    | length identities /= 22 || any ((/=32) . B.length) identities = -1
    | not (validate (IdentitySet (take 3 identities))) = 1
    | proof /= 0 = proof+1
    | not (validate (IdentitySet (zero:take 9 (drop 8 identities)))) = 4
    | not (validate (IsolatedIdentity (identities !! 17:zero:drop 18 identities))) = 5
    | otherwise = 0
    where
      zero = B.replicate 32 0
      proof = validate (ProofIdentities (take (if direct then 3 else 5) (drop 3 identities)))

data FrozenIdentityGroups = FrozenIdentityGroups Bool [B.ByteString]
instance Validation FrozenIdentityGroups where
  type ValidationResult FrozenIdentityGroups = Int
  validate (FrozenIdentityGroups direct identities)
    | length identities/=22 || any ((/=32) . B.length) identities = -1
    | not (validate (IdentitySet (take 3 identities))) = 1
    | not (validate (IdentitySet (take (if direct then 3 else 5) (drop 3 identities)))) = 2
    | not (validate (IdentitySet (take 9 (drop 8 identities)))) = 3
    | not (validate (IsolatedIdentity (drop 17 identities))) = 4
    | otherwise = 0

newtype RuntimeIdentities = RuntimeIdentities [B.ByteString]
instance Validation RuntimeIdentities where
  type ValidationResult RuntimeIdentities = Bool
  validate (RuntimeIdentities hashes) = length hashes==16 &&
    validate (IsolatedIdentity (take 2 hashes)) && all ((==32) . B.length) hashes &&
    all (\i -> hashes !! i==hashes !! (i+1)) [2,4..14]

newtype ActivationFacts = ActivationFacts [B.ByteString]
instance Validation ActivationFacts where
  type ValidationResult ActivationFacts = Int
  validate (ActivationFacts hashes)
    | length hashes/=40 || any ((/=32) . B.length) hashes = -1
    | any (\(a,b) -> at a/=at b) [(0,1),(2,3),(4,5),(4,6),(7,8),(9,10),(11,12),(13,14),
        (15,16),(17,18),(19,20),(21,22),(25,26),(25,27),(28,24),(29,30)] ||
      at 14/=B.pack (snd (exchangeIdentities !! 1)) || at 16/=B.pack (snd (head exchangeIdentities)) ||
      at 22==at 23 || at 22==at 24 || at 24==at 23 = 1
    | any (B.all (==0) . at) ([31..39]++[22,24,18,20]) = 2
    | otherwise = 0
    where at index=hashes !! index

newtype BlinderIdentities = BlinderIdentities [B.ByteString]
instance Validation BlinderIdentities where
  type ValidationResult BlinderIdentities = Int
  validate (BlinderIdentities [issuance,asset,value])
    | any ((/=32) . B.length) [issuance,asset,value] = -1
    | not (validate (IsolatedIdentity [issuance,B.replicate 32 0,asset,value])) = 1
    | not (validate (IdentitySet [asset,value])) = 2
    | otherwise = 0
  validate _ = -1

newtype ProofIdentities = ProofIdentities [B.ByteString]
instance Validation ProofIdentities where
  type ValidationResult ProofIdentities = Int
  validate (ProofIdentities identities)
    | any ((/=32) . B.length) identities = -1
    | otherwise = go identities
    where
      go [] = 0
      go (identity:rest)
        | B.all (==0) identity = 1
        | identity `elem` rest = 2
        | otherwise = go rest

newtype CustodianRegistry = CustodianRegistry [(B.ByteString,B.ByteString)]
instance Validation CustodianRegistry where
  type ValidationResult CustodianRegistry = Int
  validate (CustodianRegistry keys)
    | length keys /= 5 || any (\(a,b) -> B.length a /= 32 || B.length b /= 32) keys = -1
    | otherwise = fst (registryRecords (zip [1..] keys))

registryRecords :: [(Word8,(B.ByteString,B.ByteString))] -> (Int,[(B.ByteString,B.ByteString)])
registryRecords = go 1 []
  where
    go _ seen [] = (0,reverse seen)
    go expected seen ((index,(a,b)):rest)
      | index /= expected || B.all (==0) a || B.all (==0) b = (1,reverse seen)
      | not (validate (IdentitySet (a:map fst seen))) || not (validate (IdentitySet (b:map snd seen))) = (2,reverse ((a,b):seen))
      | otherwise = go (expected+1) ((a,b):seen) rest

newtype RegistryDecoding = RegistryDecoding B.ByteString
instance Validation RegistryDecoding where
  type ValidationResult RegistryDecoding = (Int,B.ByteString)
  validate (RegistryDecoding input)
    | B.length input /= 325 = (-1,B.empty)
    | otherwise = let (code,keys) = registryRecords [(B.index input (i*65),(part (i*65+1),part (i*65+33))) | i <- [0..4]]
                  in (code,B.concat [a <> b | (a,b) <- keys])
    where part offset = B.take 32 (B.drop offset input)

data FrozenRequest = FrozenRequest B.ByteString B.ByteString (Word32 -> B.ByteString -> IO B.ByteString)
class FrozenInput op where
  frozenInput :: op -> Either Int (B.ByteString,B.ByteString)
class XOnlyChecks op where
  xOnlyValid :: op -> B.ByteString -> IO Bool
class FrozenPublication op where
  publishFrozen :: op -> Word32 -> B.ByteString -> IO ()
instance FrozenInput FrozenRequest where
  frozenInput (FrozenRequest market input _)
    | B.length input/=1977 = Left 1
    | B.length market/=16 = Left (-1)
    | otherwise = Right (market,input)
instance DigestEffects FrozenRequest where
  digestBytes (FrozenRequest _ _ effect) = effect
instance XOnlyChecks FrozenRequest where
  xOnlyValid value input = do
    result <- checkedDigest value 3 input
    if B.head result>1 || B.any (/=0) (B.tail result) then ioError (userError "invalid key-check result")
      else pure (B.head result==1)
instance FrozenPublication FrozenRequest where
  publishFrozen (FrozenRequest _ _ effect) group input = effect (group+4) input >> pure ()

type FrozenCapabilities = '[FrozenInput,DigestEffects,XOnlyChecks,FrozenPublication]

decodeFrozenRequest :: DSL FrozenRequest
decodeFrozenRequest = DecodeFrozen

instance Operation FrozenRequest FrozenCapabilities where
  type Context FrozenRequest = CapabilityContext FrozenCapabilities FrozenRequest
  type Outcome FrozenRequest = IO Int
  data DSL FrozenRequest where
    DecodeFrozen :: Context FrozenRequest => DSL FrozenRequest
  interpret operation request = withOperation @FrozenRequest operation $ \value -> case request of
    DecodeFrozen -> Just (either pure (decodeFrozen value) (frozenInput value))

decodeFrozen :: (DigestEffects op,XOnlyChecks op,FrozenPublication op) => op -> (B.ByteString,B.ByteString) -> IO Int
decodeFrozen value (market,input) = either id (const 0) <$> runExceptT (do
  base <- checked 2 (validate (IdentityProfile False market (part 0 178)))
  emit 0 (B.drop 1 base)
  let policy=B.take 32 (B.drop 97 base)
  _ <- checked 3 (validate (CheckpointProfile False policy (part 178 73)))
  require 4 (validate (FixedProfile 7)==Just (part 251 41))
  scheme <- fixedHash 0 5
  availability <- checked 5 (validate (IdentityProfile True scheme (part 292 71)))
  emit 1 availability
  truth <- checked 6 (validate (TruthcoinProfile (part 363 390)))
  emit 2 (B.take 32 (B.drop 128 truth))
  _ <- checked 7 (validate (CheckpointProfile True policy (part 753 73)))
  prices <- checked 8 (validate (HybridOracleProfile (fromIntegral (readBE (B.drop 160 truth))) (B.take 128 truth) (part 826 221)))
  let direct=B.head base==6
  emit 3 (B.singleton (if direct then 1 else 0))
  require 9 (not direct || (policy==part 50 32 && prices==(100000000,100000000)))
  signer <- liftIO (xOnlyValid value (part 1056 32))
  matcher <- checked 10 (validate (MatcherProfile signer (part 1047 85)))
  emit 4 matcher
  accumulator <- checked 11 (validate (AccumulatorProfile (part 1132 100)))
  emit 5 accumulator
  rule 11 (validate (ConfigurationIdentities False input))
  codec <- fixedHash 1 6
  let bond=part 1232 485
      field offset size=B.take size (B.drop offset bond)
  _ <- checked 14 (validate (BondProfile codec bond))
  emit 6 (B.concat [field offset 32 | offset <- [0,32..224] ++ [257,289] ++ [325,357..453]] <> field 256 1 <> field 321 4)
  descriptor <- checked (-1) (validate (StagingEncoding False (fromIntegral (B.index bond 256)) 0
    (field 192 64 <> field 257 64)))
  commitment <- liftIO (checkedDigest value 2 descriptor)
  require 15 (commitment==field 160 32)
  key <- liftIO (xOnlyValid value (field 224 32))
  require 15 key
  rule 15 (validate (FrozenTail direct (part 1717 260)))
  emit 7 (part 1717 260)
  rule 18 (validate (ConfigurationIdentities True input)))
  where
    part offset size=B.take size (B.drop offset input)
    checked code=maybe (throwE code) pure
    require code condition=if condition then pure () else throwE code
    rule offset code=if code==0 then pure () else throwE (if code<0 then -1 else offset+code)
    emit group=liftIO . publishFrozen value group
    fixedHash kind mode=checked (-1) (validate (FixedProfile mode)) >>= liftIO . checkedDigest value kind

data RuntimeActivation = RuntimeActivation Int32 (Maybe Int32)
instance Validation RuntimeActivation where
  type ValidationResult RuntimeActivation = (Bool, Int32)
  validate (RuntimeActivation activation privateHeight) =
    (activation /= maxBound || privateHeight /= Nothing, min activation (maybe maxBound id privateHeight))

newtype Unsigned32Fields = Unsigned32Fields [Word64]
instance Validation Unsigned32Fields where
  type ValidationResult Unsigned32Fields = Bool
  validate (Unsigned32Fields fields) = all (<= 4294967295) fields

newtype FrozenBounds = FrozenBounds [Word64]
data FrozenTail = FrozenTail Bool B.ByteString
instance Validation FrozenTail where
  type ValidationResult FrozenTail = Int
  validate (FrozenTail direct input)
    | B.length input /= 260 = -1
    | not (validate (FrozenBounds [number offset 4 | offset <- [0,4..32]])) = 1
    | any (\offset -> B.all (==0) (B.take 32 (B.drop offset input)) /= direct) [36,68..196] = 2
    | not (validate (FrozenBounds (zipWith number [228,236,240,244,252] [8,4,4,8,8]))) = 3
    | otherwise = 0
    where number offset size = readBE (B.take size (B.drop offset input))

newtype HybridOracleBounds = HybridOracleBounds [Word64]
data HybridOracleProfile = HybridOracleProfile Word32 B.ByteString B.ByteString
newtype TruthcoinProfile = TruthcoinProfile B.ByteString
data CheckpointProfile = CheckpointProfile Bool B.ByteString B.ByteString
data IdentityProfile = IdentityProfile Bool B.ByteString B.ByteString
data MatcherProfile = MatcherProfile Bool B.ByteString
instance Validation MatcherProfile where
  type ValidationResult MatcherProfile = Maybe B.ByteString
  validate (MatcherProfile signerValid input)
    | B.length input /= 85 = Nothing
    | B.head input /= 1 || not signerValid || readBE (B.take 8 (B.drop 41 input)) == maxBound ||
      B.all (==0) receipt || readBE (B.drop 81 input) /= 6 = Nothing
    | otherwise = Just receipt
    where receipt = B.take 32 (B.drop 49 input)

data ConfigurationIdentities = ConfigurationIdentities Bool B.ByteString
instance Validation ConfigurationIdentities where
  type ValidationResult ConfigurationIdentities = Int
  validate (ConfigurationIdentities outer input)
    | B.length input /= 1977 = -1
    | not (validate (IdentitySet (map part unique))) = 1
    | any (not . validate . IsolatedIdentity . map part) isolated = 2
    | otherwise = 0
    where
      part offset = B.take 32 (B.drop offset input)
      bond = map (+1232) ([0,32..224] ++ [257,289] ++ [325,357..453])
      conversions = [1753,1785..1913]
      base = [2,50,82,146,179,211,754,1096,1132,1164,1196]
      unique = if outer then bond ++ (if B.head input==6 then [] else conversions) else base
      isolated = if outer then [[1653,1132,1164,293,325],[681,1753,1785,1489,1521,1232,1589]]
        else if part 114==part 50 then [] else [114:base]

data BondProfile = BondProfile B.ByteString B.ByteString
instance Validation BondProfile where
  type ValidationResult BondProfile = Maybe B.ByteString
  validate (BondProfile codec input)
    | B.length input /= 485 || B.length codec /= 32 = Nothing
    | any (B.all (==0) . part) ([0,32..224] ++ [257,289] ++ [325,357..453]) ||
      part 192 /= B.pack (snd (exchangeIdentities !! 1)) ||
      part 224 /= B.pack (snd (head exchangeIdentities)) ||
      B.index input 256 /= 0xbe || part 257 == part 289 ||
      readBE (B.take 4 (B.drop 321 input)) /= 12 || part 453 /= codec = Nothing
    | otherwise = Just B.empty
    where part offset = B.take 32 (B.drop offset input)

newtype AccumulatorProfile = AccumulatorProfile B.ByteString
instance Validation AccumulatorProfile where
  type ValidationResult AccumulatorProfile = Maybe B.ByteString
  validate (AccumulatorProfile input)
    | B.length input /= 100 = Nothing
    | any (B.all (==0)) identities || identities !! 0 == identities !! 1 || limit == 0 || limit > 64 = Nothing
    | otherwise = Just (B.take 96 input)
    where
      identities = [B.take 32 (B.drop offset input) | offset <- [0,32,64]]
      limit = readBE (B.drop 96 input)

instance Validation IdentityProfile where
  type ValidationResult IdentityProfile = Maybe B.ByteString
  validate (IdentityProfile availability expected input)
    | B.length input /= (if availability then 71 else 178) || B.length expected /= (if availability then 32 else 16) = Nothing
    | availability = if B.head input==1 && part 1 32==expected && nonzero 1 && nonzero 33 &&
        B.index input 65==3 && B.index input 66==5 && readBE (B.drop 67 input)==16777216
        then Just (part 1 64) else Nothing
    | B.head input `elem` [5,6] && B.index input 1==3 && part 34 16==expected && all nonzero [2,50,82,114,146] =
        Just (B.take 1 input <> part 2 32 <> B.drop 50 input)
    | otherwise = Nothing
    where
      part offset size = B.take size (B.drop offset input)
      nonzero offset = B.any (/=0) (part offset 32)

instance Validation CheckpointProfile where
  type ValidationResult CheckpointProfile = Maybe B.ByteString
  validate (CheckpointProfile anchor policy input)
    | B.length input /= 73 || (anchor && B.length policy /= 32) = Nothing
    | B.head input /= 1 || B.all (==0) first || B.all (==0) second || age == 0 = Nothing
    | anchor && first == policy = Nothing
    | not anchor && (first == second || age > 1123200) = Nothing
    | otherwise = Just (first <> second)
    where
      first = B.take 32 (B.drop 1 input)
      second = B.take 32 (B.drop (if anchor then 41 else 33) input)
      age = readBE (B.take 8 (B.drop (if anchor then 33 else 65) input))

instance Validation TruthcoinProfile where
  type ValidationResult TruthcoinProfile = Maybe B.ByteString
  validate (TruthcoinProfile input)
    | B.length input /= 390 = Nothing
    | B.head input /= 3 || not (nonzero 1 20) || B.index input 85 == 0 ||
      not (nonzero 118 8) || any (not . (`nonzero` 32)) ([21,53,86] ++ [126,158..350]) ||
      confirmations == 0 || proof == 0 || proof > 16777216 = Nothing
    | otherwise = Just (B.take 160 (B.drop 190 input) <> B.take 4 (B.drop 382 input))
    where
      nonzero offset size = B.any (/=0) (B.take size (B.drop offset input))
      confirmations = readBE (B.take 4 (B.drop 382 input))
      proof = readBE (B.drop 386 input)

instance Validation HybridOracleProfile where
  type ValidationResult HybridOracleProfile = Maybe (Word64,Word64)
  validate (HybridOracleProfile confirmations truth input)
    | B.length input /= 221 || B.length truth /= 128 = Nothing
    | B.head input /= 1 || B.take 128 (B.drop 1 input) /= truth ||
      any (B.all (==0) . (\offset -> B.take 32 (B.drop offset truth))) [0,32,64,96] = Nothing
    | not (validate (HybridOracleBounds (take 3 fields ++ [fromIntegral confirmations] ++ drop 3 fields))) = Nothing
    | otherwise = Just (fields !! 14, fields !! 15)
    where
      widths = [8,8,4,8,8,8,4,4,4,4,4,4,4,4,8,8]
      fields = zipWith (\offset width -> readBE (B.take width (B.drop offset input))) (scanl (+) 129 widths) widths

instance Validation HybridOracleBounds where
  type ValidationResult HybridOracleBounds = Bool
  validate (HybridOracleBounds [_,epoch,confirmations,truthConfirmations,anchorAge,snapshotAge,
      liquidity,samples,baseWeight,maxWeight,initialBand,maxBand,haircut,boundary,deviation,ecx,usdd]) =
    all (/=0) [epoch,confirmations,anchorAge,snapshotAge,liquidity,samples,deviation,ecx,usdd] &&
    confirmations <= truthConfirmations && baseWeight <= maxWeight && maxWeight <= 1000000 &&
    initialBand <= maxBand && maxBand < 10000 && haircut < 10000 &&
    boundary < 500000000 && deviation <= 10000
  validate _ = False
instance Validation FrozenBounds where
  type ValidationResult FrozenBounds = Bool
  validate (FrozenBounds [price]) = price>0 && price<=9223372036854775807
  validate (FrozenBounds [height,limit]) = height>0 && height<limit
  validate (FrozenBounds [height,activation,mtp]) =
    height>0 && height<activation && activation<=2147483647 && mtp>0 && mtp<=4294967295
  validate (FrozenBounds fields)
    | length fields == 9 = fields == [6,65536,8,589824,786432,64,64,4096,6]
  validate (FrozenBounds [age,proof,marker,supply,delay]) =
    age /= 0 && proof /= 0 && proof <= 16777216 &&
    marker == 32 && supply == bondFixedSupply && delay == 1008
  validate (FrozenBounds (leaf:refund:fields))
    | length fields == 14 = leaf == 0xbe && refund == 12 &&
        validate (FrozenBounds (take 9 fields)) && validate (FrozenBounds (drop 9 fields))
  validate _ = False

class IdentityBinding op where
  bindIdentity :: op -> Either Int ()
class SnapshotProjection op where
  projectSnapshot :: op -> Either Int B.ByteString

data CapitalRequest = CapitalRequest CapitalIdentity (Maybe B.ByteString)
instance IdentityBinding CapitalRequest where
  bindIdentity (CapitalRequest identity _) = case validate identity of
    0 -> Right ()
    code -> Left code
instance SnapshotProjection CapitalRequest where
  projectSnapshot (CapitalRequest _ Nothing) = Right B.empty
  projectSnapshot (CapitalRequest (CapitalIdentity profile program values _) (Just context))
    | profile>1 || B.length context/=96 = Left (-1)
    | otherwise = maybe (Left (-1)) Right $ validate (CapitalSnapshot profile 0 0
        (B.take 32 context <> B.replicate 96 0 <> program <> B.drop 32 context <> B.replicate 96 0 <> values))

type CapitalCapabilities = '[IdentityBinding, SnapshotProjection]

bindAndProject :: DSL CapitalRequest
bindAndProject = BindAndProject

instance Operation CapitalRequest CapitalCapabilities where
  type Context CapitalRequest = CapabilityContext CapitalCapabilities CapitalRequest
  type Outcome CapitalRequest = Either Int B.ByteString
  data DSL CapitalRequest where
    BindAndProject :: Context CapitalRequest => DSL CapitalRequest
  interpret operation request = withOperation @CapitalRequest operation $ \value -> case request of
    BindAndProject -> Just (bindIdentity value >> projectSnapshot value)

data CapitalIdentity = CapitalIdentity Word32 B.ByteString B.ByteString B.ByteString
instance Validation CapitalIdentity where
  type ValidationResult CapitalIdentity = Int
  validate (CapitalIdentity profile program values expected)
    | profile > 2 || B.length program /= 32 || B.length values /= size ||
        B.length expected /= 32 + sum (map snd fields) = -1
    | program <> B.concat [B.take width (B.drop offset values) | (offset,width) <- fields] == expected = 0
    | otherwise = 1
    where
      (size,fields) = case profile of
        0 -> (850,hashes [0,36,276,308])
        1 -> (1627,hashes [4,388,420,452,484,516])
        _ -> (364,hashes [4,36,100,164,196,228] ++ [(324,8),(332,8)])
      hashes = map (\offset -> (offset,32))

-- Pure context binding follows parsing/script admission; finite proofs do not
-- bind a sidechain height. Native-owned snapshots/cursors are checked afterward.
data SuccessorBinding = SuccessorBinding Bool B.ByteString B.ByteString [Word64]
instance Validation SuccessorBinding where
  type ValidationResult SuccessorBinding = Int
  validate (SuccessorBinding incremental values hashes context)
    | B.length values /= (if incremental then 1627 else 850) ||
        B.length hashes /= 128 || length context /= 3 = -1
    | B.concat [B.take 32 (B.drop offset values) | offset <- hashOffsets] /= hashes = 1
    | map (readBE . (\offset -> B.take 8 (B.drop offset values))) numberOffsets /=
        take (length numberOffsets) context = 1
    | otherwise = 0
    where
      hashOffsets = if incremental then [36,100,132,164] else [68,132,164,196]
      numberOffsets = if incremental then [1284,1292,1300] else [228,236]

data EnvelopePayload = EnvelopePayload Word32 B.ByteString B.ByteString
instance Validation EnvelopePayload where
  type ValidationResult EnvelopePayload = Maybe B.ByteString
  validate (EnvelopePayload height checkpoint body)
    | B.length checkpoint /= 32 || B.null body || B.length body > 100000 = Nothing
    | otherwise = Just . L.toStrict . toLazyByteString $
        byteString (C.pack "ECXM") <> word8 1 <> word32LE height <>
        byteString checkpoint <> word32LE (fromIntegral (B.length body)) <> byteString body

data EnvelopeHeader = EnvelopeHeader Word64 Word8 Word32
instance Validation EnvelopeHeader where
  type ValidationResult EnvelopeHeader = Int
  validate (EnvelopeHeader size version bodySize)
    | version /= 1 || size < 45 = 1
    | bodySize == 0 || bodySize > 100000 || size /= 45 + fromIntegral bodySize = 2
    | otherwise = 0

newtype EnvelopeScan = EnvelopeScan (Word32 -> IO Int32)
instance Validation EnvelopeScan where
  type ValidationResult EnvelopeScan = IO Int32
  validate (EnvelopeScan action) = either id (const 0) <$> runExceptT (do
    inactive <- flag 0
    if inactive then pure () else need 1 1 >> need 2 1 >> need 3 (-1) >> scan False)
    where
      flag step = liftIO (action step) >>= \value -> case value of
        0 -> pure False
        1 -> pure True
        _ -> throwE (-1)
      need step code = flag step >>= \ok -> when (not ok) (throwE code)
      matches [] = pure True
      matches (step:rest) = flag step >>= \ok -> if ok then matches rest else pure False
      advance found = need 13 (-1) >> scan found
      scan found = flag 4 >>= \more -> if not more then finish found else do
        candidate <- matches [5..9]
        if not candidate then advance found else do
          when found (throwE 2)
          need 10 3
          need 11 4
          need 12 (-1)
          advance True
      finish found = do
        flags <- liftIO (action 14)
        when (flags < 0 || flags > 7) (throwE (-1))
        case validate (EnvelopeRequirement (testBit flags 0) (testBit flags 1) (testBit flags 2) found) of
          Left code -> throwE (fromIntegral code + 4)
          Right False -> pure ()
          Right True -> need 15 3 >> need 16 3 >> need 17 8

data EnvelopeRequirement = EnvelopeRequirement Bool Bool Bool Bool
instance Validation EnvelopeRequirement where
  type ValidationResult EnvelopeRequirement = Either Int Bool
  validate (EnvelopeRequirement nonnull changed priorActive present)
    | not changed && (not nonnull || priorActive) = if present then Left 1 else Right False
    | not nonnull = if present then Left 2 else Right False
    | not present = Left 3
    | otherwise = Right True

data M6Preimage = M6Preimage B.ByteString
instance Validation M6Preimage where
  type ValidationResult M6Preimage = Either Int B.ByteString
  validate (M6Preimage bytes) = do
    rest <- maybe (Left 1) Right $ do
      (version,a) <- fieldWord 4 bytes
      (inputs,b) <- compactWord a
      (outputs,c) <- compactWord b
      if version == 2 && inputs == 0 && outputs == 4 then Just c else Nothing
    (scripts,trailer) <- outputsFrom 0 rest
    case fieldWord 4 trailer of
      Just (0,empty) | B.null empty -> pure ()
      _ -> Left 4
    case scripts of
      [_,commitment,_,anchor]
        | B.length commitment == 34 && B.take 2 commitment == B.pack [106,32]
        , B.length anchor == 39 && B.take 7 anchor == B.pack [106,37,80,88,83,84,1] ->
            Right (B.drop 2 commitment <> B.drop 7 anchor)
      _ -> Left 5
    where
      outputsFrom index raw
        | index == (4 :: Int) = Right ([],raw)
        | otherwise = do
            (amount,script,rest) <- maybe (Left 2) Right $ do
              (amount,a) <- fieldWord 8 raw
              (size,b) <- compactWord a
              if size > 10000 then Nothing else do
                (script,c) <- fieldBytes (fromIntegral size) b
                pure (amount,script,c)
            if index /= 2 && amount /= 0 then Left 3 else do
              (remaining,trailer) <- outputsFrom (index+1) rest
              pure (script:remaining,trailer)

fieldBytes :: Int -> B.ByteString -> Maybe (B.ByteString,B.ByteString)
fieldBytes size bytes
  | size < 0 || size > B.length bytes = Nothing
  | otherwise = Just (B.splitAt size bytes)

fieldWord :: Int -> B.ByteString -> Maybe (Word64,B.ByteString)
fieldWord size bytes = do
  (word,rest) <- fieldBytes size bytes
  pure (readLE word,rest)

compactWord :: B.ByteString -> Maybe (Word64,B.ByteString)
compactWord bytes = do
  (tag,rest) <- B.uncons bytes
  if tag < 253 then Just (fromIntegral tag,rest) else do
    let width = if tag == 253 then 2 else if tag == 254 then 4 else 8
    (value,trailer) <- fieldWord width rest
    if (width == 2 && value >= 253) || (width == 4 && value > 65535) || (width == 8 && value > 4294967295)
      then Just (value,trailer) else Nothing

data SourceMarker = SourceMarker Word32 Word32 Bool
instance Validation SourceMarker where
  type ValidationResult SourceMarker = Either Int Word32
  validate (SourceMarker seen kind present)
    | seen > 3 || kind > 2 = Left (-1)
    | kind == 2 = if seen == 0 || present then Right seen else Left 3
    | not present = Right seen
    | testBit seen (fromIntegral kind) = Left (fromIntegral kind + 1)
    | otherwise = Right (setBit seen (fromIntegral kind))

data InboxTotals = InboxTotals Word64 Word64 Word32 Bool
class InboxScanning op where
  scanInbox :: op -> Word64 -> ExceptT Int32 IO [InboxSource]
class InboxAppending op where
  appendInbox :: op -> Word64 -> [InboxSource] -> InboxTotals -> ExceptT Int32 IO InboxTotals
  publishInbox :: op -> Word64 -> Word64 -> ExceptT Int32 IO ()

newtype InboxRequest = InboxRequest (Word32 -> Word64 -> Word64 -> IO Int64)
inboxStatus :: Int32 -> Int64 -> ExceptT Int32 IO ()
inboxStatus failure status = case status of
  1 -> pure ()
  0 -> throwE failure
  _ -> throwE (-1)

instance InboxScanning InboxRequest where
  scanInbox (InboxRequest action) tx = do
    count <- liftIO (action 1 tx 0)
    if count < 0 then throwE (-1) else do
      seen <- outputs (fromIntegral count) 0 0
      either throwE pure (inboxSources seen)
    where
      outputs count index seen
        | index == count = pure seen
        | otherwise = marker 0 index seen >>= marker 1 index >>= outputs count (index+1)
      marker kind index seen = do
        parsed <- liftIO (action (2+2*kind) tx index)
        case parsed of
          0 -> throwE 1
          1 -> pure seen
          2 -> do
            next <- either (\code -> throwE (if code < 0 then -1 else fromIntegral code+1)) pure
              (validate (SourceMarker seen kind True))
            liftIO (action (3+2*kind) tx index) >>= inboxStatus (-1)
            pure next
          _ -> throwE (-1)

data InboxSource = ForcedSource | DepositSource deriving (Eq, Show)

appendContribution :: InboxSource -> (Word32 -> IO Int64) -> InboxTotals -> ExceptT Int32 IO InboxTotals
appendContribution ForcedSource action (InboxTotals forced deposits work parent) = do
    when (forced == maxBound) (throwE 4)
    kind <- liftIO (action 7)
    when (kind < 0 || kind > 255) (throwE (-1))
    updated <- either (throwE . fromIntegral . (+5)) pure (trancheWork work (fromIntegral kind))
    liftIO (action 8) >>= inboxStatus (-1)
    pure (InboxTotals (forced+1) deposits updated parent)
appendContribution DepositSource action (InboxTotals forced deposits work parent) = do
    when (deposits == maxBound) (throwE 5)
    liftIO (action 9) >>= inboxStatus (-1)
    pure (InboxTotals forced (deposits+1) work parent)

inboxSources :: Word32 -> Either Int32 [InboxSource]
inboxSources seen
  | seen > 3 = Left (-1)
  | otherwise = Right ([ForcedSource | testBit seen 0] ++ [DepositSource | testBit seen 1])

appendContributions :: (Word32 -> IO Int64) -> InboxTotals -> [InboxSource] -> ExceptT Int32 IO InboxTotals
appendContributions action = foldM append
  where
    append current@(InboxTotals _ _ _ parent) source = do
      when (not parent) (liftIO (action 6) >>= inboxStatus 1)
      InboxTotals forced deposits work _ <- appendContribution source action current
      pure (InboxTotals forced deposits work True)

instance InboxAppending InboxRequest where
  appendInbox (InboxRequest action) tx sources totals =
    appendContributions (\step -> action step tx 0) totals sources
  publishInbox (InboxRequest action) forced deposits = liftIO (action 10 forced deposits) >>= inboxStatus (-1)

type InboxCapabilities = '[InboxScanning, InboxAppending]
inboxProgram :: (InboxScanning op, InboxAppending op) => op -> Word64 -> Word64 -> Word64 -> ExceptT Int32 IO ()
inboxProgram value count forced deposits = visit 0 (InboxTotals forced deposits 0 False)
  where
    visit tx totals@(InboxTotals finalForced finalDeposits _ _)
      | tx == count = publishInbox value (finalForced-forced) (finalDeposits-deposits)
      | otherwise = do
          sources <- scanInbox value tx
          next <- appendInbox value tx sources totals
          visit (tx+1) next

instance Operation InboxRequest InboxCapabilities where
  type Context InboxRequest = CapabilityContext InboxCapabilities InboxRequest
  type Outcome InboxRequest = IO Int32
  data DSL InboxRequest where
    DeriveInbox :: Context InboxRequest => Word64 -> Word64 -> Word64 -> DSL InboxRequest
  interpret operation request = withOperation @InboxRequest operation $ \value -> case request of
    DeriveInbox count forced deposits -> Just $ either id (const 0) <$> runExceptT
      (inboxProgram value count forced deposits)

deriveInbox :: Word64 -> Word64 -> Word64 -> DSL InboxRequest
deriveInbox = DeriveInbox

data ParentTarget = ParentTarget (Maybe Word64) (Word32 -> IO Word64)
instance Validation ParentTarget where
  type ValidationResult ParentTarget = IO (Either Int Word64)
  validate (ParentTarget supplied readFact) = case supplied of
    Just height -> pure (bounded height)
    Nothing -> do
      testNetwork <- readFact 0
      if testNetwork /= 1 then pure (Left 1) else do
        previous <- readFact 1
        pure (if previous >= fromIntegral (maxBound :: Word32) then Left 2 else bounded (previous + 1))
    where
      bounded height
        | height == 0 || height > fromIntegral (maxBound :: Word32) = Left 2
        | otherwise = Right height

data Tranche = Tranche Word64 (Word64 -> IO Word8)
instance Validation Tranche where
  type ValidationResult Tranche = IO (Int, Word32)
  validate (Tranche count readKind) = go 0 0
    where
      go index work
        | index == count = pure (0,work)
        | otherwise = do
            kind <- readKind index
            either (\code -> pure (code,work)) (go (index+1)) (trancheWork work kind)

trancheWork :: Word32 -> Word8 -> Either Int Word32
trancheWork work kind
  | kind > 2 = Left 1
  | work > limit || cost > limit-work = Left 2
  | otherwise = Right (work+cost)
  where
    limit = fromIntegral maxTrancheWork
    cost = if kind == 0 then 1 else if kind == 1 then limit else 0

data ForcedBody = ForcedBody Int B.ByteString B.ByteString B.ByteString
instance Validation ForcedBody where
  type ValidationResult ForcedBody = Int
  validate (ForcedBody kind body chain market)
    | kind < 0 || kind > 2 || B.length body /= forcedBodySizes !! kind || B.head body /= 1 = 1
    | bytes 1 32 /= chain = 2
    | kind == 0 = if validMarket && word 129 >= word 121 then 0 else 3
    | kind == 1 = if validMarket && B.index body 81 <= 1 && bytes 82 2 == B.pack [1,1] &&
        word 84 /= 0 && word 92 /= 0 && word 92 <= 0x7fffffffffffffff &&
        readBE (bytes 116 4) <= 10000 && word 136 >= word 128 then 0 else 4
    | otherwise = if word 73 /= 0 && word 121 >= word 113 then 0 else 5
    where
      bytes offset count = B.take count (B.drop offset body)
      word offset = readBE (bytes offset 8)
      validMarket = bytes 33 16 == market

-- Reader steps: explicit asset/value, null nonce, same asset/value, P2TR size/opcodes.
data Admission = Authority Bool (Int -> IO Bool) | OutputProfile Bool (Int -> IO Bool)
               | TrackerPhase Word32 (Int -> IO Bool)
               | Configuration (Int -> IO Bool)
               | ProductionIdentity (Int -> IO Bool)
               | HeaderPhase Word32 (Int -> IO Bool)
               | Connection Bool (Int -> IO Bool)
               | DisconnectPhase Word32 (Int -> IO Bool)
               | Availability Word32 (Int -> IO Bool)
               | Checkpoint (Int -> IO Bool)
               | SnapshotContext (Int -> IO Bool)
               | GenesisInitialization Word32 (Int -> IO Bool)
               | Deployment Word32 (Int -> IO Bool)
               | RequiredIdentities Word32 (Int -> IO Bool)
               | PhysicalInputs Bool (Int -> IO Bool)
               | TransactionShape Word32 (Int -> IO Bool)
instance Validation Admission where
  type ValidationResult Admission = IO Int
  validate (Authority successor readFact) = firstFailure readFact $
    [(0,1),(1,1),(2,1)] ++ (if successor then [(3,2),(4,3)] else []) ++ [(5,4),(6,4),(7,4)]
  validate (OutputProfile collateral readFact) = firstFailure readFact
    [(step,1) | step <- [0 .. if collateral then 6 else 5]]
  validate (TrackerPhase phase readFact) = phaseFailure ([2,1,1,1,1] : map (`replicate` 1) [7,3]) phase readFact
  validate (TransactionShape 4 readFact) = firstFailure readFact [(step,5) | step <- [1..15]]
  validate (TransactionShape 15 readFact) = do
    checkpoint <- readFact 0
    activation <- readFact 1
    if not checkpoint && not activation then pure 0 else do
      privateBuild <- readFact 2
      if not privateBuild then pure 18 else do
        testNetwork <- readFact 3
        if not testNetwork then pure 19
        else if not activation then pure 20
        else if not checkpoint then pure 21
        else firstFailure readFact [(4,22)]
  validate (TransactionShape 16 readFact) = do
    present <- mapM readFact [0..8]
    if not (or present) then pure 0 else do
      network <- readFact 9
      pure (if not network then 23 else if not (and (take 8 present)) then 24 else 25)
  validate (TransactionShape 17 readFact) = firstFailure readFact $
    [(0,1)] ++ [(step,step+1) | step <- [1..required]] ++
    [(step,required+2) | step <- [required+1..required+length bondGroupedArguments]]
    where required = length bondRequiredArguments
  validate (TransactionShape phase readFact) = phaseFailure transactionShapePhases phase readFact
  validate (Configuration readFact) = firstFailure readFact $
    [(0,1)] ++ [(step,2) | step <- [1..3]] ++ [(step,3) | step <- [4..12]] ++ [(13,4)]
  validate (ProductionIdentity readFact) = firstFailure readFact $ zip [0..] $
    concat (zipWith replicate [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,4,4,3,5,7,9,5,4,7,6,10,6,3,12,6] [1..])
  validate (HeaderPhase phase readFact) = phaseFailure (map (`replicate` 1) [11,8,6]) phase readFact
  validate (Connection activation readFact) = firstFailure readFact $
    [(step,1) | step <- [0..5]] ++ [(step,2) | activation, step <- [6..8]]
  validate (DisconnectPhase phase perform) =
    phaseFailure [[1,1,1,2,2,2,2], [3,3,3,3], [4,5,5], [6,6]] phase perform
  validate (Availability kind readFact) = phaseFailure (map (`replicate` 1) [3,2,4,1]) kind readFact
  validate (Checkpoint readFact) = firstFailure readFact (zip [0..] [1,2,2,3,3,3,3,3])
  validate (SnapshotContext readFact) = firstFailure readFact
    (zip [0..] (replicate 4 1 ++ replicate 3 2 ++ replicate 6 3 ++ [2]))
  validate (Deployment version readFact)
    | version /= 2 && version /= 3 = pure 1
    | otherwise = firstFailure readFact ([(step,2) | version == 3, step <- [0..2]] ++ [(3,3),(4,4)])
  validate (RequiredIdentities flags readFact)
    | flags > 3 = pure (-1)
    | otherwise = firstFailure readFact [(step,step+1) | step <- [0..44],
        not (testBit flags 0 && step == 44), not (testBit flags 1 && step >= 33 && step <= 38)]
  validate (PhysicalInputs public readFact) = firstFailure readFact $
    [(step,1) | step <- [0..3] ++ (if public then [] else [4..8]) ++ [9..12]]
  validate (GenesisInitialization version readFact) = do
    context <- firstFailure readFact [(0,1),(1,1)]
    if context /= 0 then pure context
      else if version == 0 then firstFailure readFact [(2,2),(3,2),(4,2),(19,-1)]
      else if version /= 2 then pure 3
      else firstFailure readFact ([(step,3) | step <- [5..13]] ++ [(step,4) | step <- [14..18]] ++ [(20,-1)])

-- Empty entries reserve phases with custom control flow above. The ABI derives
-- its upper bound from this same registry, rather than a second phase limit.
transactionShapePhases :: [[Int]]
transactionShapePhases =
  [[1,1,2], replicate 9 3, replicate 8 4, replicate 16 5, [], replicate 11 6, replicate 8 7,
   [8,8,8,9,9,9,9,9,10], [11,11], [12,12], replicate 8 13, [14,14], [15], [16], replicate 16 17,
   [], [], [], replicate 11 23, [24,25,26], replicate 3 27, replicate 3 28,
   replicate 3 29 ++ replicate 7 30, [31,32], [33,25,34]]

phaseFailure :: [[Int]] -> Word32 -> (Int -> IO Bool) -> IO Int
phaseFailure [] _ _ = pure (-1)
phaseFailure (codes:_) 0 readFact = firstFailure readFact (zip [0..] codes)
phaseFailure (_:phases) phase readFact = phaseFailure phases (phase-1) readFact

firstFailure :: (Int -> IO Bool) -> [(Int,Int)] -> IO Int
firstFailure _ [] = pure 0
firstFailure readFact ((step,err):rest) = do
  accepted <- readFact step
  if accepted then firstFailure readFact rest else pure err

data Cursors = Cursors Bool Bool Bool Bool Word64 Word64 Word64 Word64
instance Validation Cursors where
  type ValidationResult Cursors = Either Int (Word64, Word64)
  validate (Cursors transitioned found emptyActivation sameTransaction previousForced previousDeposit forced deposit)
    | transitioned && not found && emptyActivation && previousForced == 0 && previousDeposit == 0 = Right (0,0)
    | transitioned /= found = Left (if transitioned then 1 else 2)
    | not transitioned = Right (previousForced,previousDeposit)
    | not sameTransaction || forced < previousForced || deposit < previousDeposit = Left 3
    | otherwise = Right (forced,deposit)

-- The scan completes before transition/cursor admission. Native actions retain
-- the first marker's transaction hash, but publish no cursor outputs on failure.
data CursorDerivation = CursorDerivation Word64 Word32 Word64 Word64
  (Word32 -> Word64 -> Word64 -> IO (Int32,Word64,Word64))
instance Validation CursorDerivation where
  type ValidationResult CursorDerivation = IO (Either Int (Word64,Word64))
  validate (CursorDerivation count flags previousForced previousDeposit action)
    | flags > 3 = pure (Left (-1))
    | otherwise = runExceptT (transactions 0 Nothing)
    where
      transactions tx found
        | tx == count = do
            same <- if testBit flags 0 && found /= Nothing then do
              (status,_,_) <- liftIO (action 4 0 0)
              case status of
                0 -> pure False
                1 -> pure True
                _ -> throwE (-1)
              else pure False
            let (forced,deposit) = maybe (0,0) id found
            either throwE pure (validate (Cursors (testBit flags 0) (found /= Nothing)
              (testBit flags 1) same previousForced previousDeposit forced deposit))
        | otherwise = do
            (status,size,_) <- liftIO (action 1 tx 0)
            when (status /= 1) (throwE (-1))
            outputs tx size 0 found >>= transactions (tx+1)
      outputs tx size index found
        | index == size = pure found
        | otherwise = do
            (status,forced,deposit) <- liftIO (action 2 tx index)
            next <- case status of
              0 -> throwE 4
              1 -> pure found
              2 -> do
                when (found /= Nothing) (throwE 5)
                (retained,_,_) <- liftIO (action 3 tx index)
                when (retained /= 1) (throwE (-1))
                pure (Just (forced,deposit))
              _ -> throwE (-1)
            outputs tx size (index+1) next

-- Counts and cursors are projected values, never native pointers.
data SourceBytes = SourceBytes Word64 Word64 Word64 Word64 Word64 Word64
data SourceTracking = SourceTracking [Word64] B.ByteString B.ByteString
instance Validation SourceTracking where
  type ValidationResult SourceTracking = Either Int B.ByteString
  validate (SourceTracking [addWitness,addTransaction,maxWitness,maxTransaction] hashes state)
    | B.length hashes /= 96 || B.length state < 8 || (B.length state-8) `mod` 104 /= 0 ||
      any (>4294967295) [addWitness,addTransaction,maxWitness,maxTransaction] = Left (-1)
    | otherwise = case filter ((== B.take 32 hashes) . B.take 32) (records (B.drop 8 state)) of
        prior:_ -> if prior == record then Right state else Left 3
        [] -> case validate (SourceBytes (readBE (B.take 4 state)) (readBE (B.take 4 (B.drop 4 state)))
                    addWitness addTransaction maxWitness maxTransaction) of
          (0,[witness,transaction]) -> Right (encode witness <> encode transaction <> B.drop 8 state <> record)
          (code,_) -> Left code
    where
      encode = L.toStrict . toLazyByteString . word32BE . fromIntegral
      record = hashes <> encode addWitness <> encode addTransaction
      records bytes | B.null bytes = []
                    | otherwise = B.take 104 bytes : records (B.drop 104 bytes)
  validate _ = Left (-1)

data MarkerBounds = MarkerBounds [Word64]
instance Validation MarkerBounds where
  type ValidationResult MarkerBounds = (Int, [Word64])
  validate (MarkerBounds [successor,height,delay,kind,refundDelay,refundHeight,markers,limit,count,tx,vout])
    | successor > 1 = (-1,[0,0])
    | not (fits maxBound [height,delay]) = (1,[0,0])
    | kind == 1 && (not (fits maxBound [height,refundDelay]) || refundHeight < height + refundDelay) = (2,result)
    | markers == limit || (successor == 0 && count == maxBound) || tx > 4294967295 || vout > 4294967295 = (3,result)
    | otherwise = (0,result)
    where result = [1,height+delay]
  validate _ = (-1,[0,0])

instance Validation SourceBytes where
  type ValidationResult SourceBytes = (Int, [Word64])
  validate (SourceBytes witness transaction addWitness addTransaction maxWitness maxTransaction)
    | not (fits 4294967295 [witness,addWitness] && fits 4294967295 [transaction,addTransaction]) =
        (1,[witness,transaction])
    | otherwise = (if nextWitness > maxWitness || nextTransaction > maxTransaction then 2 else 0,
                   [nextWitness,nextTransaction])
    where
      nextWitness = witness + addWitness
      nextTransaction = transaction + addTransaction

data TemplateBudget = TemplateBudget Int64 Int64 (Word32 -> IO Word64)
instance Validation TemplateBudget where
  type ValidationResult TemplateBudget = IO (Int32,Word64)
  validate (TemplateBudget height activation action) = do
    enabled <- action 0
    case enabled of
      0 -> pure (0,0)
      1 | height<=activation -> pure (0,0)
        | otherwise -> do
            loaded <- action 1
            case loaded of
              0 -> pure (1,0)
              1 -> do
                backlog <- Backlog <$> action 2 <*> action 3 <*> action 4 <*> action 5
                pure $ case validate (AppendBudget backlog) of
                  (Nothing,Just budget) -> (0,budget)
                  (Just InvalidCursor,_) -> (2,0)
                  (Just BacklogLimit,_) -> (3,0)
                  _ -> (-1,0)
              _ -> pure (-1,0)
      _ -> pure (-1,0)

data Backlog = Backlog Word64 Word64 Word64 Word64 deriving (Show)
data InboxRule = AppendBudget Backlog
               | Liveness Backlog Backlog Word64 Word64 Word64 Word64
               | ActivationCounts Bool Word64 Word64
               deriving (Show)
data InboxError = InvalidCursor | AppendLimit | WitnessLimit | BacklogLimit
                | MissingHeight | InvalidAge | Deadline | ActivationAppends
                deriving (Eq, Show, Enum)

-- Just records a native output write, including the write before deadline failure.
instance Validation InboxRule where
  type ValidationResult InboxRule = (Maybe InboxError, Maybe Word64)
  validate (ActivationCounts active forced deposits) =
    (if active && (forced/=0 || deposits/=0) then Just ActivationAppends else Nothing,Nothing)
  validate (AppendBudget backlog) = case pending backlog of
    Nothing -> (Just InvalidCursor, Just 0)
    Just (f,d) | fits maxCombinedUnconsumed [f,d] -> (Nothing, Just (maxCombinedUnconsumed-f-d))
               | otherwise -> (Just BacklogLimit, Just 0)
  validate (Liveness previous next forced deposits oldest height) =
    case (pending previous, pending next) of
      (Just (pf,pd), Just (nf,nd))
        | not (fits maxCombinedAppends [forced,deposits]) -> reject AppendLimit
        | not (fits maxPendingWitnessEntries [pf,pd,forced,deposits]) -> reject WitnessLimit
        | not (fits maxCombinedUnconsumed [nf,nd]) -> reject BacklogLimit
        | nf == 0 && nd == 0 -> (Nothing, Just 0)
        | height == 0 -> reject MissingHeight
        | pf + pd /= 0 && (oldest == 0 || oldest > height) -> reject InvalidAge
        | otherwise ->
            let age = if pf + pd == 0 then height else oldest
            in (if age > maxBound - forcedInclusionBlocks || height >= age + forcedInclusionBlocks then Just Deadline else Nothing, Just age)
      _ -> reject InvalidCursor
    where reject err = (Just err, Nothing)

pending :: Backlog -> Maybe (Word64, Word64)
pending (Backlog f fc d dc)
  | fc > f || dc > d = Nothing
  | otherwise = Just (f-fc,d-dc)

fits :: Word64 -> [Word64] -> Bool
fits _ [] = True
fits capacity (n:rest) = n <= capacity && fits (capacity-n) rest
