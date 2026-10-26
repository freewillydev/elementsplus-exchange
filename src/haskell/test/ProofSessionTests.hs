{-# LANGUAGE FlexibleInstances, MultiParamTypeClasses, TypeApplications, TypeFamilies #-}
module ProofSessionTests (properties) where

import qualified Bmm as H
import qualified BmmConstants as K
import CommitmentTests (commitmentFixture)
import SignetSessionTests (signetFixture)
import Control.Exception (SomeException, try)
import Control.Monad (forM, when)
import Control.Operation
import Control.Operation.Validation (Check(..))
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.Int (Int32)
import Data.IORef
import Data.Maybe (isNothing)
import Data.Word (Word32, Word64)
import qualified Drivechain as FFI
import Foreign.Ptr (nullFunPtr, nullPtr)
import Test.QuickCheck
import Withdrawal (wordLE)
import Workflow (NativeBytes)

encodeSizeError, decodeSizeError, shapeError, attachError :: String
encodeSizeError = "serialized BMM proof exceeds its consensus size bound"
decodeSizeError = "BMM proof is empty or exceeds its consensus size bound"
shapeError = "BMM proof is malformed or non-canonical"
attachError = "cannot attach BMM proof without the header version bit"

run :: Int -> NativeBytes -> IO Int32
run mode native = execute (H.ProofSession native) $ case mode of
  0 -> H.EncodeProof
  1 -> H.DecodeProof
  2 -> H.AttachProof
  3 -> H.VerifyProofEntries
  _ -> H.VerifyProofBlock

wordsBytes :: [Word64] -> B.ByteString
wordsBytes = B.concat . map (wordLE 8)

stateBytes :: Word64 -> Word64 -> B.ByteString
stateBytes count position = B.replicate 32 (fromIntegral (17+position)) <>
  B.concat (map (wordLE 4) [1+position,100+position,8,0,1]) <> B.singleton 11 <>
  B.concat (map (wordLE 4) (drop (fromIntegral position) [90..100] ++ [101..100+count]))

-- Native object projections only: these replies contain no admission decisions.
exercise :: Int -> Word64 -> Bool -> [(Word32,B.ByteString)] -> Int -> Bool
  -> IO (Maybe Int32,[Word32],String)
exercise mode count signet overrides fault malformed = do
  seen <- newIORef []
  message <- newIORef "old diagnostic"
  position <- newIORef 0
  outcome <- try @SomeException $ run mode $ \step index input -> do
    when (index /= 0 || (step `notElem` [390,405,406,407,409,523,623] &&
      not (step >= 720 && step <= 725) && not (B.null input))) (error "invalid native request")
    before <- readIORef seen
    modifyIORef' seen (++[step])
    if length before == fault then
      if malformed then pure B.empty else ioError (userError "native fault")
    else do
      when (step == 390) (writeIORef message (C.unpack input))
      when (step == 392) (writeIORef message "")
      current <- readIORef position
      when (step == 408) (modifyIORef' position (+1))
      when (step == 407 && input /= stateBytes count count) (error "wrong header state publication")
      when (step == 409) (ioError (userError (C.unpack input)))
      empty <- null <$> readIORef message
      case lookup step overrides of
        Just bytes -> pure bytes
        Nothing | step >= 500 && step <= 590 -> commitmentFixture 0 (step-500) index input
                | step >= 600 && step <= 690 -> commitmentFixture 1 (step-600) index input
                | step >= 700 && step <= 790 -> signetFixture (step-700) index input
        Nothing -> pure $ case step of
          300 -> B.singleton 1 <> wordLE 8 10
          301 -> wordLE 8 10
          303 -> wordLE 8 K.schemaVersion
          304 -> wordLE 8 count
          391 -> wordLE 8 (if empty then 1 else 0)
          400 -> wordsBytes [1,2000,1,1,100,8,0,1,11,100,count]
          401 -> stateBytes 0 0
          402 -> B.replicate 32 (fromIntegral (17+current))
          403 -> wordLE 4 (101+current) <> wordLE 4 8
          404 -> B.replicate 32 (fromIntegral (18+current))
          _ | step >= 256 -> wordLE 8 1
          1 -> wordsBytes [1,count,128,0]
          2 -> wordsBytes [0,1,1,100]
          3 -> wordsBytes [1,1,1,0]
          7 -> wordsBytes [current,count,0,0]
          12 -> wordsBytes [3,10,1000,0]
          154 -> wordsBytes [0,if signet then 1 else 0,0,0]
          205 -> wordsBytes [1,1,0,0]
          _ -> wordsBytes [1,0,0,0]
  trace <- readIORef seen
  diagnostic <- readIORef message
  pure (either (const Nothing) Just outcome,trace,diagnostic)

boundarySize :: Gen Word64
boundarySize = oneof [elements [0,1,K.proofBytes,K.proofBytes+1,maxBound],arbitrary]

prop_encode :: Property
prop_encode = forAll boundarySize $ \size -> ioProperty $ do
  actual <- exercise 0 1 False [(300,B.singleton 1 <> wordLE 8 size)] (-1) False
  let ok = size > 0 && size <= K.proofBytes
  pure (actual == (Just (if ok then 1 else 0),[392,300] ++ [390 | not ok],if ok then "" else encodeSizeError))

prop_serialization_error :: String -> Property
prop_serialization_error input = ioProperty $ do
  let bytes = C.pack input
  actual <- exercise 0 1 False [(300,B.singleton 0 <> bytes)] (-1) False
  pure (actual == (Just 0,[392,300,390],C.unpack bytes))

prop_decode :: Bool -> Bool -> Bool -> Property
prop_decode decoded version canonical = forAll boundarySize $ \size -> forAll (choose (0,130)) $ \count -> ioProperty $ do
  let scalar s v = (s,wordLE 8 v)
      overrides = [scalar 301 size,scalar 302 (fromIntegral (fromEnum decoded)),
        scalar 303 (if version then K.schemaVersion else K.schemaVersion+1),scalar 304 count,
        scalar 305 (fromIntegral (fromEnum canonical))]
      bounded = size > 0 && size <= K.proofBytes
      shape = decoded && version && count > 0 && count <= K.proofEntries
      ok = bounded && shape && canonical
      trace = [392,301] ++ (if bounded then [302] ++ [303 | decoded] ++
        [304 | decoded && version] ++ [305 | shape] else []) ++ [390 | not ok]
      diagnostic = if ok then "" else if bounded then shapeError else decodeSizeError
  actual <- exercise 1 1 False overrides (-1) False
  pure (actual == (Just (if ok then 1 else 0),trace,diagnostic))

prop_attach :: Bool -> Property
prop_attach enabled = forAll boundarySize $ \size -> ioProperty $ do
  actual <- exercise 2 1 False [(306,wordLE 8 (fromIntegral (fromEnum enabled))),
    (300,B.singleton 1 <> wordLE 8 size)] (-1) False
  let encoded = size > 0 && size <= K.proofBytes
      ok = enabled && encoded
      trace = [392,306] ++ if not enabled then [390] else [392,300,if encoded then 307 else 390]
      diagnostic = if not enabled then attachError else if encoded then "" else encodeSizeError
  pure (actual == (Just (if ok then 1 else 0),trace,diagnostic))

prop_composition :: Bool -> Bool -> Property
prop_composition block signet = forAll (choose (1,8)) $ \count -> ioProperty $ do
  (outcome,trace,diagnostic) <- exercise (if block then 4 else 3) count signet [] (-1) False
  let occurrences step = length (filter (==step) trace)
  pure (outcome == Just 1 && null diagnostic &&
    occurrences 408 == fromIntegral count && occurrences 407 == 1 &&
    occurrences 392 == (if block then 3 else 1) &&
    all (`notElem` trace) [6,7,9,14,16,18,19,23,147,150,151,152] && occurrences 17 == (if block then 1 else 0) &&
    occurrences 700 == (if signet then fromIntegral count else 0) && occurrences 701 == occurrences 700 &&
    occurrences 22 == (if block then 1 else 0) && occurrences 600 == (if block then 1 else 0) &&
    occurrences 500 == 1)

prop_fault_prefix :: Bool -> Property
prop_fault_prefix malformed = forAll (choose (0,4)) $ \mode -> forAll (choose (0,200)) $ \seed -> ioProperty $ do
  -- Nested signet failures include scope release and catch-all decode behavior;
  -- SignetSessionTests independently exhausts those prefixes.
  (_,baseline,_) <- exercise mode 2 False [] (-1) False
  let fault = seed `mod` length baseline
  (result,trace,_) <- exercise mode 2 False [] fault malformed
  pure (result == Nothing && trace == take (fault+1) baseline)

prop_header_state_rejections :: Property
prop_header_state_rejections = forAll (choose (0,9)) $ \field -> ioProperty $ do
  let original = [1,2000,1,1,100,8,0,1,11,100,1]
      wrong = [0,0,0,0,0,0,2,0,12,99] !! field
      fields = take field original ++ [wrong] ++ drop (field+1) original
      exceptional = field == 2
  (result,trace,diagnostic) <- exercise 3 1 False [(400,wordsBytes fields)] (-1) False
  pure (if exceptional then result == Nothing && trace == [392,1,400,409]
    else result == Just 0 && trace == [392,1,400,390] && diagnostic == "BMM parent-chain state is malformed")

prop_header_framing :: Property
prop_header_framing = forAll (elements [400,401,402,403,404]) $ \step -> forAll (choose (0,110)) $ \size -> ioProperty $ do
  let expected = maybe 0 id (lookup step [(400,88),(401,97),(402,32),(403,8),(404,32)])
  if size == expected then pure True else do
    (result,trace,_) <- exercise 3 1 False [(step,B.replicate size 0)] (-1) False
    pure (result == Nothing && last trace == step && 407 `notElem` trace)

prop_header_retarget :: Bool -> Bool -> Property
prop_header_retarget boundary matches = forAll arbitrary $ \time -> ioProperty $ do
  trace <- newIORef []
  let target = 2016
      height = if boundary then 2015 else 2014
      state = H.ProofHeaderProgress B.empty [height,time,8,0,1] target target 1 0
      elapsed = min (4*target) (max (target `quot` 4) (fromIntegral time - 1))
      scaled = min (sum [16*256^i | i <- [0..31 :: Int]])
        (((256^(32::Int)-1)*toInteger elapsed `mod` 256^(32::Int)) `quot` toInteger target)
      bytes = B.pack [fromIntegral (scaled `quot` 256^i) | i <- [0..31 :: Int]]
      native step index input = do
        when (index /= 0) (error "unexpected retarget index")
        modifyIORef' trace (++[step])
        case step of
          403 -> pure (wordLE 4 1 <> wordLE 4 (if matches then 8 else 9))
          405 | input == wordLE 4 8 -> pure (B.replicate 32 255 <> B.replicate 32 16)
          406 | input == bytes -> pure (wordLE 4 8)
          _ -> error "unexpected retarget projection"
  accepted <- H.matchesProofBits (H.ProofSession native) state
  seen <- readIORef trace
  pure (accepted == matches && seen == if boundary then [405,406,403] else [403])

data LocalProof = LocalProof Bool Bool Bool Bool (IORef [String])
record :: LocalProof -> String -> IO ()
record (LocalProof _ _ _ _ events) event = modifyIORef' events (++[event])
instance H.ProofCoding LocalProof where
  encodeProofBytes value = record value "encode" >> pure True
  decodeProofBytes value@(LocalProof decoded _ _ _ _) = record value "decode" >> pure decoded
instance H.ProofEnvelopeAccess LocalProof where
  resetProofError value = record value "reset"
  proofFacts value@(LocalProof _ prior parent _ _) step = do
    record value (show step)
    pure $ case step of
      12 -> [3,1,100,0]
      15 -> [fromIntegral (fromEnum prior),0,0,0]
      23 -> [fromIntegral (fromEnum parent),0,0,0]
      1 -> [1,2,128,0]
      2 -> [0,1,1,100]
      3 -> [1,1,1,0]
      154 -> [0,0,0,0]
      205 -> [1,1,0,0]
      _ -> [1,0,0,0]
  proofHeaderEnabled _ = pure True
  publishProofCommitment value = record value "publish"
  proofResult _ result = pure (result == 0)
instance H.ProofSequence LocalProof where
  verifyProofSequence value@(LocalProof _ _ _ accepted _) = record value "entries" >> pure accepted

instance H.ProofHeaderEvolution LocalProof where
  type ProofHeaderState LocalProof = Int
  inspectProofState value = record value "inspect" >> pure (Just 0)
  beginProofHeaders value state = record value "begin" >> pure state
  matchesProofParent value _ = record value "parent" >> pure True
  matchesProofBits value _ = record value "bits" >> pure True
  exceedsProofMedian value _ = record value "median" >> pure True
  advanceProofHeader value state = record value ("advance" ++ show state) >> pure (state+1,[fromIntegral state,2,0,0])
  publishProofState value state = record value ("publish" ++ show state)

prop_header_capability_reuse :: Property
prop_header_capability_reuse = once $ ioProperty $ do
  events <- newIORef []
  accepted <- H.evolveProofHeaders (LocalProof True True True True events)
  trace <- readIORef events
  pure (accepted && filter (`elem` ["inspect","begin","advance0","advance1","publish2"]) trace ==
    ["inspect","begin","advance0","advance1","publish2"] && last trace == "publish2")

prop_capability_reuse :: Bool -> Bool -> Bool -> Bool -> Property
prop_capability_reuse decoded prior parent accepted = ioProperty $ do
  events <- newIORef []
  result <- H.verifyProofEnvelope (LocalProof decoded prior parent accepted events)
  trace <- readIORef events
  let expected = ["reset","12","13","decode"] ++ (if decoded then ["15"] ++
        (if prior then ["22","23"] ++ (if parent then ["17","entries"] else []) else []) else [])
  pure (result == (decoded && prior && parent && accepted) && trace == expected)

prop_lazy_dispatch :: Property
prop_lazy_dispatch = once $ property $ isNothing $
  interpret (SomeOperation (undefined :: Check H.Header)) (undefined :: DSL H.ProofSession)

prop_missing_callback :: Property
prop_missing_callback = once $ ioProperty $ do
  replies <- forM [42..48] $ \selector -> FFI.elements_hs_replay_store selector 0 nullFunPtr nullPtr
  pure (all (==(-1)) replies)

properties :: [(String,Property)]
properties =
  [("proof session encode bounds and partial output",prop_encode)
  ,("proof session native serialization diagnostic",property prop_serialization_error)
  ,("proof session decode shape and lazy reads",property prop_decode)
  ,("proof session attachment publication ordering",property prop_attach)
  ,("proof session composed parent and entry traversal",property prop_composition)
  ,("proof session all callback failure prefixes",prop_fault_prefix False)
  ,("proof session malformed replies stop effects",prop_fault_prefix True)
  ,("proof header state rejects before history or crypto",prop_header_state_rejections)
  ,("proof header projections enforce exact framing",prop_header_framing)
  ,("proof header retarget preserves uint256 scaling and lazy reads",property prop_header_retarget)
  ,("proof header evolution reuses associated-state capability",prop_header_capability_reuse)
  ,("proof session reusable capability workflow",property prop_capability_reuse)
  ,("proof session lazy payload mismatch",prop_lazy_dispatch)
  ,("proof session missing callbacks rejected",prop_missing_callback)]
