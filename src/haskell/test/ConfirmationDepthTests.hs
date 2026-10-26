{-# LANGUAGE TypeApplications #-}
module ConfirmationDepthTests (properties) where

import BmmConstants (peginIdentityPins)
import Control.Exception (SomeException, try)
import Control.Monad (when)
import Control.Operation
import Control.Operation.Validation
import Data.Bits (testBit)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.Either (isLeft)
import Data.Int (Int32)
import Data.IORef
import Data.Maybe (isNothing)
import Data.Word (Word32, Word64)
import qualified Deposit as D
import qualified ReplayStore as R
import Test.QuickCheck
import Withdrawal (wordLE)

pin :: String -> B.ByteString
pin name = case lookup name peginIdentityPins of
  Nothing -> error "unknown test pin"
  Just text -> B.reverse (B.pack (pairs text))
  where
    pairs [] = []
    pairs (a:b:rest) = read ("0x"++[a,b]) : pairs rest
    pairs _ = error "odd test pin"

identity :: Bool -> Word32 -> D.ConfirmationIdentity
identity alpha depth = D.ConfirmationIdentity (C.pack "elements") True True (Just 24)
  (pin (if alpha then "PEGIN_ALPHA_GENESIS" else "PEGIN_BETA_GENESIS"))
  (pin "PEGIN_PARENT_GENESIS")
  (pin (if alpha then "PEGIN_ALPHA_MANIFEST" else "PEGIN_BETA_MANIFEST")) depth

encode :: D.ConfirmationSelection -> B.ByteString
encode (D.ConfirmationSelection _ height (D.ConfirmationIdentity network elementsMode parent slot genesis parentGenesis manifest depth)) =
  wordLE 8 (fromIntegral height) <> size (B.length network) <> network <>
  B.pack [flag elementsMode,flag parent,maybe 0 (const 1) slot,maybe 0 id slot] <>
  genesis <> parentGenesis <> manifest <> wordLE 4 (fromIntegral depth)
  where
    flag = fromIntegral . fromEnum
    size n | n < 253 = B.singleton (fromIntegral n)
           | otherwise = B.singleton 253 <> wordLE 2 (fromIntegral n)

-- Original identity predicate, independent of fact numbering and workflow code.
reference :: D.ConfirmationSelection -> Word32
reference (D.ConfirmationSelection alpha height value@(D.ConfirmationIdentity _ _ _ _ _ _ _ configured))
  | alpha = if value == identity True 100 then 1 else 0
  | value == identity False 100 = 6
  | height >= 64 && value == identity True 100 = 1
  | otherwise = configured

genSelection :: Gen D.ConfirmationSelection
genSelection = do
  historical <- arbitrary
  alpha <- arbitrary
  height <- frequency [(3,elements [minBound,-1,0,63,64,65,maxBound]),(1,arbitrary)]
  depth <- frequency [(3,elements [0,1,6,99,100,101,maxBound]),(1,arbitrary)]
  mask <- choose (0,511 :: Word32)
  network <- elements [C.pack "elementsregtest",B.empty,B.replicate 253 101,B.pack [101,0,108]]
  let D.ConfirmationIdentity normal _ _ _ genesis parentGenesis manifest _ = identity historical 100
      unknown = B.replicate 32 1
      value = D.ConfirmationIdentity (if testBit mask 0 then network else normal)
        (not (testBit mask 1)) (not (testBit mask 2))
        (if testBit mask 3 then Nothing else Just (if testBit mask 4 then 25 else 24))
        (if testBit mask 5 then unknown else genesis)
        (if testBit mask 6 then unknown else parentGenesis)
        (if testBit mask 7 then unknown else manifest)
        (if testBit mask 8 then depth else 100)
  pure (D.ConfirmationSelection alpha height value)

selection :: Property
selection = forAll genSelection $ \value@(D.ConfirmationSelection alpha _ _) -> conjoin
  [R.decode (D.confirmationSelection alpha) (encode value) === Right value,
   validate value === fromIntegral (reference value),
   execute (Check value) Validate === fromIntegral (reference value)]

runWorkflow :: Bool -> B.ByteString -> Int -> B.ByteString -> IO (Either SomeException Int32,[(Word32,Word64)])
runWorkflow alpha bytes fault publication = do
  events <- newIORef []
  let native step index input = do
        when (not (B.null input)) (fail "unexpected confirmation payload")
        modifyIORef' events (++[(step,index)])
        when (fromIntegral step == fault) (fail "native confirmation fault")
        case step of
          0 | index == 0 -> pure bytes
          1 -> pure publication
          _ -> fail "unexpected confirmation effect"
  status <- try (execute (Check (D.ConfirmationWorkflow alpha native)) Validate)
  (,) status <$> readIORef events

workflow :: Property
workflow = forAll genSelection $ \value@(D.ConfirmationSelection alpha _ _) -> ioProperty $ do
  (status,events) <- runWorkflow alpha (encode value) (-1) B.empty
  pure $ conjoin [either (const (-1)) id status === 1,
    events === [(0,0),(1,fromIntegral (reference value))]]

boundaries :: Property
boundaries = once $ conjoin
  [let value = D.ConfirmationSelection alpha height (identity historical depth)
   in validate value === fromIntegral (reference value)
  | alpha <- [False,True], historical <- [False,True],
    height <- [minBound,-1,0,63,64,65,maxBound], depth <- [0,1,6,99,100,101,maxBound]]

malformed :: Property
malformed = once $ ioProperty $ do
  let bytes = encode (D.ConfirmationSelection False 64 (identity False 100))
      replace n value = B.take n bytes <> B.singleton value <> B.drop (n+1) bytes
      invalid = [B.take n bytes | n <- [0..B.length bytes-1]] ++ [B.snoc bytes 0] ++
        [replace n 2 | n <- [17,18,19]] ++ [replace 19 0] ++
        [B.take 8 bytes <> B.pack [253,8,0] <> B.drop 9 bytes,
         B.take 8 bytes <> B.pack [255] <> wordLE 8 maxBound <> B.drop 9 bytes]
  results <- mapM (\bad -> do
    (status,events) <- runWorkflow False bad (-1) B.empty
    pure $ conjoin [either (const 0) id status === (-1),events === [(0,0)]]) invalid
  pure (conjoin results)

faults :: Property
faults = once $ ioProperty $ do
  let bytes = encode (D.ConfirmationSelection False 64 (identity False 100))
  results <- mapM (\fault -> do
    (status,events) <- runWorkflow False bytes fault B.empty
    pure $ conjoin [property (isLeft status),events === take (fault+1) [(0,0),(1,6)]]) [0,1]
  (invalid,events) <- runWorkflow False bytes (-1) (B.singleton 0)
  pure $ conjoin (results ++ [either (const 0) id invalid === (-1),events === [(0,0),(1,6)]])

lazyMismatch :: Property
lazyMismatch = once $ property $ isNothing $ interpret
  (SomeOperation (Check (undefined :: D.ConfirmationPolicy)))
  (undefined :: DSL (Check D.ConfirmationWorkflow))

properties :: [(String,Property)]
properties = [("confirmation identity / copied fields and independent predicate",selection),
  ("confirmation identity / selected depth publication",workflow),
  ("confirmation identity / exact Alpha Beta and depth boundaries",boundaries),
  ("confirmation identity / malformed snapshots never publish",malformed),
  ("confirmation identity / native exceptions and publication framing",faults),
  ("confirmation identity / payload equality before DSL",lazyMismatch)]
