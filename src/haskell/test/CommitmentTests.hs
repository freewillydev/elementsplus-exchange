{-# LANGUAGE FlexibleInstances, TypeApplications #-}
module CommitmentTests (properties, commitmentFixture) where

import qualified Bmm as H
import Control.Exception (SomeException, try)
import Control.Monad (forM, unless)
import Control.Operation
import Control.Operation.Validation (Check(..))
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.Int (Int32, Int64)
import Data.IORef
import Data.Maybe (isNothing)
import Data.Word (Word32, Word64)
import qualified Drivechain as FFI
import Foreign.Ptr (nullFunPtr, nullPtr)
import Test.QuickCheck hiding (Result, output)
import Withdrawal (readLE, wordLE)
import Workflow (NativeBytes)

words8 :: Integral a => [a] -> B.ByteString
words8 = B.concat . map (wordLE 8 . fromIntegral)

payloadFor :: Word32 -> B.ByteString
payloadFor kind = prefix <> B.pack [1..32]
  where
    prefix = case kind of
      0 -> B.pack [0xd1,0x61,0x73,0x68,24]
      3 -> C.pack "ELMTP"
      _ -> B.empty

-- One native GetOp projection, shared by enclosing proof and lifecycle tests.
commitmentFixture :: Word32 -> NativeBytes
commitmentFixture kind step index input = do
  unless (index == 0) (ioError (userError "unexpected commitment index"))
  unless (B.null input || step == 23) (ioError (userError "unexpected commitment payload"))
  let payload = payloadFor kind
      result = if kind == 0 then B.reverse (B.drop 5 payload) else payload
  case step of
    0 -> pure (words8 [kind,24,1])
    11 -> pure (words8 [106,0,0,0 :: Word64])
    12 -> pure (words8 [B.length payload,0,0,0])
    13 -> pure (words8 [1,fromIntegral (B.length payload),readLE (B.take 4 payload),
      fromIntegral (B.index payload 4) :: Word64])
    14 -> pure (words8 [0,0,0,0 :: Word64])
    20 -> pure (wordLE 8 1)
    21 -> pure (wordLE 8 1)
    22 -> pure payload
    23 | input == result -> pure (wordLE 8 1)
    _ -> ioError (userError ("unexpected commitment projection " ++ show (step,input)))

data Row = Row Int64 Int64 Bool B.ByteString deriving Show
type Event = (Word32,Word64,B.ByteString)
data Result = Result Bool String B.ByteString [Event] deriving (Eq,Show)

rowGen :: Word32 -> Gen Row
rowGen kind = do
  first <- frequency [(5,pure 106),(1,elements [0,76,256])]
  second <- elements [32,37,76,77,78,79,256]
  ended <- arbitrary
  payload <- frequency [(3,pure (payloadFor kind)),(1,B.pack <$> listOf arbitrary),
    (1,pure (B.drop 1 (payloadFor kind))),(1,pure (B.take 5 (payloadFor kind)))]
  pure (Row first second ended payload)

errorText :: Word32 -> Int -> String
errorText 0 (-1) = "BMM successor coinbase has no M8 commitment for slot 24"
errorText 0 _ = "BMM successor coinbase contains multiple M8 commitments for slot 24"
errorText 1 (-1) = "sidechain block has no L1 parent commitment"
errorText 1 _ = "sidechain block has multiple L1 parent commitments"
errorText _ (-4) = "block coinbase contains a noncanonical ELMTP parent commitment"
errorText _ (-2) = "block coinbase contains multiple canonical drivechain parent commitments"
errorText _ _ = "block coinbase does not contain one canonical ELMTP drivechain parent commitment"

-- Procedural predecessor oracle, independent of the production state rules.
reference :: Word32 -> Int32 -> [Row] -> Result
reference kind slot rows = scan 0 Nothing (C.pack "old hash") [(0,0,B.empty)]
  where
    event step index = (step,fromIntegral index,B.empty)
    rejected code hash trace = let message = errorText kind code in
      Result False message hash (trace ++ [(90,0,C.pack message)])
    scan index found hash trace
      | index == length rows = case found of
          Nothing -> rejected (-1) hash trace
          Just (selected,payload) | kind == 3 -> Result True "old error" hash trace
            | otherwise -> let bytes = if kind == 0 then B.reverse (B.drop 5 payload) else payload in
                Result True "old error" bytes (trace ++ map (`event` selected) [20,21,22] ++ [(23,0,bytes)])
      | otherwise =
          let Row first second ended payload = rows !! index
              steps = trace ++ [event 11 index] ++ [event 12 index | first == 106] ++ [event 13 index]
              push = first == 106 && second <= 78
              tagged = push && B.take 5 payload == C.pack "ELMTP"
              matching = push && ended && if kind == 0 then B.length payload == 37 &&
                B.take 4 payload == B.pack [0xd1,0x61,0x73,0x68] && fromIntegral (B.index payload 4) == slot
                else B.length payload == 32
          in if kind == 3 && tagged && (B.length payload /= 37 || second /= 37 || not ended)
            then rejected (-4) hash steps
            else if (kind == 3 && tagged) || (kind /= 3 && matching)
              then case found of
                Just _ -> rejected (-2) hash steps
                Nothing -> scan (index+1) (Just (index,payload))
                  (if kind == 3 then B.drop 5 payload else hash)
                  (steps ++ [event 14 index | kind == 3])
              else scan (index+1) found hash steps

exercise :: Word32 -> Int32 -> [Row] -> Int -> IO (Maybe Bool,String,B.ByteString,[Event])
exercise kind slot rows fault = do
  seen <- newIORef []
  output <- newIORef (C.pack "old hash")
  message <- newIORef "old error"
  result <- try @SomeException $ execute (H.CommitmentSession $ \step index input -> do
    trace <- readIORef seen
    modifyIORef' seen (++[(step,index,input)])
    if length trace == fault then ioError (userError "native fault") else do
      let row = rows !! fromIntegral index
          Row first second ended payload = row
          reply = pure . words8
      case step of
        0 -> reply [fromIntegral kind,fromIntegral slot,fromIntegral (length rows) :: Int64]
        11 -> reply [first,0,0,0]
        12 -> reply [second,0,0,0]
        13 -> reply [fromIntegral (fromEnum ended),fromIntegral (B.length payload),
          fromIntegral (readLE (B.take 4 payload) :: Word64),
          if B.length payload > 4 then fromIntegral (B.index payload 4) else 0 :: Int64]
        14 -> writeIORef output (B.drop 5 payload) >> reply [0,0,0,0 :: Int64]
        20 -> pure (wordLE 8 1)
        21 -> pure (wordLE 8 1)
        22 -> pure payload
        23 -> writeIORef output input >> pure (wordLE 8 1)
        90 -> writeIORef message (C.unpack input) >> pure (wordLE 8 1)
        _ -> error "unexpected script request") H.ExtractSelectedCommitment
  (,,,) (either (const Nothing) (Just . (==1)) result) <$> readIORef message <*> readIORef output <*> readIORef seen

generated :: Property
generated = forAll (elements [0,1,3]) $ \kind -> forAll (elements [-1,0,24,255,256]) $ \slot ->
  forAll (resize 12 (listOf (rowGen kind))) $ \rows -> ioProperty $ do
    let expected@(Result accepted message hash trace) = reference kind slot rows
    actual <- exercise kind slot rows (-1)
    pure $ counterexample (show expected) (actual === (Just accepted,message,hash,trace))

faultPrefixes :: Property
faultPrefixes = once $ ioProperty $ conjoin <$> sequence
  [do (_,_,_,trace) <- exercise kind 24 rows (-1)
      conjoin <$> forM [0..length trace-1] (\fault -> do
        (accepted,_,_,actual) <- exercise kind 24 rows fault
        pure $ counterexample (show (kind,rows,fault)) $ conjoin
          [accepted === Nothing, actual === take (fault+1) trace])
  | kind <- [0,1,3],
    let valid = Row 106 (if kind == 1 then 32 else 37) True (payloadFor kind),
    rows <- [[],[valid],[valid,valid],[valid,Row 106 76 True (payloadFor kind)],
      [Row 0 256 False B.empty,valid,Row 256 256 True B.empty]]]

framing :: Property
framing = once $ ioProperty $ do
  cases <- forM [0,11,12,13,20,21,22,23] $ \badStep -> do
    result <- try @SomeException $ execute (H.CommitmentSession $ \step index input ->
      if step == badStep then pure B.empty else commitmentFixture 0 step index input) H.ExtractSelectedCommitment
    pure (either (const True) (const False) result)
  unknown <- FFI.elements_hs_replay_store 51 0 nullFunPtr nullPtr
  missing <- FFI.elements_hs_replay_store 50 0 nullFunPtr nullPtr
  pure (and cases && missing == -1 && unknown == -1 && isNothing
    (interpret (SomeOperation (undefined :: Check H.Header)) (undefined :: DSL H.CommitmentSession)))

payloadBeforePublication :: Property
payloadBeforePublication = once $ ioProperty $ conjoin <$> sequence
  [do seen <- newIORef []
      result <- try @SomeException $ execute (H.CommitmentSession $ \step index input -> do
        modifyIORef' seen (++[step])
        if step == 22 then pure (B.replicate size 0)
        -- Deliberately ignore the bytes: validation must not depend on a
        -- particular native publication callback forcing its argument.
        else if step == 23 then pure (wordLE 8 1)
        else commitmentFixture kind step index input) H.ExtractSelectedCommitment
      trace <- readIORef seen
      pure (conjoin [property (either (const True) (const False) result),
        trace === [0,11,12,13,20,21,22]])
  | kind <- [0,1], size <- [0..40], size /= if kind == 0 then 37 else 32]

properties :: [(String,Property)]
properties = [("BMM commitments / selection, exact diagnostics, byte order and effect traces",generated),
  ("BMM commitments / every native failure prefix",faultPrefixes),
  ("BMM commitments / strict framing, lazy mismatch and ABI rejection",framing),
  ("BMM commitments / payload validation precedes every publication callback",payloadBeforePublication)]
