{-# LANGUAGE TypeApplications #-}
module SignetSessionTests (properties, signetFixture) where

import qualified Bmm as H
import Control.Exception (SomeException, try)
import Control.Monad (forM, unless, when)
import Control.Operation
import Control.Operation.Validation (Check(..))
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.IORef
import Data.Maybe (isNothing)
import Data.Word (Word32, Word64)
import Test.QuickCheck hiding (output)
import Withdrawal (wordLE)
import Workflow (NativeBytes)

words8 :: [Word64] -> B.ByteString
words8 = B.concat . map (wordLE 8)

-- Empty signet solution, authentic witness prefix, valid replacement proof.
signetFixture :: NativeBytes
signetFixture step index input = do
  unless (index == 0) (error "unexpected fixture index")
  let fields = B.concat (map (wordLE 4) [0,0,0,0,0,106])
  unless (input == if step >= 20 && step <= 25 then fields else B.empty)
    (error "unexpected fixture payload")
  pure $ case step of
    40 -> wordLE 8 1
    41 -> words8 [38,0xeda921aa246a]
    10 -> words8 [0,1,0,0]
    53 -> wordLE 8 0
    50 -> words8 [1,1,1,0]
    _ -> wordLE 8 1

data Scenario = Scenario Bool Int Word64 Bool Bool Bool deriving Show

scenarios :: Gen Scenario
scenarios = Scenario <$> arbitrary <*> choose (0,3) <*> elements [0,1,2] <*> arbitrary <*> arbitrary <*> arbitrary

messages :: [String]
messages = ["BMM parent block has no Bitcoin witness commitment",
  "BMM parent block has a malformed signet commitment script",
  "BMM parent block signet solution contains trailing data",
  "BMM parent block signet solution cannot be decoded",
  "BMM signet proof does not authenticate exactly the coinbase",
  "BMM parent block signet solution is invalid"]

-- This ordered predecessor oracle does not call production transition rules.
reference :: Scenario -> (Bool,[Word32],String)
reference (Scenario found script decoding merkle coinbase signature)
  | not found = reject 0 [0,40,41,42]
  | script == 2 = reject 1 (selection ++ [54,10])
  | hasSolution && decoding /= 0 = reject (if decoding == 1 then 2 else 3) decoded
  | not merkle = reject 4 (decoded ++ [50])
  | not coinbase = reject 4 (decoded ++ [50,51])
  | not signature = reject 5 verified
  | otherwise = (True,verified ++ [1],"old error")
  where
    reject which trace = (False,trace ++ [90,1],messages !! which)
    selection = [0,40,41,42]
    hasSolution = script /= 0
    extraction = if script == 0 then [54,10] else
      [54,10,11,12] ++ (if script == 3 then [10,12] else []) ++ [10,14]
    assembled = selection ++ extraction ++ [20..25] ++ [53]
    decoded = assembled ++ if hasSolution then
      (if decoding == 2 then [60,61,64] else [60,61,62,63,64]) else []
    verified = decoded ++ [50,51] ++ [30..33] ++ [52]

exercise :: Scenario -> Int -> Bool -> IO (Maybe Bool,[Word32],String)
exercise (Scenario found script decoding merkle coinbase signature) fault malformed = do
  seen <- newIORef []
  cursor <- newIORef (0 :: Int)
  message <- newIORef "old error"
  outcome <- try @SomeException $ execute (H.SignetSession $ \step index input -> do
    trace <- readIORef seen
    modifyIORef' seen (++[step])
    when (index /= if step == 42 && not found then maxBound else 0) (error "wrong signet index")
    unless (input == if step >= 20 && step <= 25 then B.concat (map (wordLE 4) [0,0,0,0,0,106])
      else if step == 90 then input else B.empty) (error "wrong signet input")
    if length trace == fault then if malformed then pure B.empty else ioError (userError "native failure")
    else do
      when (step == 90) (writeIORef message (C.unpack input))
      position <- readIORef cursor
      when (step == 10) (modifyIORef' cursor (+1))
      pure $ case step of
        40 -> wordLE 8 1
        41 -> words8 [38,if found then 0xeda921aa246a else 0]
        42 -> wordLE 8 (if found then 1 else 0)
        10 | script == 2 -> words8 [0,0,0,0]
           | script /= 0 && position < (if script == 3 then 2 else 1) -> words8 [1,0,6,0xa2dac7ec]
           | otherwise -> words8 [0,1,0,0]
        53 -> wordLE 8 (if script == 0 then 0 else 1)
        61 | decoding == 2 -> wordLE 8 2
        63 -> wordLE 8 decoding
        50 -> words8 [if merkle then 1 else 0,1,1,0]
        51 -> wordLE 8 (if coinbase then 1 else 0)
        52 -> wordLE 8 (if signature then 1 else 0)
        _ -> wordLE 8 1) H.VerifySignetSession
  trace <- readIORef seen
  diagnostic <- readIORef message
  pure (either (const Nothing) Just outcome,trace,diagnostic)

prop_reference :: Property
prop_reference = forAll scenarios $ \scenario -> ioProperty $ do
  actual <- exercise scenario (-1) False
  let (result,trace,message) = reference scenario
  pure (counterexample (show (scenario,actual,(result,trace,message))) (actual == (Just result,trace,message)))

prop_faults :: Bool -> Property
prop_faults malformed = once $ ioProperty $ do
  checks <- forM [Scenario True 0 0 True True True,Scenario True 1 0 True True True,
    Scenario True 3 0 True True True,Scenario False 0 0 True True True,
    Scenario True 2 0 True True True,Scenario True 1 1 True True True,
    Scenario True 1 0 False True True,Scenario True 1 0 True False True,
    Scenario True 1 0 True True False] $ \scenario -> do
      let (_,baseline,_) = reference scenario
      forM (zip [0..] baseline) $ \(position,step) -> do
        (result,trace,message) <- exercise scenario position malformed
        let caught = step >= 60 && step <= 63
            cleanup = if step `elem` [0,1] then [] else if caught then [64,90,1] else [1]
        pure (counterexample (show (scenario,position,result,trace))
          (trace == take (position+1) baseline ++ cleanup &&
            if caught then result == Just False && message == messages !! 3 else isNothing result))
  pure (conjoin (concat checks))

prop_replies :: Property
prop_replies = once $ ioProperty $ do
  let invalid = [(40,wordLE 8 (2^(32::Int))), (41,B.replicate 15 0),
        (42,wordLE 8 2), (10,words8 [2,1,0,0]), (10,words8 [0,2,0,0]),
        (10,words8 [1,0,maxBound,0]), (10,words8 [1,0,1,0x100000000]),
        (50,words8 [1,0,1,0]), (50,words8 [1,1,2,0]), (50,words8 [1,1,1,1])]
  checks <- forM invalid $ \(changed,bytes) -> do
    seen <- newIORef []
    result <- try @SomeException $ execute (H.SignetSession $ \step index input -> do
      modifyIORef' seen (++[step])
      if step == changed then pure bytes else if step == 90 then pure (wordLE 8 1)
        else signetFixture step index input) H.VerifySignetSession
    trace <- readIORef seen
    pure (last trace == 1 && 52 `notElem` trace && either (const True) not result)
  pure (and checks)

prop_mismatch :: Property
prop_mismatch = once $ property $ isNothing $
  interpret (SomeOperation (undefined :: Check H.Header)) (undefined :: DSL H.SignetSession)

properties :: [(String,Property)]
properties = [("signet workflow procedural parity",prop_reference),
  ("signet exception prefixes and decoder scope",prop_faults False),
  ("signet malformed frame prefixes and decoder scope",prop_faults True),
  ("signet projection bounds and Merkle gates",prop_replies),
  ("signet payload mismatch stays lazy",prop_mismatch)]
