{-# LANGUAGE ForeignFunctionInterface, TypeFamilies #-}
module DepositParsingTests (whole, rejections, faults, malformed, lazyDispatch, stages) where

import Control.Exception (SomeException, try)
import Control.Monad (when)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Except (runExceptT, throwE)
import Control.Operation
import Control.Operation.Validation
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.IORef (IORef, newIORef, readIORef, modifyIORef')
import Data.Int (Int32, Int64)
import Data.Word (Word32, Word64)
import Foreign.Marshal.Array (withArray)
import Foreign.Marshal.Utils (withMany)
import Foreign.Ptr (FunPtr, castPtr)
import qualified Deposit as D
import Test.QuickCheck hiding (witness, witnesses)
import Withdrawal (wordLE)

foreign import ccall "&reference_transaction_hash" hasher :: FunPtr D.HashTransaction
foreign import ccall "&reference_evidence_decode" decoder :: FunPtr D.DecodeEvidence

type Event = (Word32,Word64,B.ByteString)
type Override = [((Word32,Word64),B.ByteString)]
type ParseResult = (Int32,[Event])

expected :: [Event]
expected = [(step,index,if step == 13 then wordLE 8 100 else B.empty) |
  (step,index) <- [(0,0),(1,0),(2,0),(3,0),(4,0),(5,0),(5,1),(6,0),(7,0),
    (8,0),(9,0),(10,0),(11,0),(8,1),(12,0),(13,0),(14,0),(15,0),(16,0),
    (20,0),(21,0),(20,1),(21,1),(22,1),(23,1),(24,0)]]

fixture :: Int -> Override -> (Int64,Int64,Int64,Int64) -> IO ParseResult
fixture failure overrides (decodeStatus,current,prior,headerCount) =
  let asset = B.replicate 32 3
      genesis = B.replicate 32 4
      txid = B.replicate 32 5
      stack = [wordLE 8 100,asset,genesis,B.singleton 81,C.pack "drivechain-deposit-v2",
        txid,B.singleton 1,B.singleton 1,wordLE 8 1,wordLE 8 0,B.singleton 1]
  in withMany B.useAsCString stack $ \pointers -> withArray (map castPtr pointers) $ \fields ->
    withArray (map (fromIntegral . B.length) stack) $ \sizes ->
    B.useAsCString asset $ \assetPtr -> B.useAsCString genesis $ \genesisPtr -> B.useAsCString txid $ \txidPtr ->
    withArray [decodeStatus,current,prior,headerCount,0] $ \context -> do
      seen <- newIORef []
      let native step index input = do
            previous <- readIORef seen
            modifyIORef' seen ((step,index,input):)
            when (length previous == failure) (ioError (userError "parsing native fault"))
            case lookup (step,index) overrides of
              Just bytes -> pure bytes
              Nothing -> pure $ case step of
                0 -> B.empty
                1 -> wordLE 8 1
                2 -> wordLE 8 1
                3 -> wordLE 8 1
                4 -> wordLE 8 15 <> wordLE 8 1 <> wordLE 8 2
                5 -> wordLE 8 3
                6 -> B.empty
                7 -> wordLE 8 2
                8 -> wordLE 8 (if index == 0 then 1 else 0)
                9 -> wordLE 8 1
                10 -> B.pack [0xb4,1,24,0x51]
                11 -> B.empty
                12 -> wordLE 8 100
                13 -> B.empty
                14 -> B.pack [0xb4,1,24,0x51]
                15 -> wordLE 8 200
                16 -> wordLE 8 2
                20 -> wordLE 8 (if index == 0 then 0 else 106)
                21 -> wordLE 8 (1+512+1024)
                22 -> wordLE 8 1
                23 -> wordLE 8 1
                24 -> B.empty
                _ -> error ("unexpected parsing callback " ++ show (step,index))
          evidence = D.DeterministicEvidence 4000000 11 sizes fields (castPtr txidPtr) hasher decoder (castPtr context)
          witness = D.DepositWitness 2100000000000000 4000000 1 11 sizes fields
            (castPtr assetPtr) (castPtr genesisPtr) (castPtr txidPtr) hasher
      result <- try (execute (D.Parsing 1 0 1 evidence witness native) D.ParseDeposit) :: IO (Either SomeException Int32)
      (,) (either (const (-1)) id result) . reverse <$> readIORef seen

validState :: (Int64,Int64,Int64,Int64)
validState = (1,1,0,2)

whole :: Property
whole = once $ ioProperty $ (=== (0,expected)) <$> fixture (-1) [] validState

rejections :: Property
rejections = once $ ioProperty $ do
  let word step index value code = (((step,index),wordLE 8 value),code)
      cases = [word 1 0 0 2,word 2 0 0 2,word 3 0 0 2,
        (((4,0),wordLE 8 14 <> wordLE 8 1 <> wordLE 8 2),0x201),
        (((4,0),wordLE 8 13 <> wordLE 8 1 <> wordLE 8 2),0x202),
        word 5 0 0 0x203,word 5 1 1 0x204,
        (((14,0),B.pack [0xb7,1,24,0x51]),0x205),
        word 8 0 0 0x206,word 8 1 1 0x206,
        word 12 0 0 0x207,word 15 0 100 0x207,word 15 0 201 0x207,
        word 22 1 0 0x301,word 20 0 106 0x302]
  rows <- mapM (\(entry,code) -> do
    (status,trace) <- fixture (-1) [entry] validState
    pure (counterexample (show entry) (conjoin [status === code,property (all (\(step,_,_) -> step /= 24) trace)]))) cases
  evidence <- mapM (\(state,code) -> do
    result <- fixture (-1) [] state
    pure (counterexample (show state) (result === (code,[]))))
    [((0,1,0,2),0x104),((1,0,0,2),0x105),((1,1,0,0),0x106),((1,1,0,2018),0x106),((-1,1,0,2),-2)]
  pure (conjoin (rows ++ evidence))

faults :: Property
faults = withMaxSuccess 100 $ forAll (choose (0,length expected-1)) $ \failure -> ioProperty $ do
  (status,trace) <- fixture failure [] validState
  let (step,_,_) = expected !! failure
      code | step == 5 = -3
           | step >= 20 && step <= 23 = -4
           | otherwise = -1
  pure (conjoin [status === code,trace === take (failure+1) expected])

malformed :: Property
malformed = once $ ioProperty $ do
  let cases = [(((0,0),B.singleton 0),-1),(((1,0),wordLE 8 2),-1),
        (((4,0),B.replicate 23 0),-1),(((5,0),wordLE 8 (2^(32 :: Int)+3)),-3),
        (((5,0),wordLE 8 4),-3),(((7,0),B.empty),-1),
        (((8,0),wordLE 8 2),-1),(((11,0),B.singleton 0),-1),
        (((13,0),B.singleton 0),-1),(((20,0),wordLE 8 (2^(32 :: Int)+106)),-4),
        (((21,0),wordLE 8 2048),-4),(((22,1),wordLE 8 2),-4),
        (((23,1),wordLE 8 0),-4),(((24,0),B.singleton 0),-1)]
  results <- mapM (\(entry,code) -> do
    (status,trace) <- fixture (-1) [entry] validState
    let (step,index,_) = last trace
    pure (counterexample (show entry) (conjoin [status === code,(step,index) === fst entry]))) cases
  pure (conjoin results)

lazyDispatch :: Property
lazyDispatch = ioProperty $ do
  invalid <- mapM (\(inputs,index,witnesses) ->
    execute (D.Parsing inputs index witnesses undefined undefined undefined) D.ParseDeposit)
    [(0,0,0),(1,1,1),(1,0,0),(maxBound,maxBound,maxBound)]
  pure $ conjoin [invalid === replicate 4 1,
    (() <$ interpret (SomeOperation (undefined :: D.Parsing)) D.ParseDeposit) === Just (),
    (() <$ interpret (SomeOperation (undefined :: Check D.PreviousSequence)) (undefined :: DSL D.Parsing)) === Nothing]

data Probe = Probe Int (IORef [Int])
record :: Int -> Probe -> D.ConstructionCheck ()
record step (Probe failure seen) = do
  liftIO (modifyIORef' seen (++ [step]))
  when (step == failure) (throwE 2)
instance D.EvidenceParsing Probe where parseEvidence = record 0
instance D.InclusionVerification Probe where verifyInclusion = record 1
instance D.TreasuryVerification Probe where verifyTreasury = record 2
instance D.DestinationSelection Probe where selectDestination = record 3
instance D.DepositPublication Probe where publishDeposit = record 4

stages :: Property
stages = forAll (choose (-1,4)) $ \failure -> ioProperty $ do
  seen <- newIORef []
  result <- runExceptT (D.parseDeposit (Probe failure seen))
  trace <- readIORef seen
  pure $ conjoin [result === if failure == -1 then Right () else Left 2,
    trace === [0..if failure == -1 then 4 else failure]]
