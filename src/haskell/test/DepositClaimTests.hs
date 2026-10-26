{-# LANGUAGE TypeFamilies #-}
module DepositClaimTests (whole, lookupOrder, transaction, legacy, faults, malformed, lazyDispatch) where

import Control.Exception (SomeException, try)
import Control.Monad (when)
import Control.Operation
import Control.Operation.Validation
import Data.Bits ((.|.), shiftL)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.Int (Int32, Int64)
import Data.IORef (newIORef, readIORef, modifyIORef')
import Data.Word (Word32, Word64)
import Foreign.Marshal.Array (withArray)
import Foreign.Marshal.Utils (withMany)
import Foreign.Ptr (castPtr, nullFunPtr)
import qualified Deposit as D
import Test.QuickCheck hiding (witness, witnesses)
import Withdrawal (wordLE)
import Workflow (NativeBytes)

type Shape = (Word64,Word64,Word64,Word64)
type Event = (Word32,Word64,B.ByteString)
type Overrides = [((Word32,Word64),B.ByteString)]

withClaim :: Int -> Shape -> NativeBytes -> (D.Claim -> IO a) -> IO a
withClaim broken (inputs,index,witnesses,outputs) native action =
  let asset = B.replicate 32 3; genesis = B.replicate 32 4; txid = B.replicate 32 5
      stack = [wordLE 8 100,if broken == 1 then B.empty else asset,genesis,B.singleton 81,
        C.pack (if broken == 2 then "wrong" else "drivechain-deposit-v1"),txid]
  in withMany B.useAsCString stack $ \pointers -> withArray (map castPtr pointers) $ \fields ->
    withArray (map (fromIntegral . B.length) stack) $ \sizes ->
    B.useAsCString asset $ \a -> B.useAsCString genesis $ \g -> B.useAsCString txid $ \t ->
      action (D.Claim inputs index witnesses outputs
        (\mode -> D.DepositWitness 2100000000000000 4000000 mode 6 sizes fields
          (castPtr a) (castPtr g) (castPtr t) nullFunPtr) native)

request :: Word32 -> DSL D.Claim
request 0 = D.DiscoverCheckpoint
request 1 = D.AuthenticateLegacy
request 2 = D.VerifyClaimTransaction
request _ = error "invalid test request"

identity, record :: B.ByteString
(identity,record) = case D.legacyCheckpoints of
  (txid,previous,bytes):_ -> (txid <> previous <> wordLE 4 0,bytes)
  [] -> error "missing checkpoint fixture"

run :: Word32 -> Int -> Shape -> Overrides -> Int -> IO (Int32,[Event])
run mode broken dimensions overrides failure = do
  seen <- newIORef []
  let native step index input = do
        prior <- readIORef seen
        modifyIORef' seen (++ [(step,index,input)])
        when (length prior == failure) (ioError (userError "claim native fault"))
        pure $ case lookup (step,index) overrides of
          Just bytes -> bytes
          Nothing -> case step of
            0 -> identity
            1 -> B.empty
            10 -> wordLE 8 1
            11 -> wordLE 8 100
            12 -> B.empty
            20 -> wordLE 8 15
            21 -> wordLE 8 3
            22 -> wordLE 8 (if index == 0 then 23 else 15) <> wordLE 8 (if index == 0 then 90 else 10)
            23 -> wordLE 8 100
            _ -> error "unexpected native claim action"
  result <- try (withClaim broken dimensions native (\value -> execute value (request mode))) :: IO (Either SomeException Int32)
  (,) (either (const (-1)) id result) <$> readIORef seen

shape :: Shape
shape = (1,0,1,2)

expected :: Word32 -> [Event]
expected 0 = [(0,0,B.empty),(1,0,record)]
expected 1 = [(10,0,B.empty),(11,0,B.empty),(12,0,B.empty)]
expected 2 = [(20,0,B.empty),(21,0,B.singleton 1),(22,0,B.empty),(22,1,B.empty),(23,0,B.empty)]
expected _ = error "invalid trace mode"

whole :: Property
whole = once $ ioProperty $ conjoin <$> mapM (\mode -> (=== (0,expected mode)) <$> run mode 0 shape [] (-1)) [0..2]

lookupOrder :: Property
lookupOrder = forAll (elements [0,1,2,maxBound]) $ \inputs ->
  forAll (elements [0,1,2,maxBound]) $ \index -> forAll (choose (0,2)) $ \witnesses ->
  forAll (choose (0,2)) $ \broken -> forAll arbitrary $ \wrongVout -> ioProperty $ do
    let bounded = index < inputs && index < witnesses
        found = bounded && broken /= 2 && not wrongVout
        row = B.take 64 identity <> wordLE 4 (if wrongVout then 1 else 0)
        trace = if not bounded then [] else take (if found then 2 else 1) (expected 0)
    result <- run 0 broken (inputs,index,witnesses,0) [((0,0),row)] (-1)
    pure (result === (if found then 0 else 1,trace))

transaction :: Property
transaction = forAll (choose (0,3)) $ \inputs -> forAll (choose (0,2)) $ \index ->
  forAll (choose (0,3)) $ \witnesses -> forAll (choose (0,4)) $ \outputs ->
  forAll (choose (0,15)) $ \inputFlags -> forAll (choose (0,2)) $ \broken ->
  forAll (vectorOf 2 ((,) <$> choose (0,31) <*> elements [-1,0,10,90,100,2100000000000000 :: Int64])) $ \outs -> ioProperty $ do
    let bounded = inputs == 1 && index == 0 && witnesses == 1
        readWitness = bounded && inputFlags == 15
        decoded = broken == 0
        flags = if not bounded then 0 else if not readWitness then inputFlags else
          15 .|. (fromIntegral (fromEnum decoded) `shiftL` 4) .|. 96
        amount = if readWitness && decoded then 100 else 0
        selected = take (fromIntegral (min 2 outputs)) outs
        want = validate (D.AuthenticatedDeposit inputs index witnesses flags 100 amount outputs selected)
        overrides = ((20,0),wordLE 8 (fromIntegral inputFlags)) :
          [((22,i),wordLE 8 (fromIntegral f) <> wordLE 8 (fromIntegral n)) | (i,(f,n)) <- zip [0..] outs]
        trace = [(20,0,B.empty) | bounded] ++ [(21,0,B.singleton (if decoded then 1 else 0)) | readWitness] ++
          [(22,i,B.empty) | i <- take (length selected) [0..]] ++ [(23,0,B.empty)]
    result <- run 2 broken (inputs,index,witnesses,outputs) overrides (-1)
    pure (result === (want,trace))

legacy :: Property
legacy = forAll (choose (0,2)) $ \broken -> forAll arbitrary $ \destination ->
  forAll (elements [minBound,-1,0,99,100,101,maxBound :: Int64]) $ \amount -> ioProperty $ do
    let want = if broken /= 0 || amount /= 100 then 1 else if not destination then 2 else 0
        trace = take (if want == 0 then 3 else 2) (expected 1)
    result <- run 1 broken shape [((10,0),wordLE 8 (if destination then 1 else 0)),((11,0),wordLE 8 (fromIntegral amount))] (-1)
    pure (result === (want,trace))

faults :: Property
faults = once $ ioProperty $ conjoin <$> mapM (\(mode,index) -> do
  result <- run mode 0 shape [] index
  pure (result === (-1,take (index+1) (expected mode)))) [(mode,index) | mode <- [0..2],index <- [0..length (expected mode)-1]]

malformed :: Property
malformed = once $ ioProperty $ conjoin <$> mapM (\(mode,step,bytes,code) -> do
  (status,trace) <- run mode 0 shape [((step,0),bytes)] (-1)
  pure (counterexample (show (mode,step)) (conjoin [status === code,property (not (null trace)),
    let (lastStep,_,_) = last trace in lastStep === step])))
  [(0,0,B.replicate 67 0,-2),(0,1,B.singleton 0,-1),(1,10,wordLE 8 2,-1),
   (1,11,B.empty,-1),(1,12,B.singleton 0,-1),(2,20,wordLE 8 (2^(32 :: Int)+15),-1),
   (2,21,wordLE 8 4,-1),(2,22,B.replicate 15 0,-1),(2,22,wordLE 8 256 <> wordLE 8 90,-1),(2,23,B.empty,-1)]

lazyDispatch :: Property
lazyDispatch = ioProperty $ do
  missed <- execute (D.Claim 0 0 0 0 undefined undefined) D.DiscoverCheckpoint
  pure $ conjoin [missed === 1,
    (() <$ interpret (SomeOperation (undefined :: D.Claim)) D.DiscoverCheckpoint) === Just (),
    (() <$ interpret (SomeOperation (undefined :: Check D.PreviousSequence)) (undefined :: DSL D.Claim)) === Nothing]
