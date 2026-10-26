{-# LANGUAGE TypeFamilies #-}
module DepositConstructionTests (transcript, boundaries, exceptions, recovery, malformed, lazyDispatch, stages) where

import Control.Exception (SomeException, try)
import Control.Monad (when)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Except (runExceptT, throwE)
import Control.Operation
import Control.Operation.Validation
import Data.Bits (testBit)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.IORef (IORef, newIORef, readIORef, modifyIORef')
import Data.Int (Int32, Int64)
import Data.Word (Word8, Word32, Word64)
import qualified Deposit as D
import Test.QuickCheck
import Withdrawal (wordLE)

data Candidate = Candidate Word8 Bool Bool B.ByteString Bool deriving Show
data Spec = Spec Int64 Int64 Word32 Int32 Word64 [Candidate] Int64 (Maybe Word64) deriving Show
type Event = (Word32,Word64,B.ByteString)
type Override = [((Word32,Word64),B.ByteString)]

treasury :: Word8 -> Word8 -> B.ByteString
treasury opcode slot = B.pack [opcode,1,slot,0x51]

good :: Candidate
good = Candidate 2 True True (treasury 0xb4 24) True

fixture :: Spec -> Int -> Override -> IO (Int32,[Event])
fixture (Spec sequenceNumber height flags slot source candidates tip badHeader) failure overrides = do
  seen <- newIORef []
  let native step index input = do
        history <- readIORef seen
        modifyIORef' seen ((step,index,input):)
        when (length history == failure) (ioError (userError "native reconstruction failure"))
        case lookup (step,index) overrides of
          Just reply -> pure reply
          Nothing -> do
            let word = pure . wordLE 8
                boolean = word . fromIntegral . fromEnum
            case step of
              0 -> pure B.empty
              1 -> boolean (testBit source 0)
              2 -> boolean (testBit source 1)
              3 -> boolean (testBit source 2)
              4 -> pure B.empty
              10 -> word (fromIntegral (length candidates))
              11 -> pure B.empty
              12 -> word (fromIntegral tip)
              20 -> pure B.empty
              21 -> boolean (Just index /= badHeader)
              22 -> pure B.empty
              109 -> ioError (userError "original fatal candidate exception")
              _ | step >= 101 && step <= 105 -> do
                let Candidate kind decoded bounded script stored = candidates !! fromIntegral index
                body <- case step of
                  101 -> pure (wordLE 8 (if kind /= 0 then 1 else 0) <> wordLE 8 (if kind == 2 then 1 else 0))
                  102 -> boolean stored
                  103 -> boolean decoded
                  104 -> boolean bounded
                  105 -> pure script
                  _ -> error "unreachable candidate action"
                pure (B.cons 0 body)
              _ -> ioError (userError ("unexpected construction callback " ++ show (step,index)))
  outcome <- try (execute (D.Construction sequenceNumber height flags slot native) D.ReconstructEvidence)
    :: IO (Either SomeException Int32)
  (,) (either (const (-1)) id outcome) . reverse <$> readIORef seen

-- Independent ordered trace, including the historical candidate-skip behavior.
reference :: Spec -> (Int32,[Event])
reference (Spec sequenceNumber height flags slot source candidates tip badHeader)
  | sequenceNumber <= 0 || height < 0 || flags /= 3 = (1,[])
  | otherwise = sourceChecks 1 [event 0 0]
  where
    event step index = (step,index,B.empty)
    sourceChecks step trace
      | step == 4 = search 0 False (trace ++ [event 4 0,event 10 0]) candidates
      | testBit source (fromIntegral step-1) = sourceChecks (step+1) (trace ++ [event step 0])
      | otherwise = (2,trace ++ [event step 0])
    search _ found trace []
      | not found = (3,trace)
      | tip < 0 || tip < height || toInteger tip-toInteger height > 2016 = (5,published)
      | otherwise = headers (fromIntegral height) (published ++ [event 20 0])
      where published = trace ++ [(11,0,wordLE 8 (fromIntegral (sequenceNumber-1))),event 12 0]
    search index found trace (Candidate kind decoded bounded script stored:rest) =
      let checks = [(101,kind == 2),(103,decoded),(104,bounded),
            (105,slot >= 0 && slot <= 255 && script == treasury 0xb4 (fromIntegral slot))]
          visit observed []
            | found = (4,observed)
            | otherwise = search (index+1) stored (observed ++ [event 102 index]) rest
          visit observed ((step,valid):remaining)
            | valid = visit (observed ++ [event step index]) remaining
            | otherwise = search (index+1) found (observed ++ [event step index]) rest
      in visit trace checks
    headers current trace
      | current > fromIntegral tip = (0,trace)
      | Just current == badHeader = (6,trace ++ [event 21 current])
      | otherwise = headers (current+1) (trace ++ [event 21 current,event 22 0])

specs :: Gen Spec
specs = do
  sequenceNumber <- frequency [(4,choose (1,1000)),(1,elements [minBound,-1,0,maxBound])]
  height <- frequency [(4,choose (0,20)),(1,elements [-1,maxBound])]
  flags <- frequency [(4,pure 3),(1,elements [0,1,2,4,maxBound])]
  slot <- frequency [(4,pure 24),(1,elements [-1,0,255,256,maxBound])]
  source <- frequency [(4,pure 7),(1,choose (0,7))]
  candidates <- resize 6 (listOf (frequency [(3,pure good),(1,Candidate <$> choose (0,2) <*> arbitrary <*> arbitrary <*>
    elements [treasury 0xb4 24,treasury 0xb7 24,treasury 0xb4 255,B.empty,B.replicate 5 0] <*> arbitrary)]))
  tip <- elements [height,if height == maxBound then height else height+2,0,2016,2017,maxBound,-1]
  badHeader <- elements [Nothing,Just 0,Just (fromIntegral height),Just (fromIntegral height+1)]
  pure (Spec sequenceNumber height flags slot source candidates tip badHeader)

transcript :: Property
transcript = withMaxSuccess 600 $ forAll specs $ \spec -> ioProperty $ do
  observed <- fixture spec (-1) []
  pure (observed === reference spec)

exceptions :: Property
exceptions = withMaxSuccess 300 $ forAll specs $ \spec -> forAll (choose (0,80)) $ \failure -> ioProperty $ do
  let baseline@(_,trace) = reference spec
  actual@(status,seen) <- fixture spec failure []
  pure $ if failure >= length trace then actual === baseline
    else conjoin [status === -1,seen === take (failure+1) trace]

boundaries :: Property
boundaries = once $ ioProperty $ do
  let windows = [(0,0),(0,2016),(0,2017),(10,9),(10,11),(maxBound,maxBound),
        (maxBound-2016,maxBound),(maxBound-2017,maxBound),(0,-1),(-1,0)]
      cases = [Spec sequenceNumber first 3 24 7 [good] tip bad
        | sequenceNumber <- [minBound,0,1,maxBound],(first,tip) <- windows,
          bad <- [Nothing,Just (fromIntegral first),Just (fromIntegral tip)]] ++
        [Spec 7 10 flags slot source candidates 11 Nothing
        | (flags,slot,source,candidates) <- [(0,24,7,[good]),(3,-1,7,[good]),
            (3,256,7,[good]),(3,24,6,[good]),(3,24,5,[good]),(3,24,3,[good]),
            (3,24,7,[]),(3,24,7,[good,good]),(3,24,7,[Candidate 2 True True (treasury 0xb7 24) True])]]
  results <- mapM (\spec -> fixture spec (-1) []) cases
  pure (conjoin [counterexample (show spec) (actual === reference spec) | (spec,actual) <- zip cases results])

recovery :: Property
recovery = once $ ioProperty $ do
  let spec = Spec 7 10 3 24 7 [good,good] 11 Nothing
  results <- sequence [do
    outcome <- fixture spec (-1) [((step,0),reply)]
    pure (step,fatal,outcome)
    | step <- [101..105],(fatal,reply) <-
      [(False,B.cons 1 (C.pack "temporary RPC failure")),(False,B.singleton 2),
       (True,B.cons 1 (C.pack "prefix multiple slot CTIP suffix"))]]
  pure $ conjoin [counterexample (show step) $ if fatal
    then conjoin [status === -1,last trace === (109,0,B.empty),property (null [() | (11,_,_) <- trace])]
    else conjoin [status === 0,property ((102,1,B.empty) `elem` trace),
      property (not ((109,0,B.empty) `elem` trace))]
    | (step,fatal,(status,trace)) <- results]

malformed :: Property
malformed = once $ ioProperty $ do
  let spec = Spec 7 10 3 24 7 [good] 11 Nothing
      cases = [((0,0),B.singleton 0),((1,0),B.replicate 7 0),((2,0),wordLE 8 2),
        ((10,0),B.replicate 9 0),((101,0),B.empty),((101,0),B.singleton 3),
        ((101,0),B.pack [2,0]),((101,0),B.cons 0 (B.replicate 15 0)),
        ((101,0),B.cons 0 (wordLE 8 2 <> wordLE 8 1)),
        ((103,0),B.cons 0 (wordLE 8 2)),((104,0),B.singleton 0),
        ((102,0),B.cons 0 (wordLE 8 2)),((11,0),B.singleton 0),
        ((12,0),B.empty),((20,0),B.singleton 0),((21,10),wordLE 8 2),((22,0),B.singleton 0)]
  results <- mapM (\entry -> fixture spec (-1) [entry]) cases
  pure $ conjoin [counterexample (show key) (conjoin [status === -1,
    let (step,index,_) = last trace in (step,index) === key])
    | ((key,_),(status,trace)) <- zip cases results]

lazyDispatch :: Property
lazyDispatch = (() <$ interpret (SomeOperation (undefined :: D.Construction)) D.ReconstructEvidence) === Just ()
  .&&. ((() <$ interpret (SomeOperation (undefined :: Check D.PreviousSequence)) (undefined :: DSL D.Construction)) === Nothing)

data StageProbe = StageProbe Int (IORef [Int])
record :: Int -> StageProbe -> D.ConstructionCheck ()
record phase (StageProbe failure seen) = do
  liftIO (modifyIORef' seen (++ [phase]))
  when (phase == failure) (throwE 1)
instance D.DepositSource StageProbe where readDepositSource = record 0
instance D.PriorTreasury StageProbe where readPriorTreasury = record 1
instance D.ConfirmationHeaders StageProbe where readConfirmationHeaders = record 2

stages :: Property
stages = forAll (choose (-1,2)) $ \failure -> ioProperty $ do
  seen <- newIORef []
  status <- runExceptT (D.constructEvidence (StageProbe failure seen))
  trace <- readIORef seen
  pure $ conjoin [status === if failure < 0 then Right () else Left 1,
    trace === [0..if failure < 0 then 2 else failure]]
