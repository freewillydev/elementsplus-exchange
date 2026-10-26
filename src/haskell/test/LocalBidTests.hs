{-# LANGUAGE FlexibleInstances, MultiParamTypeClasses, TypeFamilies #-}
module LocalBidTests (properties) where

import qualified Bmm as H
import Control.Exception (SomeException, throwIO, try)
import Control.Monad (forM, when)
import Control.Operation
import Control.Operation.Validation (Check(..))
import Control.Monad.Trans.Except (runExceptT, throwE)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.Int (Int32)
import Data.IORef
import Data.Maybe (isNothing)
import Data.Word (Word32, Word64)
import qualified Drivechain as FFI
import qualified ParentHeader as P
import Foreign.Ptr (nullFunPtr, nullPtr)
import Test.QuickCheck
import Withdrawal (wordLE)
import Workflow (NativeBytes)

type Event = (Word32,Word64)
money :: Word64
money = 2100000000000000

-- Synthetic native observations; the independent trace below specifies order.
fixture :: Int -> Integer -> (Event -> B.ByteString -> IO B.ByteString) -> IO (NativeBytes, IO [Event])
fixture route count alter = do
  events <- newIORef []
  outputs <- newIORef 2
  change <- newIORef (count*100000-250)
  let native step index input = do
        modifyIORef' events (++ [(step,index)])
        when (step == 0) (ioError (userError (C.unpack input)))
        when (if step == 6 then input /= B.pack [0x6a,68,0,0xbf,0,24] <> B.replicate 64 0
              else not (B.null input)) (ioError (userError "unexpected bid input bytes"))
        when (step == 26) (writeIORef outputs 3)
        when (step == 29) (writeIORef outputs 2)
        when (step == 35) (writeIORef change (toInteger index))
        outCount <- readIORef outputs
        amount <- readIORef change
        let value = case step of
              4 -> 100
              6 -> if route == 0 then 0 else 1
              10 -> if route <= 2 then 1 else 0
              12 -> if route == 1 || route == 3 then 1 else 0
              13 -> 250
              14 -> 1000
              15 -> 170
              16 -> count
              18 -> 6
              19 -> 100000
              26 -> 1
              27 -> outCount
              30 -> 2
              31 -> 0
              32 -> 100
              47 -> amount
              _ -> 1
            bytes | step == 1 = B.concat (map (wordLE 8) [24,100,250,202,1,1]) <> B.replicate 64 0
                  | step == 8 = B.pack [0x6a,68,0,0xbf,0,24] <> B.replicate 64 0
                  | otherwise = wordLE 8 (fromInteger value)
        alter (step,index) bytes
  pure (native,readIORef events)

traceFor :: Int -> Integer -> [Event]
traceFor route count = initial ++ restored ++ rest
  where
    steps = map (\s -> (s,0))
    current = steps [2,3,4,2]
    initial = [(1,0)] ++ current ++ steps [5,6]
    restored | route == 0 = []
             | otherwise = steps [7,30,16,27,31,8,10] ++
                (if route <= 2 then steps [32,11,12] else steps [12] ++
                  (if route == 3 then steps [13,14,15] else []) ++ concat [ [(2,0),(17,fromInteger i)] | i <- [0..count-1]])
    fee = if route == 3 then 452 else 250
    inputs = steps [16,34] ++ concat [ [(2,0),(20,fromInteger i),(17,fromInteger i),(18,0),(19,0)] | i <- [0..count-1]]
    fresh = steps [21,22,23,24] ++ [(25,fromInteger (fee+1000))] ++ steps [26,27] ++ [(28,1),(28,2),(29,0)]
    funding = (if route == 0 then fresh else []) ++ steps [30,27,31] ++
      (if route == 0 then steps [11,32] else []) ++ steps [33] ++ inputs ++
      [(35,fromInteger (count*100000-fee)),(16,0)] ++ [(36,fromInteger i) | i <- [0..count-1]] ++
      current ++ steps [37,38,39,40,41,42,43] ++ concat [ [(44,fromInteger i),(45,fromInteger i)] | i <- [0..count-1]] ++ steps [46]
    publication = inputs ++ steps [47,48] ++ current ++ steps [49,50,51,53] ++ current ++ steps [54]
    rest | route == 1 = steps [55]
         | route == 2 = publication
         | otherwise = funding ++ publication

workflow :: Property
workflow = once $ ioProperty $ do
  checks <- forM [(route,count) | route <- [0..4],count <- [1..3]] $ \(route,count) -> do
    let expected = traceFor route count
    (native,events) <- fixture route count (\_ -> pure)
    result <- execute (H.LocalBidWallet money native) H.SubmitLocalBid
    actual <- events
    failures <- forM [0..length expected-1] $ \fault -> do
      index <- newIORef 0
      (failed,observed) <- fixture route count $ \_ bytes -> do
        i <- readIORef index
        modifyIORef' index (+1)
        when (i == fault) (ioError (userError "injected bid callback fault"))
        pure bytes
      status <- try (execute (H.LocalBidWallet money failed) H.SubmitLocalBid) :: IO (Either SomeException Int32)
      prefix <- observed
      pure (conjoin [property (either (const True) (const False) status), prefix === take (fault+1) expected])
    pure (conjoin ([result === 1,actual === expected] ++ failures))
  pure (conjoin checks)

frames :: Property
frames = once $ ioProperty $ do
  checks <- forM [(route,step) | route <- [0..4],step <- [1..55],step /= 8,step /= 9,elem step (map fst (traceFor route 1))] $ \(route,changed) -> do
    (native,events) <- fixture route 1 (\(step,_) bytes -> pure (if step == changed then B.empty else bytes))
    status <- try (execute (H.LocalBidWallet money native) H.SubmitLocalBid) :: IO (Either SomeException Int32)
    actual <- events
    let expected = traceFor route 1
        prefix = takeWhile ((/= changed).fst) expected
    pure (conjoin [property (either (const True) (const False) status),
      actual === prefix ++ take 1 (drop (length prefix) expected)])
  nullStatus <- FFI.elements_hs_replay_store 27 money nullFunPtr nullPtr
  unknown <- FFI.elements_hs_replay_store 40 money nullFunPtr nullPtr
  pure (conjoin (checks ++ [nullStatus === -1,unknown === -1]))

replacement :: Property
replacement = forAll ((,,) <$> elements [-1,0,1,250,toInteger money,toInteger money+1] <*>
  elements [-1,0,1,1000,div (toInteger money) 100032,toInteger money] <*>
  elements [-1,0,1,170,100000,100001]) $ \(old,rate,size) -> ioProperty $ do
    (native,_) <- fixture 3 1 $ \(step,_) bytes -> pure $ case step of
      13 -> wordLE 8 (fromInteger old)
      14 -> wordLE 8 (fromInteger rate)
      15 -> wordLE 8 (fromInteger size)
      _ -> bytes
    result <- try (H.prepareLocalBid (H.LocalBidWallet money native)) :: IO (Either SomeException (Maybe (H.BidLimits,H.BidPlan)))
    let increment = div (rate*(size+32)+999) 1000
        fee = max 250 (old+increment)
        valid = old >= 0 && old <= toInteger money && rate > 0 && rate <= div (toInteger money) 100032 &&
          size > 0 && size <= 100000 && old <= toInteger money-increment && fee <= 452
    pure $ if valid then case result of
      Right (Just (_,plan)) -> plan === H.FundLocalBid True fee
      _ -> counterexample (show result) False
      else property (either (const True) (const False) result)

data Probe = Probe (IORef [String]) Bool
instance H.BidPreparation Probe where
  prepareLocalBid (Probe trace pending) = do
    modifyIORef' trace (++ ["prepare"])
    pure (if pending then Nothing else Just (H.BidLimits 100 250 452 (toInteger money),H.RetrySignedBid))
instance H.BidFunding Probe where
  fundLocalBid (Probe trace _) _ _ = modifyIORef' trace (++ ["fund"])
instance H.BidPublication Probe where
  publishLocalBid (Probe trace _) _ = modifyIORef' trace (++ ["publish"])

dispatch :: Property
dispatch = once $ ioProperty $ do
  trace <- newIORef []
  result <- H.submitLocalBid (Probe trace False)
  ordinary <- readIORef trace
  writeIORef trace []
  pending <- H.submitLocalBid (Probe trace True)
  early <- readIORef trace
  pure (conjoin [result === 1,pending === 1,ordinary === ["prepare","fund","publish"],early === ["prepare"],
    property (isNothing (interpret (SomeOperation (Check (H.NextBlockHeight 0 0))) (undefined :: DSL H.LocalBidWallet)))])

properties :: [(String,Property)]
properties =
  [("Local bid / complete routes and every callback failure prefix",workflow),
   ("Local bid / strict framing, null callback and unknown mode",frames),
   ("Local bid / replacement arithmetic and allowance",replacement),
   ("Local bid / capability reuse, early completion and lazy payload mismatch",dispatch),
   ("BMM submission / complete composition and every failure prefix",submission),
   ("BMM submission / strict admission, network and malformed frames",submissionFrames),
   ("BMM submission / capability reuse and lazy mismatch",submissionDispatch)]

submissionCapture :: Int -> Bool -> Bool -> Bool -> Int -> Maybe (Word32,B.ByteString)
  -> IO (Either String Int32,[Event])
submissionCapture route opened selected pinned fault altered = do
  events <- newIORef []
  poisoned <- newIORef Nothing
  (local,_) <- fixture route 2 (\_ -> pure)
  let native step index input = do
        readIORef poisoned >>= maybe (pure ()) throwIO
        trace <- readIORef events
        modifyIORef' events (++[(step,index)])
        let body = do
              when (length trace == fault) (ioError (userError "submission fault"))
              when (step == 0) (ioError (userError (C.unpack input)))
              bytes <- if step >= 2000 then pure (B.cons 1 (wordLE 8 (if step == 2042 then 64 else 1)))
                else if step >= 1000 then local (step-1000) index input else pure $ case step of
                  100 -> B.concat (map (wordLE 8) [24,250,100,1,1])
                  102 -> B.cons 4 (wordLE 4 0x7f000001)
                  104 -> wordLE 8 (if opened then 1 else 0)
                  109 -> wordLE 8 (if selected then 1 else 0)
                  111 -> wordLE 8 (if pinned then 1 else 0)
                  _ -> wordLE 8 1
              pure $ case altered of Just (at,replacementBytes) | at == step -> replacementBytes; _ -> bytes
        result <- try body
        case result of
          Left err -> writeIORef poisoned (Just (err :: SomeException)) >> throwIO err
          Right bytes -> pure bytes
  result <- try (execute (P.BmmBidSubmission money native) P.SubmitBmmBid) :: IO (Either SomeException Int32)
  trace <- readIORef events
  pure (either (Left . show) Right result,trace)

submissionTrace :: Int -> Bool -> Bool -> Bool -> [Event]
submissionTrace route opened selected pinned = map (\step -> (step,0))
  ([100,101,102,103,104] ++ [105 | not opened] ++ [106,107,108] ++
   map (+2000) [0,1,2,41,42,43,44,45,3] ++ [116,109] ++ [110 | selected] ++
   [111] ++ [112 | pinned] ++ [113]) ++
  [(1000+step,index) | (step,index) <- traceFor route 2] ++ [(114,0)]

submission :: Property
submission = once $ ioProperty $ do
  checks <- forM [(route,opened,selected,pinned) | route <- [0..4],opened <- [False,True],
    selected <- [False,True],pinned <- [False,True]] $ \(route,opened,selected,pinned) -> do
    let expected = submissionTrace route opened selected pinned
    actual <- submissionCapture route opened selected pinned (-1) Nothing
    faults <- forM [0..length expected-1] $ \position -> do
      (status,trace) <- submissionCapture route opened selected pinned position Nothing
      pure (conjoin [property (either (const True) (const False) status),trace === take (position+1) expected])
    pure (conjoin ((actual === (Right 1,expected)):faults))
  pure (conjoin checks)

submissionFrames :: Property
submissionFrames = once $ ioProperty $ do
  let trace = submissionTrace 0 False True True
      frame fields = B.concat (map (wordLE 8) fields)
      malformed = [(step,bytes) | step <- [100..114] ++ [116] ++ map (+2000) [0,1,2,41,42,43,44,45,3],
        bytes <- [B.empty,B.singleton 1,B.replicate 9 0]]
      invalid = [(100,frame fields) | fields <- [[maxBound,0,0,0,0],[256,250,100,1,1],
        [24,0,100,1,1],[24,money+1,100,1,1],[24,250,0,1,1],[24,250,100,0,1],[24,250,100,1,0]]] ++
        [(step,wordLE 8 0) | step <- [101,107,110,112]] ++ [(102,B.cons 4 (wordLE 4 0x08080808))] ++
        [(2002,B.cons 0 (C.pack "offline")),(2003,B.cons 1 (wordLE 8 0))]
  checks <- forM (malformed ++ invalid) $ \change@(step,_) -> do
    (status,events) <- submissionCapture 0 False True True (-1) (Just change)
    let prefix = takeWhile ((/= step).fst) trace ++ [(step,0)]
    pure (counterexample (show (change,status,events)) (conjoin
      [property (either (const True) (/=1) status),take (length prefix) events === prefix,
       property (step == 114 || notElem (114,0) events)]))
  nullStatus <- FFI.elements_hs_replay_store 28 money nullFunPtr nullPtr
  pure (conjoin (checks ++ [nullStatus === -1]))

data SubmissionProbe = SubmissionProbe (IORef [String]) Bool
instance P.BidAdmission SubmissionProbe where
  admitBidSubmission (SubmissionProbe events allowed) = do
    P.effect (\_ _ _ -> modifyIORef' events (++["admit"]) >> pure (wordLE 8 1)) 0 0
    when (not allowed) (throwE 0)
instance P.ParentNetwork SubmissionProbe where
  checkParentNetwork (SubmissionProbe events _) = P.effect
    (\_ _ _ -> modifyIORef' events (++["network"]) >> pure (wordLE 8 1)) 0 0
instance P.BidWalletSession SubmissionProbe where
  submitWalletBid (SubmissionProbe events _) = P.effect
    (\_ _ _ -> modifyIORef' events (++["wallet"]) >> pure (wordLE 8 1)) 0 0

submissionDispatch :: Property
submissionDispatch = once $ ioProperty $ do
  events <- newIORef []
  success <- runExceptT (P.submitBmmBid (SubmissionProbe events True))
  trace <- readIORef events
  writeIORef events []
  rejected <- runExceptT (P.submitBmmBid (SubmissionProbe events False))
  early <- readIORef events
  pure (conjoin [success === Right (),rejected === Left 0,trace === ["admit","network","wallet"],early === ["admit"],
    property (isNothing (interpret (SomeOperation (Check (H.NextBlockHeight 0 0))) (undefined :: DSL P.BmmBidSubmission)))])
