{-# LANGUAGE FlexibleInstances, MultiParamTypeClasses, TypeApplications, TypeFamilies #-}
module BmmChainTests (properties) where

import qualified Bmm as H
import qualified BmmConstants as K
import CommitmentTests (commitmentFixture)
import Control.Exception (SomeException, try)
import Control.Monad (forM, unless, when)
import Control.Operation
import Control.Operation.Validation (Check(..), validate)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.Bits (testBit)
import Data.Int (Int32)
import Data.IORef
import Data.Maybe (isNothing)
import Data.Word (Word32, Word64)
import qualified Drivechain as FFI
import Foreign.Ptr (nullFunPtr, nullPtr)
import Test.QuickCheck hiding (output)
import Withdrawal (wordLE)

data Event = Fact Word32 | Header | Load | Effective | SameCheckpoint | Store Int
  | Required | Decode | Parent | Verify Bool | Error String | ReadError deriving (Eq,Show)
data Fixture = Fixture Word32 Word32 Int Bool Bool deriving Show
data Probe = Probe Fixture (IORef [Event]) (IORef String) Int

event :: Probe -> Event -> IO ()
event (Probe _ events _ fault) value = do
  prior <- readIORef events
  modifyIORef' events (++[value])
  when (length prior == fault) (ioError (userError "chain observation fault"))
method :: Probe -> Event -> Int -> IO Bool
method value@(Probe (Fixture _ methods _ specific _) _ errorText _) action bit = do
  event value action
  let accepted = testBit methods bit
  when (specific && not accepted) (writeIORef errorText "specific subworkflow rejection")
  pure accepted
instance H.ChainObservations Probe where
  chainFact value@(Probe (Fixture facts _ _ _ _) _ _ _) step =
    event value (Fact step) >> pure (testBit facts (fromIntegral step))
  chainFailure value@(Probe _ _ errorText _) message = event value (Error message) >> writeIORef errorText message
  chainError value@(Probe _ _ errorText _) = event value ReadError >> readIORef errorText
instance H.ChainStateAccess Probe where
  loadChainState value@(Probe (Fixture _ _ load _ _) _ _ _) = do
    event value Load
    pure $ case load of 0 -> Right False; 1 -> Right True; 2 -> Left "storage rejection"; _ -> Left ""
  effectiveChainState value = method value Effective 1
  matchesChainCheckpoint value = method value SameCheckpoint 2
  storeChainState value output = event value (Store (fromEnum output))
instance H.ChainProofAccess Probe where
  checkChainHeader value = method value Header 0
  chainProofRequired value = method value Required 3
  decodeChainProof value = method value Decode 4
  extractChainParent value = method value Parent 5
  verifyChainProof value entries = method value (Verify entries) (if entries then 7 else 6)

-- Independent branch oracle for the previous C++ connect/disconnect functions.
-- This deliberately does not call StateFlow, StateWorkflow or Lifecycle.
reference :: Bool -> Probe -> IO Int32
reference disconnect value = if disconnect then disconnectState else connectState
  where
    fact = H.chainFact value
    reject message = H.chainFailure value message >> pure 0
    store output = H.storeChainState value output >> pure 1
    checkpoint = do
      first <- fact 10
      if not first then pure False else do
        previous <- fact 11
        if not previous then pure False else fact 12
    load = do
      answer <- H.loadChainState value
      pure $ either (\e -> (False,e)) (\found -> (found,"")) answer
    connectState = do
      native <- fact 0
      if native then do
        header <- H.checkChainHeader value
        if not header then pure 0 else do
          bytes <- fact 2
          stored <- if bytes then pure True else fact 5
          if stored then reject "historical signet BMM state is not valid on native Elements" else pure 1
      else do
        initial <- checkpoint
        if initial then do
          (found,message) <- load
          if found then reject "public BMM checkpoint cannot overwrite existing parent-chain state"
          else if not (null message) then reject message else store H.InitialOutput
        else do
          required <- H.chainProofRequired value
          present <- if required then pure False else fact 1
          if not required && not present then pure 1 else do
            allow <- fact 4
            has <- fact 1
            uncommitted <- fact 3
            bytes <- fact 2
            if allow && has && uncommitted && not bytes then pure 1 else do
              effective <- H.effectiveChainState value
              if not effective then pure 0 else do
                verified <- H.verifyChainProof value False
                if verified then store H.NextOutput else pure 0
    disconnectState = do
      initial <- checkpoint
      if initial then do
        (found,message) <- load
        same <- if found then H.matchesChainCheckpoint value else pure False
        if found && same then do
          removed <- fact 6
          if removed then pure 1 else reject "public BMM checkpoint state could not be removed"
        else if not (null message) then reject message
        else reject "public BMM checkpoint state is inconsistent during disconnect"
      else do
        present <- fact 1
        if not present then pure 1 else do
          decoded <- H.decodeChainProof value
          if not decoded then pure 0 else do
            (found,message) <- load
            if not found then reject (if null message then "cannot disconnect BMM proof without authenticated state" else message)
            else do
              parent <- H.extractChainParent value
              verified <- if parent then H.verifyChainProof value True else pure False
              same <- if verified then fact 7 else pure False
              if same then store H.PriorOutput else do
                previousError <- H.chainError value
                unless (not (null previousError)) (H.chainFailure value "BMM state is inconsistent during disconnect")
                pure 0

capture :: (Bool -> Probe -> IO Int32) -> Bool -> Fixture -> Int -> IO (Either String Int32,[Event],String)
capture run disconnect fixture@(Fixture _ _ _ _ existing) fault = do
  events <- newIORef []
  errorText <- newIORef (if existing then "existing error" else "")
  result <- try @SomeException (run disconnect (Probe fixture events errorText fault))
  (,,) (either (Left . show) Right result) <$> readIORef events <*> readIORef errorText

compareFixture :: Bool -> Fixture -> IO Property
compareFixture disconnect fixture = do
  expected@(_,trace,_) <- capture reference disconnect fixture (-1)
  actual <- capture H.runChainLifecycle disconnect fixture (-1)
  faults <- forM [0..length trace-1] $ \fault -> do
    old <- capture reference disconnect fixture fault
    new@(_,prefix,_) <- capture H.runChainLifecycle disconnect fixture fault
    pure (counterexample (show fault) (conjoin [new===old,prefix===take (fault+1) trace]))
  pure (counterexample (show (disconnect,fixture)) (conjoin ((actual===expected):faults)))

routes :: Property
routes = once $ ioProperty $ do
  let facts = [0,1,2,4,8,16,32,64,128,1024,3072,7168,8191]
  conjoin <$> mapM (uncurry compareFixture)
    [(disconnect,Fixture f m load specific existing) | disconnect <- [False,True],f <- facts,
      m <- [0,1,2,4,8,16,32,64,128,255],load <- [0..3],specific <- [False,True],existing <- [False,True]]

generated :: Property
generated = forAll ((,,,,,) <$> arbitrary <*> arbitrary <*> arbitrary <*> choose (0,3) <*> arbitrary <*> arbitrary) $
  \(disconnect,facts,methods,load,specific,existing) -> ioProperty $
    compareFixture disconnect (Fixture facts methods load specific existing)

-- Exercise the real routing adapters, strict replies and lazy GADT mismatch.
wire :: Property
wire = once $ ioProperty $ do
  traces <- forM [False,True] $ \disconnect -> do
    events <- newIORef []
    let native step index bytes = do
          modifyIORef' events (++[(step,index,bytes)])
          pure (wordLE 8 0)
    result <- execute (H.ChainSession native) (if disconnect then H.DisconnectChainState else H.ConnectChainState)
    seen <- readIORef events
    pure (conjoin [result===1,seen===[(n,0,B.empty) | n <- if disconnect then [10,1] else [0,10,1001,1]]])
  bad <- forM [B.empty,B.replicate 7 0,B.replicate 9 0,wordLE 8 2] $ \bytes -> do
    seen <- newIORef []
    result <- try @SomeException $ execute (H.ChainSession (\step _ _ -> modifyIORef' seen (++[step]) >> pure bytes)) H.ConnectChainState
    trace <- readIORef seen
    pure (conjoin [property (either (const True) (const False) result),trace===[0]])
  absent <- mapM (\mode -> FFI.elements_hs_replay_store mode 0 nullFunPtr nullPtr) [48,49]
  let mismatch = interpret (SomeOperation (Check (H.NextBlockHeight 0 0))) (undefined :: DSL H.ChainSession)
  pure (conjoin (traces++bad++[absent===replicate 2 (-1),property (isNothing mismatch)]))

-- Script, coin, and crypto objects remain native; these fixtures check the
-- enclosing adapter routes and publication bytes rather than reimplement them.
type Call = (Word32,Word64,B.ByteString)
type Reply = (Call,B.ByteString)
words8 :: [Word64] -> B.ByteString
words8 = B.concat . map (wordLE 8)
readReply :: Word32 -> [Word64] -> Reply
readReply step fields = ((step,0,B.empty),words8 fields)
effectReply :: Word32 -> Word64 -> B.ByteString -> Reply
effectReply step index bytes = ((step,index,bytes),wordLE 8 1)

routeFixture :: Bool -> Int32 -> [Reply] -> IO Property
routeFixture disconnect answer replies = do
  let run fault = do
        events <- newIORef []
        let native step index bytes = do
              prior <- readIORef events
              let call = (step,index,bytes)
              modifyIORef' events (++[call])
              when (length prior == fault) (ioError (userError "chain route fault"))
              case drop (length prior) replies of
                (expected,reply):_ | call == expected -> pure reply
                _ -> ioError (userError ("unexpected chain route: " ++ show call))
        result <- try @SomeException $ execute (H.ChainSession native)
          (if disconnect then H.DisconnectChainState else H.ConnectChainState)
        (,) (either (Left . show) Right result) <$> readIORef events
  (result,trace) <- run (-1)
  -- These routes have no native-owned decoding catch region. Once a callback
  -- fails, no later storage/effect callback may execute.
  faults <- forM [0..length replies-1] $ \fault -> do
    (failed,prefix) <- run fault
    pure (conjoin [property (either (const True) (const False) failed),
      prefix===take (fault+1) (map fst replies)])
  pure (conjoin ([result===Right answer,trace===map fst replies]++faults))

composedRoutes :: Property
composedRoutes = once $ ioProperty $ do
  let (fields,hash) = validate (H.CheckpointPreset 0)
      checkpoint = B.pack hash <> B.concat (map (wordLE 4 . fromIntegral) fields)
      emptyState = [readReply 2001 [0]]
      checkpointPrefix = map (`readReply` [1]) [10,11,12]
      storage selected height = effectReply 5000 selected B.empty : readReply 4000 [height] :
        [effectReply n 0 B.empty | n <- [4010,4011,4012,4013]] ++
        [effectReply 4014 117 B.empty,effectReply 4014 0 B.empty,
         effectReply 4015 0 B.empty,effectReply 4016 height B.empty]
      (consensus,limit,challenge) = validate (H.ConsensusPreset 0)
      config = words8 consensus <> B.pack limit <> B.pack challenge
      reject = effectReply 3390 0 . C.pack
      connectCheckpoint = [readReply 0 [0]] ++ checkpointPrefix ++ emptyState ++
        [effectReply 2033 0 checkpoint] ++ storage 0 2
      disconnectMissing = checkpointPrefix ++ emptyState ++
        [effectReply 90 0 (C.pack "public BMM checkpoint state is inconsistent during disconnect")]
      badDecode = [readReply 10 [0],readReply 1 [1],effectReply 3392 0 B.empty,
        readReply 3301 [0],reject "BMM proof is empty or exceeds its consensus size bound"]
      badEnvelope = [readReply 0 [0],readReply 10 [0],readReply 1001 [0],readReply 1 [1],
        readReply 4 [0],readReply 1 [1],readReply 3 [0],readReply 2 [1],
        readReply 2030 [0],readReply 2001 [0],readReply 2031 [1],effectReply 2033 0 checkpoint,
        readReply 1002 [0],effectReply 2999 0 config,effectReply 3392 0 B.empty,
        readReply 3012 [0,0,0,0],reject "sidechain block does not commit its exact BMM proof bytes"]
      nativeNoop = [readReply 0 [1],effectReply 90 0 B.empty,readReply 1010 [1],
        readReply 2 [0],readReply 5 [0]]
  conjoin <$> sequence [routeFixture False 1 connectCheckpoint,
    routeFixture True 0 disconnectMissing,routeFixture True 0 badDecode,
    routeFixture False 0 badEnvelope,routeFixture False 1 nativeNoop]

proofStorage :: Property
proofStorage = once $ ioProperty $ conjoin <$> sequence
  [exercise disconnect count height same | disconnect <- [False,True], count <- [1..8],
    height <- [-2,0,1,2,100 :: Int32], same <- [False,True]]
  where
    exercise disconnect count height same = do
      events <- newIORef []
      position <- newIORef 0
      let state at = B.replicate 32 (fromIntegral (17+at)) <>
            B.concat (map (wordLE 4) [1+at,100+at,8,0,1]) <> B.singleton 11 <>
            B.concat (map (wordLE 4) (drop (fromIntegral at) [90..100] ++ [101..100+at]))
          (fields,limit,challenge) = validate (H.ConsensusPreset 0)
          config = words8 fields <> B.pack limit <> B.pack challenge
          native step index input = do
            modifyIORef' events (++[(step,index,input)])
            unless ((index == 0 || step `elem` [4014,4016,5000]) &&
                (B.null input || step `elem` [90,2999,3407,3523,3623]))
              (ioError (userError "invalid composed proof request"))
            at <- readIORef position
            let wordsReply = pure . words8
                owned values = pure (B.singleton 1 <> words8 values)
            case step of
              0 -> wordsReply [0]
              10 -> wordsReply [0]
              1001 -> wordsReply [0]
              1002 -> wordsReply [0]
              2030 -> wordsReply [0]
              4 -> wordsReply [0]
              3 -> wordsReply [0]
              1 -> wordsReply [1]
              2 -> wordsReply [1]
              7 -> wordsReply [if same then 1 else 0]
              92 -> pure B.empty
              90 | input == C.pack "BMM state is inconsistent during disconnect" -> wordsReply [1]
              _ | step >= 2001 && step <= 2006 -> wordsReply [1]
              2010 -> wordsReply [1,0]
              2011 -> wordsReply [1,117]
              2012 -> wordsReply [3,0]
              2020 -> owned []
              2021 -> owned []
              2022 -> owned [3]
              2024 -> owned [0]
              2023 -> owned [1,1,100,8,0,1,11,100]
              2999 | input == config -> wordsReply [1]
              2998 -> wordsReply [1]
              3301 -> wordsReply [10]
              3303 -> wordsReply [K.schemaVersion]
              3304 -> wordsReply [count]
              _ | step `elem` [3302,3305,3392] -> wordsReply [1]
              3400 -> wordsReply [1,2000,1,1,100,8,0,1,11,100,count]
              3401 -> pure (state 0)
              3402 -> pure (B.replicate 32 (fromIntegral (17+at)))
              3403 -> pure (wordLE 4 (101+at) <> wordLE 4 8)
              3404 -> pure (B.replicate 32 (fromIntegral (18+at)))
              3408 -> modifyIORef' position (+1) >> wordsReply [1]
              3407 | input == state count -> wordsReply [1]
              3001 -> wordsReply [1,count,128,0]
              3002 -> wordsReply [0,1,1,100]
              3003 -> wordsReply [1,1,1,0]
              3012 -> wordsReply [3,10,1000,0]
              3154 -> wordsReply [0,0,0,0]
              3205 -> wordsReply [1,1,0,0]
              _ | step `elem` [3004,3008,3010,3013,3015,3017,3022,3155,3200,3201,3202,3203,3204] -> wordsReply [1,0,0,0]
              _ | step >= 3500 && step <= 3590 -> commitmentFixture 0 (step-3500) index input
              _ | step >= 3600 && step <= 3690 -> commitmentFixture 1 (step-3600) index input
              5000 | index == (if disconnect then 2 else 1) -> wordsReply [1]
              4000 -> wordsReply [fromIntegral (fromIntegral height :: Word32)]
              _ | step `elem` [4010,4011,4012,4013,4015] -> wordsReply [1]
              4014 | index `elem` [117,0] -> wordsReply [1]
              4016 | index == fromIntegral (if disconnect then max 1 height-1 else max 0 height) -> wordsReply [1]
              _ -> ioError (userError ("unexpected composed proof callback: " ++ show (step,index,input)))
      result <- try @SomeException $ execute (H.ChainSession native)
        (if disconnect then H.DisconnectChainState else H.ConnectChainState)
      trace <- readIORef events
      let accepted = not disconnect || same
          steps = map (\(s,_,_) -> s) trace
          writes = filter (>=4000) steps
      pure $ counterexample (show (disconnect,count,height,same,result,steps)) $ conjoin
        [either (Left . show) Right result === Right (if accepted then 1 else 0),
         property (all (`notElem` steps) [3009,3023]),
         length (filter (==3500) steps) === 1,
         length (filter (==3600) steps) === 1,
         length (filter (==3408) steps) === fromIntegral count,
         writes === if accepted then [5000,4000,4010,4011,4012,4013,4014,4014,4015,4016] else []]

properties :: [(String,Property)]
properties = [("BMM chain / independent connect-disconnect branches and all fault prefixes",routes),
  ("BMM chain / generated facts, reusable capabilities and exact errors",generated),
  ("BMM chain / real adapters, malformed flags, absent ABI and lazy mismatch",wire),
  ("BMM chain / composed state-proof-storage routes, payloads and faults",composedRoutes),
  ("BMM chain / complete proof-to-storage composition and reverse mismatch",proofStorage)]
