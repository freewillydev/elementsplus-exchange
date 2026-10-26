{-# LANGUAGE FlexibleInstances, TypeApplications #-}
module ReplayStoreTests (properties) where

import Control.Monad (when, unless)
import Control.Exception (SomeException, try)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Except (ExceptT, runExceptT, throwE)
import Control.Operation
import Data.Bits (testBit)
import qualified Data.Binary.Get as G
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.Either (isLeft)
import Data.IORef
import Data.Int (Int32, Int64)
import Data.Maybe (isNothing)
import qualified Data.Set as S
import Data.Word (Word8, Word32, Word64)
import qualified ParentReplay
import qualified ParentCache
import qualified ReplayStore as R
import Test.QuickCheck
import Withdrawal (wordLE)
import Workflow (FoldOperation(..), Continue(..))

-- Unpinned fixture identity: empty network, disabled modes, absent slot and
-- three zero hashes. Selection must retain the supplied fallback depth.
confirmationDepthSnapshot :: Word32 -> B.ByteString
confirmationDepthSnapshot depth = wordLE 8 0 <> B.pack [0,0,0,0,0] <>
  B.replicate 96 0 <> wordLE 4 (fromIntegral depth)

storeTip :: Word32 -> B.ByteString -> B.ByteString
storeTip height block = wordLE 4 (fromIntegral height) <> block <> B.replicate 82 0

blockParameters :: B.ByteString
blockParameters = wordLE 4 100 <> B.concat (map (wordLE 2) [10,5,10,5]) <>
  B.concat (map (wordLE 4) [10,5,0xb7,0])

-- An empty, valid parent block: use the actual block interpreter rather than
-- a precomputed success bit when testing the enclosing cache workflow.
blockReply :: Bool -> Word32 -> Word64 -> B.ByteString
blockReply accepted step index = case step of
  0 -> B.concat (map (wordLE 8) [24,19,0,1000]) <> B.concat (replicate 3 (wordLE 2 10 <> wordLE 2 5))
  1 -> wordLE 8 (if accepted then 6 else 1)
  2 -> B.empty
  3 -> B.empty
  10 -> wordLE 8 0
  20 -> wordLE 8 1
  30 -> wordLE 8 0
  200 -> B.empty
  201 -> B.empty
  5096 -> wordLE 8 0
  4136 -> B.empty
  8192 -> B.pack [24,0]
  8193 -> B.empty
  13288 -> B.concat (map (wordLE 8) [1,0,1000])
  17384 -> wordLE 8 0
  16394 -> B.empty
  16395 -> B.empty
  16405 -> B.singleton 0
  16411 -> B.singleton 0
  20481 | index <= 1 -> B.singleton (if index == 0 then 1 else 0)
        | otherwise -> error "rejected block interpreter fault"
  _ -> error ("unexpected empty block effect " ++ show (step,index))

-- On malformed replies, the interpreter may throw immediately or return its
-- typed error for native completion. Neither may run further replay effects.
blockFaultTails :: Word32 -> Word32 -> Word32 -> [(Word32,Word64)] -> [[(Word32,Word64)]]
blockFaultTails offset open close prefix = case reverse prefix of
  ((step,_):_) | step == open || (step >= offset && step <= offset+20481) ->
    [[(close,0)]] ++ [[(offset+20481,code),(close,0)] | step /= offset+20481, code <- [2..5]]
  _ -> [[]]

blockSessionFraming :: Property
blockSessionFraming = once $ ioProperty $ do
  let run parameters completed = do
        seen <- newIORef []
        let native step index _ = do
              modifyIORef' seen (++[(step,index)])
              pure $ case step of
                23 -> parameters
                24 -> B.empty
                21481 -> completed
                _ -> blockReply True (step-1000) index
        result <- runExceptT (ParentCache.parentBlockSession native 23 24 1000 0)
        (,) result <$> readIORef seen
  invalid <- mapM (\parameters -> do
    (result,seen) <- run parameters (B.singleton 1)
    pure (conjoin [result === Left (-1),seen === [(23,0),(21481,2),(24,0)]]))
    (B.snoc blockParameters 0 : [B.take n blockParameters | n <- [0..B.length blockParameters-1]])
  completions <- mapM (\reply -> do
    (result,seen) <- run blockParameters reply
    pure (conjoin [result === if reply == B.singleton 1 then Right True else Left (-1),
      take 1 seen === [(23,0)],drop (length seen-2) seen === [(21481,0),(24,0)]]))
    [B.singleton 1,B.singleton 0,B.empty,B.pack [1,0],B.singleton 2]
  exceptions <- mapM (\pureFailure -> do
    seen <- newIORef []
    let native step index _ = do
          modifyIORef' seen (++[(step,index)])
          case step of
            23 -> pure blockParameters
            24 -> pure B.empty
            1030 -> if pureFailure then pure (error "pure block failure")
              else ioError (userError "block callback exception")
            21481 -> pure (B.singleton 1) -- Cannot turn a failed workflow into success.
            _ -> error "later replay effect after exception"
    result <- runExceptT (ParentCache.parentBlockSession native 23 24 1000 0)
    trace <- readIORef seen
    pure (conjoin [result === Left (-1),trace === [(23,0),(1030,1),(21481,2),(24,0)]])) [False,True]
  pure (conjoin (invalid ++ completions ++ exceptions))

-- Real record framing for cache composition; the policy differentials still
-- compare against the retained scalar reference, not the new interpreter.
sessionReply :: R.StoreSession -> Int64 -> B.ByteString -> B.ByteString -> Word32 -> Word64 -> B.ByteString
sessionReply kind status previous next step index
  | step == 43 = B.singleton 1 <> wordLE 4 index
  | step == 39 && status == 4 = B.singleton 0 <> wordLE 4 4
  | otherwise = B.cons 1 $ case step of
      0 -> B.singleton 1
      1 -> previous
      2 -> next
      3 -> yes (kind /= R.LoadSession || status /= 0)
      4 -> B.singleton 1 <> wordLE 4 5 <> B.replicate 32 (if status == 3 then 2 else 1)
      5 -> yes (kind /= R.LoadSession || status /= 0)
      6 -> if status == 2 then B.singleton 0 else B.cons 1 previous
      7 -> B.replicate 32 3
      8 -> if index == 0 then wordLE 4 5 else B.replicate 25 0
      24 -> yes (status /= 0)
      26 -> B.replicate 32 1
      _ -> B.empty
  where yes b = B.singleton (if b then 1 else 0)

-- A malformed subworkflow reply must only complete/close its native scope;
-- no later database write or cache publication is permitted.
sessionFaultTail :: Word32 -> Word32 -> Word32 -> [(Word32,Word64)] -> [(Word32,Word64)]
sessionFaultTail offset loadClose resetClose prefix = case reverse prefix of
  ((step,_):_) | step >= offset && step <= offset+43 ->
    (if step == offset+43 then [] else [(offset+43,4)]) ++ [(close,0)]
  _ -> []
  where close = case [step | (step,_) <- reverse prefix, step == loadClose-1 || step == resetClose-1] of
          (step:_) -> step+1
          [] -> loadClose

compact :: Property
compact = forAll (arbitrary :: Gen Word64) $ \value ->
  let encoded
        | value < 253 = B.singleton (fromIntegral value)
        | value <= 65535 = B.cons 253 (wordLE 2 value)
        | value <= 4294967295 = B.cons 254 (wordLE 4 value)
        | otherwise = B.cons 255 (wordLE 8 value)
  in conjoin [R.decode R.compact encoded === Right value,
       conjoin [property (isLeft (R.decode R.compact (B.take n encoded))) | n <- [0..B.length encoded-1]],
       property (isLeft (R.decode R.compact (B.snoc encoded 0)))]

bounds :: Property
bounds = once $ conjoin $
  [property (isLeft (R.decode R.compact bytes)) | bytes <-
    [B.cons 253 (wordLE 2 252),B.cons 254 (wordLE 4 65535),B.cons 255 (wordLE 8 4294967295)]] ++
  [property (isLeft (R.decode (R.counted 1 G.getWord8) bytes)) | bytes <-
    [B.pack [1], B.cons 255 (wordLE 8 maxBound), B.pack [253,0,1,0]]] ++
  [R.decode (R.counted 1 G.getWord8) (B.pack [3,4,5,6]) === Right [4,5,6]]

data Mock = Mock Bool (IORef [String])
instance R.ReplayAdmission Mock where
  admitReplayAppend (Mock accepted events) = do
    liftIO (modifyIORef' events (++["admit"]))
    if accepted then pure (R.AppendPlan 2 True 1 False) else throwE 0
instance R.ReplayCommit Mock where
  commitReplayAppend (Mock _ events) plan = do
    when (plan /= R.AppendPlan 2 True 1 False) (throwE (-1))
    liftIO (modifyIORef' events (++["commit"]))

dispatch :: Property
dispatch = once $ ioProperty $ do
  outcomes <- mapM (\accepted -> do
    events <- newIORef []
    result <- runExceptT (R.appendReplay (Mock accepted events))
    seen <- readIORef events
    pure (conjoin [result === if accepted then Right () else Left 0,
      seen === if accepted then ["admit","commit"] else ["admit"]])) [False,True]
  let mismatch = interpret (SomeOperation (ParentReplay.RpcPreparation undefined))
        (error "mismatched replay DSL forced" :: DSL R.Store)
  pure (conjoin (property (isNothing mismatch):outcomes))

framing :: Property
framing = once $ ioProperty $ do
  let state = B.replicate 82 0
      previous = wordLE 4 100 <> B.replicate 32 1 <> state
      next = wordLE 4 101 <> B.replicate 32 2 <> state
      reply step index = case step of
        0 -> B.singleton 1
        1 -> previous
        2 -> next
        3 -> B.singleton 1
        4 -> B.singleton 1 <> wordLE 4 4 <> B.replicate 32 0
        5 -> B.singleton 1
        6 -> B.singleton 1 <> previous
        7 -> B.replicate 32 3
        8 -> if index == 0 then wordLE 4 4 else B.replicate 25 0
        24 -> B.singleton 1
        _ -> B.empty
      capture bad = do
        events <- newIORef []
        let native step index _ = do
              modifyIORef' events (++[(step,index)])
              pure $ if Just (step,index) == bad then B.snoc (reply step index) 0 else reply step index
        result <- execute (R.Store 2100000000000000 native) R.AppendBlock
        seen <- readIORef events
        pure (result,seen)
  (good,events) <- capture Nothing
  failures <- mapM (\event -> do
    (result,seen) <- capture (Just event)
    pure (counterexample (show event) (conjoin [result === -1,
      seen === takeWhile (/=event) events ++ [event]]))) events
  pure (conjoin ([good === 1,property (not (null events))] ++ failures))

deposit :: Int -> Bool -> B.ByteString
deposit index valid = outpoint index <> B.replicate 32 2 <> wordLE 4 1 <>
  wordLE 8 (if valid then 1000 else 0) <> B.pack [1,0x51]

outpoint :: Int -> B.ByteString
outpoint index = wordLE 4 (fromIntegral index+1) <> B.replicate 28 0 <> wordLE 4 0

lookupFraming :: Property
lookupFraming = once $ ioProperty $ do
  let reply step = case step of
        0 -> B.singleton 1
        27 -> B.singleton 1
        28 -> B.singleton 1 <> deposit 0 True
        26 -> outpoint 0
        _ -> B.empty
      run bad = do
        calls <- newIORef []
        let native step index input = do
              modifyIORef' calls (++[(step,index,input)])
              pure $ if Just step == bad then B.snoc (reply step) 0 else reply step
        result <- execute (R.Store 1000 native) (R.LookupRecord R.DepositRecord)
        seen <- readIORef calls
        pure (result,seen)
  (good,events) <- run Nothing
  failures <- mapM (\(step,_,_) -> do
    (result,seen) <- run (Just step)
    pure (conjoin [result === -1, seen === takeWhile (\(s,_,_) -> s /= step) events ++
      filter (\(s,_,_) -> s == step) events])) events
  pure (conjoin ([good === 0, map (\(s,_,_) -> s) events === [0,27,28,26]] ++ failures))

scanPages :: Property
scanPages = forAll (chooseInt (0,75)) $ \count ->
  forAll (chooseInt (0,65)) $ \limit ->
  forAll (chooseInt (-1,count+1)) $ \after ->
  forAll (elements [-1,0,count `div` 2,count-1]) $ \bad -> ioProperty $ do
    position <- newIORef (max 0 after)
    staged <- newIORef []
    published <- newIORef ([-1],Just (-1))
    cursor <- newIORef Nothing
    messages <- newIORef []
    let native step _ input = do
          index <- readIORef position
          case step of
            0 -> pure (B.singleton 1)
            8 -> pure (wordLE 8 (fromIntegral limit))
            25 -> modifyIORef' messages (++[input]) >> pure B.empty
            26 -> pure (if after < 0 then B.singleton 0 else B.singleton 1 <> outpoint after)
            29 -> writeIORef published ([],Nothing) >> pure B.empty
            30 -> pure B.empty
            31 -> pure (B.singleton (if index < count then 1 else 0))
            32 -> pure (B.pack [1,100])
            33 -> pure (B.singleton 1 <> outpoint index)
            34 -> pure (B.singleton 1 <> deposit index (index /= bad))
            35 -> modifyIORef' staged (++[index]) >> pure B.empty
            36 -> modifyIORef' position (+1) >> pure B.empty
            37 -> readIORef staged >>= writeIORef cursor . Just . last >> pure B.empty
            38 -> do
              stagedPage <- readIORef staged
              next <- readIORef cursor
              writeIORef published (stagedPage,next)
              pure B.empty
            _ -> fail ("unexpected scan effect " ++ show step)
        remaining = [max 0 (after+1)..count-1]
        page = take limit remaining
        validLimit = limit >= 1 && limit <= 64
        accepted = validLimit && bad `notElem` page
        expectedCursor = if length remaining > limit && accepted then Just (last page) else Nothing
    result <- execute (R.Store 1000 native) R.ListDeposits
    actual <- readIORef published
    errors <- readIORef messages
    pure (conjoin [result === if accepted then 1 else 0,
      actual === if accepted then (page,expectedCursor) else ([],Nothing),
      null errors === accepted])

scanFraming :: Property
scanFraming = once $ ioProperty $ do
  let run bad = do
        calls <- newIORef ([] :: [Word32])
        position <- newIORef (0 :: Int)
        let native step _ _ = do
              modifyIORef' calls (++[step])
              count <- length <$> readIORef calls
              index <- readIORef position
              reply <- case step of
                0 -> pure (B.singleton 1)
                8 -> pure (wordLE 8 1)
                26 -> pure (B.singleton 0)
                31 -> pure (B.singleton (if index < 1 then 1 else 0))
                32 -> pure (B.pack [1,100])
                33 -> pure (B.singleton 1 <> outpoint index)
                34 -> pure (B.singleton 1 <> deposit index True)
                36 -> modifyIORef' position (+1) >> pure B.empty
                _ -> pure B.empty
              pure (if count == bad then B.snoc reply 0 else reply)
        result <- execute (R.Store 1000 native) R.ListDeposits
        seen <- readIORef calls
        pure (result,seen)
  (good,events) <- run 0
  failures <- mapM (\index -> do
    (result,seen) <- run index
    pure (conjoin [result === -1, seen === take index events])) [1..length events]
  pure (conjoin ([good === 1, last events === 38] ++ failures))

lifecycleFraming :: Property
lifecycleFraming = once $ ioProperty $ do
  let seed = wordLE 4 100 <> B.replicate 32 1 <> B.replicate 82 0
      reply reset rejected step = case step of
        0 -> B.singleton 1
        1 -> seed
        3 -> B.singleton 1
        4 -> if rejected then B.singleton 0 else B.singleton 1 <> wordLE 4 5 <> B.replicate 32 2
        5 -> B.singleton 1
        6 -> B.singleton 1 <> seed
        8 -> wordLE 4 5
        24 -> B.singleton (if reset && rejected then 0 else 1)
        26 -> B.replicate 32 2
        _ -> B.empty
      capture reset rejected bad = do
        calls <- newIORef ([] :: [Word32])
        let native step index input = do
              when (index /= 0 || (step /= 25 && not (B.null input))) (fail "invalid lifecycle effect")
              modifyIORef' calls (++[step])
              count <- length <$> readIORef calls
              pure (if count == bad then B.snoc (reply reset rejected step) 0 else reply reset rejected step)
        result <- execute (R.Store 1000 native) (if reset then R.ResetStore else R.LoadStore)
        seen <- readIORef calls
        pure (result,seen)
  cases <- mapM (\(reset,rejected) -> do
    (good,events) <- capture reset rejected 0
    failures <- mapM (\index -> do
      (result,seen) <- capture reset rejected index
      pure (conjoin [result === -1, seen === take index events])) [1..length events]
    let expected | reset = [1,40,41,42,23,24] ++ [25 | rejected]
                 | rejected = [39,0,3,4,25]
                 | otherwise = [39,0,3,4,8,26,5,6]
    pure (conjoin ([good === if rejected then (if reset then 0 else 2) else 1,
      events === expected] ++ failures))) [(a,b) | a <- [False,True], b <- [False,True]]
  pure (conjoin cases)

sessionFailures :: Property
sessionFailures = once $ ioProperty $ do
  let seed = storeTip 100 (B.replicate 32 1)
      next = storeTip 101 (B.replicate 32 2)
      capture :: R.StoreSession -> Int -> Int -> IO (Int32,[(Word32,Word64)])
      capture kind fault failure = do
        calls <- newIORef []
        let code = if kind == R.LoadSession then 2 else 0
            native step index _ = do
              modifyIORef' calls (++[(step,index)])
              count <- length <$> readIORef calls
              let reply = sessionReply kind 1 seed next step index
              if count == fault then case failure of
                0 -> pure (B.singleton 0 <> wordLE 4 code)
                1 -> pure (B.snoc reply 0)
                2 -> pure (B.init reply)
                _ -> ioError (userError "session callback fault")
              else if step == 43 && index == 4 then pure (B.singleton 0 <> wordLE 4 code)
              else pure reply
        result <- try (execute (R.Store 1000 native) (R.RunSession kind)) :: IO (Either SomeException Int32)
        seen <- readIORef calls
        pure (either (const (-1)) id result,seen)
  checks <- mapM (\kind -> do
    (good,calls) <- capture kind 0 0
    let code = if kind == R.LoadSession then 2 else 0
    faults <- mapM (\(at,failure) -> do
      (result,seen) <- capture kind at failure
      let completion = if failure == 0 then fromIntegral code else 4
      pure (counterexample (show (kind,at,failure)) (conjoin [result === code,
        seen === take at calls ++ [(43,completion)]])))
      [(at,failure) | at <- [1..length calls-1], failure <- [0..3]]
    endings <- mapM (\failure -> do
      (result,seen) <- capture kind (length calls) failure
      pure (conjoin [result === -1,seen === calls])) [1..3]
    pure (conjoin ([good === 1,last calls === (43,1)] ++ faults ++ endings)))
    [R.LoadSession,R.ResetSession,R.AppendSession]
  pure (conjoin checks)

lifecycleTruncation :: Property
lifecycleTruncation = forAll (elements [1,4,6]) $ \target ->
  forAll (arbitrary :: Gen Word32) $ \height ->
  forAll (chooseInt (0,if target == 4 then 36 else if target == 6 then 118 else 117)) $ \size ->
  ioProperty $ do
    calls <- newIORef []
    let seed = wordLE 4 (fromIntegral height) <> B.replicate 32 1 <> B.replicate 82 0
        native step _ _ = do
          modifyIORef' calls (++[step])
          let reply = case step of
                0 -> B.singleton 1
                1 -> seed
                3 -> B.singleton 1
                4 -> B.singleton 1 <> wordLE 4 5 <> B.replicate 32 2
                5 -> B.singleton 1
                6 -> B.singleton 1 <> seed
                8 -> wordLE 4 5
                26 -> B.replicate 32 2
                _ -> B.empty
          pure (if step == target then B.take size reply else reply)
    result <- execute (R.Store 1000 native) (if target == 1 then R.ResetStore else R.LoadStore)
    seen <- readIORef calls
    pure (conjoin [result === -1, last seen === target])

data CacheMock = CacheMock Bool Bool Bool (IORef [String])
instance ParentCache.CachePreflight CacheMock where
  prepareCacheProgress (CacheMock present _ _ events) = do
    liftIO (modifyIORef' events (++["prepare"]))
    pure (if present then Just (undefined,undefined) else Nothing)
instance ParentCache.CacheAdvance CacheMock where
  advanceCacheProgress (CacheMock _ accepted _ events) _ _ = do
    liftIO (modifyIORef' events (++["advance"]))
    unless accepted (throwE 0)
instance ParentCache.CachePublication CacheMock where
  publishCacheProgress (CacheMock _ _ accepted events) _ = do
    liftIO (modifyIORef' events (++["publish"]))
    unless accepted (throwE 0)

cacheComposition :: Property
cacheComposition = once $ ioProperty $ do
  cases <- mapM (\(present,advanced,published) -> do
    events <- newIORef []
    result <- runExceptT (ParentCache.progressReplayCache (CacheMock present advanced published events))
    seen <- readIORef events
    pure (conjoin [result === if not present || (advanced && published) then Right () else Left 0,
      seen === ["prepare"] ++ ["advance" | present] ++ ["publish" | present && advanced]]))
    [(a,b,c) | a <- [False,True], b <- [False,True], c <- [False,True]]
  let mismatch = interpret (SomeOperation (R.Store undefined undefined))
        (error "mismatched cache DSL forced" :: DSL ParentCache.CacheProgress)
  pure (conjoin (property (isNothing mismatch):cases))

cacheCapture :: Int -> Bool -> IO (Int32,[(Word32,Word64,B.ByteString,B.ByteString)])
cacheCapture = cacheCaptureWithMilestone False

cacheCaptureWithMilestone :: Bool -> Int -> Bool -> IO (Int32,[(Word32,Word64,B.ByteString,B.ByteString)])
cacheCaptureWithMilestone rejected = cacheCaptureWithBmm rejected (-1)

cacheCaptureWithBmm :: Bool -> Int -> Int -> Bool -> IO (Int32,[(Word32,Word64,B.ByteString,B.ByteString)])
cacheCaptureWithBmm rejected bmmMode bad truncated = do
  events <- newIORef []
  height <- newIORef (100 :: Word32)
  let hash value = wordLE 4 (fromIntegral value) <> B.replicate 28 0
      key = B.pack [1,24,1] <> hash (1 :: Word32) <> hash (2 :: Word32) <> hash (100 :: Word32) <>
        B.concat (map (wordLE 2) [1..6]) <> wordLE 4 5
      native step index input = do
        current <- readIORef height
        let reply = case step of
              0 -> key <> wordLE 4 100 <> wordLE 4 102 <> hash (102 :: Word32) <> B.singleton 1
              1 -> B.singleton 1 <> key <> wordLE 4 (fromIntegral current) <> hash current <>
                B.singleton 1 <> hash (1 :: Word32) <> wordLE 4 100
              2 -> B.singleton 1
              3 -> wordLE 4 2 <> B.singleton 1
              5 -> wordLE 8 (if index == 7 then 1 else 0)
              9 -> B.singleton 1 <> hash index
              13 -> B.singleton 1
              14 -> hash current
              16 -> blockParameters
              17 -> B.singleton 1
              100 -> if rejected then milestoneFixture 0 0 0 else
                wordLE 4 1 <> B.pack [0,1,24,1] <> hash (1 :: Word32) <>
                  B.concat [wordLE 4 n <> hash n | n <- [2..4 :: Word64]] <> B.replicate 44 0
              101 -> B.replicate 32 3
              201 -> wordLE 4 24 <> B.replicate 33 0
              202 -> if bmmMode < 0 then B.singleton 1 <> wordLE 8 0 else bmmFixture bmmMode 2 index
              203 -> bmmFixture bmmMode 3 index
              204 -> bmmFixture bmmMode 4 index
              20 -> B.singleton 1
              21 -> wordLE 8 2100000000000000
              _ | step >= 30000 && step <= 50481 -> blockReply True (step-30000) index
              _ | step >= 500 && step <= 543 -> sessionReply R.AppendSession 1
                (storeTip current (hash current)) (storeTip (current+1) (hash (current+1))) (step-500) index
              _ -> B.empty
        modifyIORef' events (++[(step,index,input,reply)])
        when (step == 22) (writeIORef height (fromIntegral index))
        count <- length <$> readIORef events
        pure (if count /= bad then reply else
          if truncated && not (B.null reply) then B.init reply else B.snoc reply 0)
  result <- try (execute (ParentCache.CacheProgress native) ParentCache.ProgressReplayCache) :: IO (Either SomeException Int32)
  seen <- readIORef events
  pure (either (const (-1)) id result,seen)

cacheFraming :: Property
cacheFraming = once $ ioProperty $ do
  (good,events) <- cacheCapture 0 False
  failures <- mapM (\(bad,truncated) -> do
    (result,seen) <- cacheCapture bad truncated
    let prefix = take bad events
        trace = [(s,i) | (s,i,_,_) <- prefix]
        cleanup = [sessionFaultTail 500 27 27 trace ++ cleanupTail | cleanupTail <- blockFaultTails 30000 16 28 trace]
    pure (conjoin [result === -1, take bad seen === prefix,
      property ([(s,i) | (s,i,_,_) <- drop bad seen] `elem` cleanup)]))
    [(index,truncateReply) | index <- [1..length events], truncateReply <- [False,True]]
  let writes = [(step,index) | (step,index,_,_) <- events, step `elem` [4,21,22,23,24]]
  (rejected,failed) <- cacheCaptureWithMilestone True 0 False
  let lastSteps = reverse (take 6 (reverse [step | (step,_,_,_) <- failed]))
      reportAt = length failed-1
  (malformed,stopped) <- cacheCaptureWithMilestone True reportAt False
  pure (conjoin ([good === 1, writes === [(4,0),(21,101),(22,101),(23,0),(21,102),(22,102),(23,0),(24,0)],
    rejected === 0, lastSteps === [28,17,100,101,108,6], malformed === -1, stopped === take reportAt failed,
    property (all (\(step,_,_,_) -> step `notElem` [21,22,24]) failed)] ++ failures))

cacheSnapshotTruncation :: Property
cacheSnapshotTruncation = forAll (arbitrary :: Gen Word32) $ \height ->
  forAll (chooseInt (0,255)) $ \cut ->
    let hash = B.replicate 32 1
        key = B.pack [1,24,1] <> hash <> hash <> hash <> B.replicate 12 0 <> wordLE 4 5
        encoded = B.singleton 1 <> key <> wordLE 4 (fromIntegral height) <> hash <> B.singleton 0 <> hash <> wordLE 4 0
        size = cut `mod` B.length encoded
    in conjoin [property (not (isLeft (R.decode ParentCache.cacheSnapshot encoded))),
         property (isLeft (R.decode ParentCache.cacheSnapshot (B.take size encoded))),
         property (isLeft (R.decode ParentCache.cacheSnapshot (B.snoc encoded 0)))]

data MilestoneMock = MilestoneMock Int (IORef [Int])
milestoneStage :: MilestoneMock -> Int -> ExceptT Int32 IO ()
milestoneStage (MilestoneMock rejected events) stage = do
  liftIO (modifyIORef' events (++[stage]))
  when (rejected == stage) (throwE 0)
instance ParentReplay.MilestoneSource MilestoneMock where
  readMilestone value = milestoneStage value 0 >> pure undefined
instance ParentReplay.ProposalMilestone MilestoneMock where
  checkProposalMilestone value _ = milestoneStage value 1
instance ParentReplay.ActivationMilestone MilestoneMock where
  checkActivationMilestone value _ = milestoneStage value 2
instance ParentReplay.CheckpointMilestone MilestoneMock where
  checkCheckpointMilestone value _ = milestoneStage value 3

milestoneComposition :: Property
milestoneComposition = once $ ioProperty $ do
  cases <- mapM (\rejected -> do
    events <- newIORef []
    result <- runExceptT (ParentReplay.validateMilestones (MilestoneMock rejected events))
    seen <- readIORef events
    pure (conjoin [result === if rejected == 4 then Right () else Left 0,
      seen === [0..min 3 rejected]])) [0..4]
  let mismatch = interpret (SomeOperation (ParentCache.CacheProgress undefined))
        (error "mismatched milestone DSL forced" :: DSL ParentReplay.Milestone)
  pure (conjoin (property (isNothing mismatch):cases))

milestoneFixture :: Int -> Word32 -> Word64 -> B.ByteString
milestoneFixture mode step index = case step of
  0 -> wordLE 4 height <> (if mode == 3 then B.singleton 0 else B.pack [2,1,2]) <>
    B.pack [1,24,1] <> hash 1 <> B.concat [wordLE 4 h <> hash 2 | h <- points] <>
    hash (if mode == 3 then 0 else 3) <> wordLE 4 5 <> wordLE 8 42
  1 -> hash 2
  2 -> B.singleton 1 <> wordLE 8 2
  3 -> wordLE 2 (if index == 0 then 106 else 81)
  4 -> wordLE 2 (fromIntegral (B.length payload)) <> B.singleton 1 <> B.singleton (fromIntegral (B.length payload)) <> payload
  5 -> if mode == 1 || mode == 7 then B.singleton 0 else B.singleton 1 <> wordLE 4 height <> wordLE 4 (if mode == 6 then 1 else 0)
  6 -> hash (if mode == 3 || mode == 7 then 0 else 1)
  7 -> if mode == 3 then B.singleton 0 <> wordLE 8 0 else
    B.singleton 1 <> hash (if mode == 8 then 4 else 3) <> wordLE 4 5 <> wordLE 8 42
  _ -> B.empty
  where
    hash = B.replicate 32
    height | mode == 1 || mode == 7 = 20
           | mode == 2 || mode == 3 || mode == 8 = 30
           | mode == 4 = 40
           | otherwise = 10
    points = if mode == 5 then [10,10,10] else [10,20,30]
    payload = if mode == 1 || mode == 7 then B.pack [214,225,197,223,24] <> hash 1 else B.pack [213,224,196,175,24,1,2]

milestoneCapture :: Int -> Int -> Int -> IO (Int32,[(Word32,Word64,B.ByteString)])
milestoneCapture mode bad fault = do
  events <- newIORef []
  let native step index input = do
        modifyIORef' events (++[(step,index,input)])
        count <- length <$> readIORef events
        let reply = milestoneFixture mode step index
        if count /= bad then pure reply else case fault of
          0 -> pure (B.snoc reply 0)
          1 -> pure (if B.null reply then B.singleton 0 else B.init reply)
          _ -> ioError (userError "milestone fixture failure")
  result <- try (execute (ParentReplay.Milestone native) ParentReplay.ValidateMilestones) :: IO (Either SomeException Int32)
  seen <- readIORef events
  pure (either (const (-1)) id result,seen)

milestoneFraming :: Property
milestoneFraming = once $ ioProperty $ do
  results <- mapM (\mode -> do
    (result,events) <- milestoneCapture mode 0 0
    faults <- mapM (\(bad,fault) -> do
      (status,seen) <- milestoneCapture mode bad fault
      pure (conjoin [status === -1,seen === take bad events]))
      [(bad,fault) | bad <- [1..length events], fault <- [0..2]]
    pure (conjoin ([result === if mode >= 5 then 0 else 1,
      property (all (\(step,_,_) -> step /= 4 || any (\(s,i,_) -> s == 3 && i == 0) events) events)] ++ faults))) [0..8]
  pure (conjoin results)

milestoneTruncation :: Property
milestoneTruncation = forAll (arbitrary :: Gen Word32) $ \height ->
  forAll (chooseInt (0,1000)) $ \cut ->
    let encoded = wordLE 4 (fromIntegral height) <> B.drop 4 (milestoneFixture 0 0 0)
    in conjoin [property (not (isLeft (R.decode ParentReplay.milestoneInput encoded))),
      property (isLeft (R.decode ParentReplay.milestoneInput (B.take (cut `mod` B.length encoded) encoded))),
      property (isLeft (R.decode ParentReplay.milestoneInput (B.snoc encoded 0)))]

data BmmMock = BmmMock Int (IORef [Int])
bmmStage :: BmmMock -> Int -> ExceptT Int32 IO ()
bmmStage (BmmMock rejected events) stage = do
  liftIO (modifyIORef' events (++[stage]))
  when (rejected == stage) (throwE 0)
instance ParentReplay.BmmScanAdmission BmmMock where
  prepareBmmScan value = bmmStage value 0 >> pure undefined
instance ParentReplay.BmmCollection BmmMock where
  collectBmmCommitment value _ = bmmStage value 1 >> pure (ParentReplay.BmmCommitment B.empty 0)
instance ParentReplay.BmmPublication BmmMock where
  publishBmmCommitment value _ _ = bmmStage value 2

bmmComposition :: Property
bmmComposition = once $ ioProperty $ do
  cases <- mapM (\rejected -> do
    events <- newIORef []
    result <- runExceptT (ParentReplay.scanBmmCommitment (BmmMock rejected events))
    seen <- readIORef events
    pure (conjoin [result === if rejected == 3 then Right (ParentReplay.BmmCommitment B.empty 0) else Left 0,
      seen === [0..min 2 rejected]])) [0..3]
  let mismatch = interpret (SomeOperation (ParentReplay.Milestone undefined))
        (error "mismatched BMM DSL forced" :: DSL ParentReplay.BmmScan)
  pure (conjoin (property (isNothing mismatch):cases))

bmmFixture :: Int -> Word32 -> Word64 -> B.ByteString
bmmFixture mode step index = case step of
  1 -> wordLE 4 (if mode == 2 then 256 else 24) <> B.singleton 1 <> wanted
  2 -> if mode == 3 then B.singleton 0 else B.singleton 1 <> wordLE 8 2
  3 -> wordLE 2 (if mode == 10 then 81 else 106)
  4 -> wordLE 2 (if mode == 9 then 256 else if mode == 11 then 81 else 37) <>
    B.singleton (if mode == 8 then 0 else 1) <> B.singleton 37 <> payload
  _ -> B.empty
  where
    hash = if mode == 6 then B.replicate 32 0 else B.pack [0..31]
    wanted = if mode == 1 then B.replicate 32 2 else B.reverse hash
    valid = (index == 1 || mode == 5) && mode /= 4
    payload = B.pack [if valid then 0xd1 else 0,0x61,0x73,0x68,if mode == 7 then 23 else 24] <> hash

bmmCapture :: Bool -> Int -> Int -> Int -> IO (Int32,[(Word32,Word64,B.ByteString)])
bmmCapture cache mode bad fault = do
  events <- newIORef []
  let native step index input = do
        modifyIORef' events (++[(step,index,input)])
        count <- length <$> readIORef events
        let reply = if cache then if step > 200 then bmmFixture mode (step-200) index else B.empty
                    else bmmFixture mode step index
        if count /= bad then pure reply else case fault of
          0 -> pure (B.snoc reply 0)
          1 -> pure (if B.null reply then B.singleton 0 else B.init reply)
          _ -> ioError (userError "BMM fixture failure")
      run = if cache then either id (const 1) <$> runExceptT
              (ParentCache.buildCacheBmmEdge (ParentCache.CacheProgress native) 101)
            else execute (ParentReplay.BmmScan native) ParentReplay.ScanBmmCommitment
  result <- try run :: IO (Either SomeException Int32)
  seen <- readIORef events
  pure (either (const (-1)) id result,seen)

bmmFraming :: Property
bmmFraming = once $ ioProperty $ do
  cases <- mapM (\mode -> do
    (result,events) <- bmmCapture False mode 0 0
    faults <- mapM (\(bad,fault) -> do
      (status,seen) <- bmmCapture False mode bad fault
      pure (conjoin [status === -1, seen === take bad events]))
      [(bad,fault) | bad <- [1..length events], fault <- [0..2]]
    let published = [index | (step,index,_) <- events, step == 5]
        expectedPublish = if mode `elem` [0,1,6] then [1] else []
    pure (counterexample (show mode) (conjoin ([result === if mode `elem` [0,6] then 1 else 0,
      published === expectedPublish,
      property (mode /= 1 || map (\(s,_,_) -> s) (drop (length events-2) events) == [5,6])] ++ faults)))) [0..11]
  pure (conjoin cases)

bmmCacheComposition :: Property
bmmCacheComposition = once $ ioProperty $ do
  cases <- mapM (\mode -> do
    (result,events) <- bmmCapture True mode 0 0
    faults <- mapM (\(bad,fault) -> do
      (status,seen) <- bmmCapture True mode bad fault
      pure (conjoin [status === -1, seen === take bad events]))
      [(bad,fault) | bad <- [1..length events], fault <- [0..2]]
    pure (conjoin ([result === 1, head events === (25,0,B.empty),
      last events === (19,101,B.singleton (if mode `elem` [0,6] then 1 else 0))] ++ faults))) [0..11]
  pure (conjoin cases)

bmmGenerated :: Property
bmmGenerated = forAll (arbitrary :: Gen Word8) $ \slot ->
  forAll (vectorOf 32 arbitrary) $ \hash -> forAll (chooseInt (0,5)) $ \matches -> ioProperty $ do
    events <- newIORef []
    let payload = B.pack [0xd1,0x61,0x73,0x68,slot] <> B.pack hash
        native step index input = do
          modifyIORef' events (++[(step,index,input)])
          pure $ case step of
            1 -> wordLE 4 (fromIntegral slot) <> B.singleton 0 <> B.replicate 32 0
            2 -> B.singleton 1 <> wordLE 8 (fromIntegral matches)
            3 -> wordLE 2 106
            4 -> wordLE 2 76 <> B.pack [1,37] <> payload
            _ -> B.empty
    result <- execute (ParentReplay.BmmScan native) ParentReplay.ScanBmmCommitment
    seen <- readIORef events
    let published = [(index,input) | (step,index,input) <- seen, step == 5]
    pure (conjoin [result === if matches == 1 then 1 else 0,
      published === if matches == 1 then [(0,B.reverse (B.pack hash))] else [],
      [index | (step,index,_) <- seen, step == 3] === if matches == 0 then [] else [0..fromIntegral matches-1]])

cacheBmmProgress :: Property
cacheBmmProgress = once $ ioProperty $ do
  cases <- mapM (\mode -> do
    (result,events) <- cacheCaptureWithBmm False mode 0 False
    let edges = [(index,input) | (step,index,input,_) <- events, step == 19]
        commits = [input | (step,_,input,_) <- events, step == 205]
        canonical = mode `elem` [0,6]
        commitment = if mode == 6 then B.replicate 32 0 else B.pack [31,30..0]
        writes = [(step,index) | (step,index,_,_) <- events, step `elem` [21,22,24]]
    faults <- mapM (\bad -> do
      (status,seen) <- cacheCaptureWithBmm False mode bad False
      let trace = [(s,i) | (s,i,_,_) <- take bad events]
      pure (conjoin [status === -1, take bad seen === take bad events,
        property ([(s,i) | (s,i,_,_) <- drop bad seen] `elem`
          [sessionFaultTail 500 27 27 trace ++ cleanupTail | cleanupTail <- blockFaultTails 30000 16 28 trace])]))
      [i | (i,(step,_,_,_)) <- zip [1..] events, step == 25 || step >= 201 || step == 19]
    pure (conjoin ([result === 1,
      edges === [(height,B.singleton (if canonical then 1 else 0)) | height <- [101,102]],
      commits === if canonical then replicate 2 commitment else [],
      writes === [(21,101),(22,101),(21,102),(22,102),(24,0)]] ++ faults))) [0,4,5,6]
  pure (conjoin cases)

launchFixture :: ParentCache.LaunchIdentity
launchFixture = ParentCache.LaunchIdentity
  (ParentCache.CacheKey (Just 24) (Just (hash 1)) (hash 2) (hash 3) [2,1,4,3,6,5] 5)
  (B.singleton 1) (hash 1) (B.singleton 2) (10,hash 4) (20,hash 5) 30 (hash 6)
  (hash 0,maxBound,0) (hash 7) True 5 2100000000000000
  where hash n = B.singleton n <> B.replicate 31 0

encodeLaunch :: ParentCache.LaunchIdentity -> B.ByteString
encodeLaunch c = key <> encodeVector (ParentCache.launchDescription c) <> ParentCache.launchManifest c <>
  encodeVector (ParentCache.launchActiveDescription c) <> point (ParentCache.launchProposal c) <>
  point (ParentCache.launchActivation c) <> wordLE 4 (fromIntegral (ParentCache.launchHeight c)) <>
  ParentCache.launchWork c <> treasury <> ParentCache.launchGenesis c <>
  B.singleton (if ParentCache.launchWithdrawals c then 1 else 0) <>
  wordLE 4 (fromIntegral (ParentCache.launchVersion c)) <> wordLE 8 (ParentCache.launchMaximumMoney c)
  where
    ParentCache.CacheKey slot proposal active checkpoint windows version = ParentCache.launchKey c
    key = B.pack [maybe 0 (const 1) slot,maybe 0 id slot,maybe 0 (const 1) proposal] <>
      maybe (B.replicate 32 0) id proposal <> active <> checkpoint <>
      B.concat (map (wordLE 2 . fromIntegral) windows) <> wordLE 4 (fromIntegral version)
    encodeVector b = B.cons (fromIntegral (B.length b)) b
    point (height,block) = wordLE 4 (fromIntegral height) <> block
    (txid,vout,amount) = ParentCache.launchTreasury c
    treasury = txid <> wordLE 4 (fromIntegral vout) <> wordLE 8 (fromIntegral amount)

-- The retained scalar implementation is the pre-migration reference. Observe
-- only real hashing/RPC/diagnostic effects, not its scalar field projections.
launchReference :: ParentCache.LaunchIdentity -> [B.ByteString] -> IO (Int32,[(Word32,B.ByteString)])
launchReference c replies = do
  events <- newIORef []
  let ParentCache.CacheKey slot proposal active checkpoint windows version = ParentCache.launchKey c
      (ph,pb) = ParentCache.launchProposal c
      (ah,ab) = ParentCache.launchActivation c
      (ctip,vout,amount) = ParentCache.launchTreasury c
      empty = not . R.nonzero
      yes True = 1; yes False = 0
      effect step input = modifyIORef' events (++[(step,input)]) >> pure (replies !! fromIntegral step)
      report text = effect 5 (B.pack (map (fromIntegral . fromEnum) text)) >> pure 0
      cp :: Word32 -> IO Int64
      cp step = case step of
        1 -> pure (yes (if empty ctip then vout == maxBound && amount == 0 else
          vout < maxBound && amount > 0 && toInteger amount <= toInteger (ParentCache.launchMaximumMoney c)))
        2 -> pure (yes (B.null (ParentCache.launchActiveDescription c)))
        3 -> pure 1
        4 -> pure (yes (empty active))
        5 -> pure (yes (ph == 0))
        6 -> pure (yes (empty pb))
        7 -> pure (yes (ah == 0))
        8 -> pure (yes (empty ab))
        9 -> pure (yes (empty ctip))
        11 -> cp 2
        12 -> cp 3
        13 -> cp 4
        14 -> yes . (== active) <$> effect 2 B.empty
        15 -> cp 6
        16 -> cp 8
        17 -> pure (yes (ph < ah))
        18 -> pure (yes (ah <= ParentCache.launchHeight c))
        _ -> error "bad checkpoint reference phase"
      action step = case step of
        1 -> pure (yes (not (isNothing slot) && not (isNothing proposal) && not (empty checkpoint)))
        2 -> pure (yes (not (B.null (ParentCache.launchDescription c))))
        3 -> pure (yes (maybe False R.nonzero proposal))
        4 -> yes . (== proposal) . Just <$> effect 1 B.empty
        5 -> pure (yes (R.nonzero (ParentCache.launchManifest c)))
        6 -> fromIntegral <$> ParentReplay.runStore 60 cp
        7 -> pure (yes (R.nonzero (ParentCache.launchWork c)))
        8 -> pure (fromIntegral (windows !! 0))
        9 -> pure (fromIntegral (windows !! 1))
        11 -> pure (fromIntegral (windows !! 2))
        12 -> pure (fromIntegral (windows !! 3))
        14 -> pure (fromIntegral (windows !! 4))
        15 -> pure (fromIntegral (windows !! 5))
        17 -> pure (yes (not (isNothing slot) && ParentCache.launchWithdrawals c))
        18 -> pure (yes (version == ParentCache.launchVersion c))
        19 -> report "native drivechain parent launch identity is incomplete or internally inconsistent"
        20 -> yes . (/= B.singleton 0) <$> effect 3 B.empty
        21 -> pure (yes (B.tail (replies !! 3) == ParentCache.launchGenesis c))
        22 -> report "mainchain RPC does not serve the pinned parent genesis"
        23 -> yes . (/= B.singleton 0) <$> effect 4 B.empty
        24 -> pure (yes (B.take 4 (B.tail (replies !! 4)) == wordLE 4 (fromIntegral (ParentCache.launchHeight c))))
        25 -> pure (yes (B.drop 5 (replies !! 4) == ParentCache.launchWork c))
        26 -> report "authenticated parent launch checkpoint height or chainwork is not pinned value"
        27 -> action 9
        28 -> action 8
        29 -> action 12
        30 -> action 11
        31 -> action 15
        32 -> action 14
        _ -> error "bad launch reference phase"
  result <- ParentCache.admitReplayCache (ParentCache.CacheInitialization action)
  seen <- readIORef events
  pure (result,seen)

launchReplies :: ParentCache.LaunchIdentity -> [B.ByteString]
launchReplies c = [encodeLaunch c,B.singleton 1 <> B.replicate 31 0,B.singleton 2 <> B.replicate 31 0,
  B.cons 1 (ParentCache.launchGenesis c), B.singleton 1 <> wordLE 4 (fromIntegral (ParentCache.launchHeight c)) <>
  ParentCache.launchWork c,B.empty]

data Admission = Admission ParentCache.LaunchIdentity Int32 Int64 Word64 B.ByteString deriving Show

admissionReplies :: Admission -> [B.ByteString]
admissionReplies (Admission c requested amount size digest) =
  [B.empty, eligibility, identity, digest, B.empty]
  where
    ParentCache.CacheKey slot proposal active state windows version = ParentCache.launchKey c
    flag = B.singleton . fromIntegral . fromEnum
    point (height,block) = wordLE 4 (fromIntegral height) <> block
    (ctip,vout,value) = ParentCache.launchTreasury c
    eligibility = flag (not (isNothing slot)) <> B.singleton (maybe 0 id slot) <>
      wordLE 4 (fromIntegral requested) <> wordLE 8 (fromIntegral amount) <> wordLE 8 size
    identity = flag (not (isNothing proposal)) <> maybe (B.replicate 32 0) id proposal <>
      ParentCache.launchManifest c <> state <> ParentCache.launchWork c <>
      encodeVector (ParentCache.launchActiveDescription c) <> active <>
      point (ParentCache.launchProposal c) <> point (ParentCache.launchActivation c) <>
      wordLE 4 (fromIntegral (ParentCache.launchHeight c)) <> ctip <> wordLE 4 (fromIntegral vout) <>
      wordLE 8 (fromIntegral value) <> B.concat (map (wordLE 2 . fromIntegral) windows) <>
      flag (ParentCache.launchWithdrawals c) <> wordLE 4 (fromIntegral version) <>
      wordLE 4 (fromIntegral (ParentCache.launchVersion c))
    encodeVector b = B.cons (fromIntegral (B.length b)) b

-- Independent retained scalar decisions; compare real effects, not the number
-- of now-batched immutable-field callbacks.
admissionReference :: Admission -> IO (Int32,[(Word32,B.ByteString)])
admissionReference (Admission c requested amount size digest) = do
  effects <- newIORef []
  let ParentCache.CacheKey slot proposal active state windows version = ParentCache.launchKey c
      (ph,pb) = ParentCache.launchProposal c
      (ah,ab) = ParentCache.launchActivation c
      (ctip,vout,value) = ParentCache.launchTreasury c
      empty = not . R.nonzero
      yes = fromIntegral . fromEnum
      record step input = modifyIORef' effects (++[(step,input)])
      report :: String -> IO Int64
      report text = record 4 (C.pack text) >> pure 1
      cp step = case step of
        1 -> pure (yes (if empty ctip then vout == maxBound && value == 0 else
          vout < maxBound && value > 0 && toInteger value <= toInteger (ParentCache.launchMaximumMoney c)))
        2 -> pure (yes (B.null (ParentCache.launchActiveDescription c)))
        3 -> pure 1
        4 -> pure (yes (empty active))
        5 -> pure (yes (ph == 0))
        6 -> pure (yes (empty pb))
        7 -> pure (yes (ah == 0))
        8 -> pure (yes (empty ab))
        9 -> pure (yes (empty ctip))
        11 -> cp 2
        12 -> cp 3
        13 -> cp 4
        14 -> record 3 B.empty >> pure (yes (digest == active))
        15 -> cp 6
        16 -> cp 8
        17 -> pure (yes (ph < ah))
        18 -> pure (yes (ah <= ParentCache.launchHeight c))
        _ -> error "invalid reference checkpoint step"
      action step = case step of
        1 -> pure 1
        2 -> record 0 B.empty >> pure 1
        3 -> record 1 B.empty >> case slot of
          Nothing -> report "this network has no configured BIP300/301 sidechain slot" >> pure 0
          Just configured | fromIntegral configured == requested -> pure 1
                          | otherwise -> report ("drivechain sidechain slot must match configured slot " ++
                              show configured ++ ", got " ++ show requested) >> pure 0
        4 -> pure (yes (amount > 0 && toInteger amount <= toInteger (ParentCache.launchMaximumMoney c) && size > 0 && size <= 128))
        5 -> pure 1
        6 -> yes . all ((/=4) . fst) <$> readIORef effects
        7 -> report "invalid slot, amount, or address for drivechain deposit"
        8 -> record 2 B.empty >> pure 1
        9 -> pure (yes (not (isNothing proposal)))
        10 -> pure (yes (maybe False R.nonzero proposal))
        11 -> pure (yes (R.nonzero (ParentCache.launchManifest c)))
        12 -> pure (yes (R.nonzero state))
        13 -> pure (yes (R.nonzero (ParentCache.launchWork c)))
        14 -> fromIntegral <$> ParentReplay.runStore 60 cp
        n | n >= 15 && n <= 20 -> pure (yes (windows !! fromIntegral (n-15) > 0))
        21 -> pure (yes (not (isNothing slot) && ParentCache.launchWithdrawals c))
        22 -> pure (yes (version == ParentCache.launchVersion c))
        23 -> report "native deposits require a complete immutable parent genesis-replay identity" >> pure 2
        _ -> error "invalid reference admission step"
  result <- ParentReplay.runStore 94 action
  (,) result <$> readIORef effects

admissionRun :: Admission -> [(Int,B.ByteString)] -> Int
  -> IO (Int32,[(Word32,B.ByteString)])
admissionRun f@(Admission c _ _ _ _) changed fault = do
  seen <- newIORef []
  let replies = admissionReplies f
      native step index input = do
        when (index /= 0 || (step /= 4 && not (B.null input))) (error "invalid admission request")
        modifyIORef' seen (++[(step,input)])
        count <- length <$> readIORef seen
        when (count == fault) (ioError (userError "admission callback fault"))
        pure (maybe (replies !! fromIntegral step) id (lookup (fromIntegral step) changed))
  result <- try (execute (ParentCache.DepositAdmission (ParentCache.launchMaximumMoney c) native)
    ParentCache.AdmitDeposit) :: IO (Either SomeException Int32)
  (,) (either (const (-1)) id result) <$> readIORef seen

admissionFixture :: Admission
admissionFixture = Admission launchFixture 24 1 1 (B.singleton 2 <> B.replicate 31 0)

admissionGenerated :: Property
admissionGenerated = forAll generator $ \f -> ioProperty $ do
  expected <- admissionReference f
  actual <- admissionRun f [] 0
  pure (actual === expected)
  where
    generator = do
      mode <- chooseInt (0,28)
      requested <- frequency [(8,pure 24),(1,elements [-1,0,23,25,255,256,minBound,maxBound]),(1,arbitrary)]
      amount <- frequency [(8,choose (1,2100000000000000)),(2,elements [minBound,-1,0,2100000000000001,maxBound])]
      size <- frequency [(8,choose (1,128)),(2,elements [0,129,maxBound])]
      let c = launchFixture
          ParentCache.CacheKey slot proposal active state windows version = ParentCache.launchKey c
          zero = B.replicate 32 0
          key s p a h w v = c {ParentCache.launchKey = ParentCache.CacheKey s p a h w v}
          changed = case mode of
            1 -> key Nothing proposal active state windows version
            2 -> key slot Nothing active state windows version
            3 -> key slot (Just zero) active state windows version
            4 -> c {ParentCache.launchManifest = zero}
            5 -> key slot proposal active zero windows version
            6 -> c {ParentCache.launchWork = zero}
            7 -> (key slot proposal zero state windows version) {ParentCache.launchActiveDescription = B.empty,
              ParentCache.launchProposal = (0,zero),ParentCache.launchActivation = (0,zero)}
            8 -> c {ParentCache.launchActiveDescription = B.empty}
            9 -> key slot proposal zero state windows version
            10 -> c {ParentCache.launchProposal = (10,zero)}
            11 -> c {ParentCache.launchActivation = (20,zero)}
            12 -> c {ParentCache.launchProposal = (20,active)}
            13 -> c {ParentCache.launchHeight = 19}
            14 -> c {ParentCache.launchTreasury = (zero,0,0)}
            15 -> c {ParentCache.launchTreasury = (zero,maxBound,1)}
            16 -> c {ParentCache.launchTreasury = (active,maxBound,1)}
            17 -> c {ParentCache.launchTreasury = (active,0,0)}
            18 -> c {ParentCache.launchTreasury = (active,0,-1)}
            19 -> c {ParentCache.launchTreasury = (active,0,2100000000000001)}
            20 -> c {ParentCache.launchTreasury = (active,0,2100000000000000)}
            21 -> c {ParentCache.launchWithdrawals = False}
            22 -> key slot proposal active state windows (version+1)
            n | n >= 23 -> key slot proposal active state
              (take (n-23) windows ++ [0] ++ drop (n-22) windows) version
            _ -> c
      digest <- frequency [(8,pure active),(2,pure zero)]
      pure (Admission changed requested amount size digest)

admissionFraming :: Property
admissionFraming = once $ ioProperty $ do
  (_,trace) <- admissionRun admissionFixture [] 0
  (_,badTrace) <- admissionRun (Admission launchFixture 25 1 1 B.empty) [] 0
  let fixtures = [(admissionFixture,trace),(Admission launchFixture 25 1 1 B.empty,badTrace)]
  cases <- mapM (\(f,calls) -> do
    faults <- mapM (\at -> do
      (result,seen) <- admissionRun f [] at
      pure (conjoin [result === -1,seen === take at calls])) [1..length calls]
    truncated <- mapM (\(at,(step,_)) -> do
      let reply = admissionReplies f !! fromIntegral step
          invalid = B.snoc reply 0 : [B.take n reply | n <- [0..B.length reply-1]]
      checks <- mapM (\bytes -> do
        (result,seen) <- admissionRun f [(fromIntegral step,bytes)] 0
        pure (conjoin [result === -1,seen === take at calls])) invalid
      pure (conjoin checks)) (zip [1..] calls)
    pure (conjoin (faults++truncated))) fixtures
  let mismatch = interpret (SomeOperation (R.Store 0 (error "forced mismatch")))
        (undefined :: DSL ParentCache.DepositAdmission)
  pure (conjoin (property (isNothing mismatch):cases))

launchRun :: ParentCache.LaunchIdentity -> [B.ByteString] -> Int -> Int
  -> IO (Int32,[(Word32,B.ByteString)])
launchRun _ replies fault kind = do
  events <- newIORef []
  let native step index input = do
        when (index /= 0 || step > 5 || (step /= 5 && not (B.null input))) (error "invalid launch request")
        modifyIORef' events (++[(step,input)])
        count <- length <$> readIORef events
        let reply = replies !! fromIntegral step
        if count /= fault then pure reply else case kind of
          0 -> pure (B.snoc reply 0)
          1 -> pure (if B.null reply then B.singleton 0 else B.init reply)
          _ -> ioError (userError "launch callback fault")
  result <- try (ParentCache.admitReplayCache (ParentCache.CacheStartup native)) :: IO (Either SomeException Int32)
  seen <- readIORef events
  pure (either (const (-1)) id result,seen)

launchDifferential :: Property
launchDifferential = forAll (chooseInt (0,34)) $ \mode ->
  forAll (arbitrary :: Gen Word32) $ \bits -> ioProperty $ do
    let f = launchFixture
        ParentCache.CacheKey _ _ active checkpoint windows version = ParentCache.launchKey f
        zero = B.replicate 32 0
        key slot proposal a p w v = f {ParentCache.launchKey = ParentCache.CacheKey slot proposal a p w v}
        base = key (Just 24) (Just (B.singleton 1 <> B.replicate 31 0))
        c = case mode of
          1 -> key Nothing Nothing active checkpoint windows version
          2 -> key (Just 24) Nothing active checkpoint windows version
          3 -> base active zero windows version
          4 -> f {ParentCache.launchDescription = B.empty}
          5 -> key (Just 24) (Just zero) active checkpoint windows version
          6 -> f {ParentCache.launchManifest = zero}
          7 -> (base zero checkpoint windows version) {ParentCache.launchActiveDescription = B.empty,
            ParentCache.launchProposal = (0,zero),ParentCache.launchActivation = (0,zero)}
          8 -> f {ParentCache.launchActiveDescription = B.empty}
          9 -> base zero checkpoint windows version
          10 -> f {ParentCache.launchProposal = (10,zero)}
          11 -> f {ParentCache.launchActivation = (20,zero)}
          12 -> f {ParentCache.launchProposal = (20,active)}
          13 -> f {ParentCache.launchHeight = 19}
          14 -> f {ParentCache.launchTreasury = (zero,0,0)}
          15 -> f {ParentCache.launchTreasury = (zero,maxBound,1)}
          16 -> f {ParentCache.launchTreasury = (active,maxBound,1)}
          17 -> f {ParentCache.launchTreasury = (active,0,0)}
          18 -> f {ParentCache.launchTreasury = (active,0,-1)}
          19 -> f {ParentCache.launchTreasury = (active,0,fromIntegral (ParentCache.launchMaximumMoney f)+1)}
          20 -> f {ParentCache.launchTreasury = (active,0,1)}
          21 -> f {ParentCache.launchWork = zero}
          22 -> base active checkpoint [if testBit bits i then 0 else w | (i,w) <- zip [0..] windows] version
          23 -> base active checkpoint [1,2,3,4,5,6] version
          24 -> f {ParentCache.launchWithdrawals = False}
          25 -> f {ParentCache.launchVersion = 4}
          26 -> f {ParentCache.launchProposal = (bits,active),ParentCache.launchActivation = (bits+1,checkpoint)}
          _ -> f
        ordinary = launchReplies c
        replacement = case mode of
          27 -> Just (1,zero)
          28 -> Just (2,zero)
          29 -> Just (3,B.singleton 0)
          30 -> Just (3,B.cons 1 zero)
          31 -> Just (4,B.singleton 0)
          32 -> Just (4,B.singleton 1 <> wordLE 4 0 <> ParentCache.launchWork c)
          33 -> Just (4,B.singleton 1 <> wordLE 4 (fromIntegral (ParentCache.launchHeight c)) <> zero)
          _ -> Nothing
        replies = [case replacement of Just (i,changed) | i == index -> changed; _ -> b | (index,b) <- zip [0 :: Int ..] ordinary]
    expected <- launchReference c replies
    (actual,events) <- launchRun c replies 0 0
    pure (counterexample (show (mode,bits)) (conjoin [R.decode ParentCache.launchIdentity (encodeLaunch c) === Right c,
      (actual,drop 1 events) === expected]))

launchFraming :: Property
launchFraming = once $ ioProperty $ do
  let c = launchFixture
      variants = [(1,launchReplies c),(2,launchReplies (c {ParentCache.launchManifest = B.replicate 32 0}))]
      mismatch = interpret (SomeOperation (ParentReplay.RpcPreparation undefined))
        (error "forced mismatched startup DSL" :: DSL ParentCache.CacheStartup)
  checks <- mapM (\(expected,replies) -> do
    (good,events) <- launchRun c replies 0 0
    faults <- mapM (\(at,kind) -> do
      (status,seen) <- launchRun c replies at kind
      pure (conjoin [status === -1,seen === take at events]))
      [(at,kind) | at <- [1..length events],kind <- [0..2]]
    pure (conjoin ((good === expected):faults))) variants
  let bytes = encodeLaunch c
  pure (conjoin (property (isNothing mismatch):checks ++
    [property (isLeft (R.decode ParentCache.launchIdentity (B.take n bytes))) | n <- [0..B.length bytes-1]]))

startupCapture :: Int -> Int -> Int -> IO (Int32,[(Word32,Word64)])
startupCapture mode fault kind = do
  events <- newIORef []
  let ordinary = launchReplies launchFixture
      scalar index
        | index == 204 = if mode >= 4 then 1 else 0
        | index == 205 = 0
        | index == 225 = 31
        | index == 209 = 30
        | index == 301 = if mode == 4 then 0 else 1
        | index == 311 || index == 707 = 0
        | index == 336 = 0
        | otherwise = 1
      native step index input = do
        when (step `notElem` [305,425,1500] && not (B.null input)) (error "invalid startup input")
        modifyIORef' events (++[(step,index)])
        count <- length <$> readIORef events
        let reply = case step of
              8 -> B.empty
              26 -> B.empty
              300 | mode == 3 -> let bytes = head ordinary in B.cons 0 (B.tail bytes)
              301 | mode == 2 -> B.replicate 32 0
              303 | mode == 1 -> B.singleton 0
              310 -> wordLE 8 (scalar index)
              311 -> wordLE 4 31 <> B.pack [1,2] <> B.replicate 32 0 <>
                B.replicate 32 1 <> wordLE 4 30 <> B.replicate 32 1 <> B.singleton 1 <>
                B.replicate 32 2 <> wordLE 4 2 <> B.singleton 0
              312 -> B.replicate 32 1
              313 -> B.replicate 32 1
              314 -> B.singleton 24 <> wordLE 8 0
              318 -> B.replicate 32 0
              319 -> wordLE 8 2100000000000000
              320 -> B.empty
              321 -> wordLE 8 2100000000000000
              322 -> B.empty
              323 -> blockParameters
              324 -> B.empty
              _ | step >= 1300 && step <= 21781 -> blockReply True (step-1300) index
              _ | step >= 400 && step <= 443 -> sessionReply
                (if mode >= 4 then R.ResetSession else R.LoadSession) (if mode == 6 then 0 else 1)
                (storeTip 30 (B.replicate 32 1)) B.empty (step-400) index
              _ | step >= 300 && step <= 305 -> ordinary !! fromIntegral (step-300)
              _ -> error "invalid startup effect"
        if count /= fault then pure reply else case kind of
          0 -> pure (B.snoc reply 0)
          1 -> pure (if B.null reply then B.singleton 0 else B.init reply)
          _ -> ioError (userError "startup effect fault")
  result <- try (runExceptT (ParentCache.initializeCacheProgress (ParentCache.CacheProgress native)
    (if mode >= 4 then 1 else 0))) :: IO (Either SomeException (Either Int32 ()))
  seen <- readIORef events
  pure (either (const (-1)) (either id (const 1)) result,seen)

startupCleanup :: Property
startupCleanup = once $ ioProperty $ do
  checks <- mapM (\mode -> do
    (status,events) <- startupCapture mode 0 0
    failures <- mapM (\(at,kind) -> do
      (failed,seen) <- startupCapture mode at kind
      let prefix = take at events
          cleanup = [sessionFaultTail 400 320 322 prefix ++ cleanupTail ++
            (if at > 1 && at < length events then [(26,0)] else [])
            | cleanupTail <- blockFaultTails 1300 323 324 prefix]
      pure (counterexample (show (mode,at,kind)) (conjoin [failed === -1,
        property (seen `elem` map (prefix ++) cleanup)])))
      [(at,kind) | at <- [1..length events],kind <- [0..2]]
    pure (conjoin ([status === if mode `elem` [1,2,6] then 0 else 1,
      last events === (26,0),length (filter ((==26) . fst) events) === 1,
      property (if mode <= 3 && mode /= 0 then all ((/=310) . fst) events else True),
      property (if mode >= 4 then (310,250) `elem` events && (321,0) `elem` events else True)] ++ failures))) [0..6]
  pure (conjoin checks)

loadedFixture :: Word32 -> ParentCache.LoadedCache
loadedFixture bits = ParentCache.LoadedCache 100 (if testBit bits 3 then B.singleton 1 else B.empty)
  (h (testBit bits 4)) (h True) (if testBit bits 5 then 99 else 101)
  (if testBit bits 6 then h False else if testBit bits 7 then B.replicate 32 2 else h True)
  (testBit bits 8) (h (testBit bits 9)) (if testBit bits 10 then 200 else 50) (testBit bits 11)
  where h present = B.replicate 32 (if present then 1 else 0)

encodeLoaded :: ParentCache.LoadedCache -> B.ByteString
encodeLoaded (ParentCache.LoadedCache checkpoint description ctip required height active activated activationBlock activationHeight hasCtip) =
  wordLE 4 (fromIntegral checkpoint) <> B.cons (fromIntegral (B.length description)) description <> ctip <> required <>
  wordLE 4 (fromIntegral height) <> active <> flag activated <> activationBlock <>
  wordLE 4 (fromIntegral activationHeight) <> flag hasCtip
  where flag b = B.singleton (if b then 1 else 0)

loadedCapture :: Bool -> Word32 -> Int64 -> Int -> Int -> IO (Int32,[Word32],[(Word32,Word64)])
loadedCapture migrated bits status fault kind = do
  effects <- newIORef []
  calls <- newIORef []
  let c@(ParentCache.LoadedCache checkpoint description ctip required height active activated activationBlock activationHeight hasCtip) = loadedFixture bits
      yes b = if b then 1 else 0
      action step = do
        when (step `notElem` [207..217] && step `notElem` [222,223,225,226]) (modifyIORef' effects (++[step]))
        pure $ case step of
          201 -> yes (testBit bits 0)
          204 -> yes (testBit bits 1)
          205 -> yes (testBit bits 2)
          206 -> status
          209 -> fromIntegral height
          210 -> yes (not (B.null description))
          211 -> yes (not (R.nonzero active))
          212 -> yes activated
          213 -> yes (active /= required)
          214 -> yes (not (R.nonzero activationBlock))
          215 -> fromIntegral height
          216 -> yes (R.nonzero ctip)
          217 -> yes (not hasCtip)
          222 -> yes (status == 2)
          223 -> yes (status == 3)
          225 -> fromIntegral checkpoint
          226 -> fromIntegral activationHeight
          _ -> 1
      native step index input = do
        unless (B.null input || step == 125) (error "unexpected load request input")
        modifyIORef' calls (++[(step,index)])
        reply <- case step of
          10 -> wordLE 8 . fromIntegral <$> action (fromIntegral index)
          11 | index == 0 -> pure (encodeLoaded c)
          19 -> modifyIORef' effects (++[206]) >> pure (wordLE 8 2100000000000000)
          20 -> pure B.empty
          _ | step >= 100 && step <= 143 -> pure (sessionReply R.LoadSession status
            (storeTip height (B.replicate 32 1)) B.empty (step-100) index)
          _ -> error "unknown load request"
        count <- length <$> readIORef calls
        if count /= fault then pure reply else case kind of
          0 -> pure (B.snoc reply 0)
          1 -> pure (B.init reply)
          _ -> ioError (userError "load callback fault")
  result <- try (if migrated then ParentCache.loadReplayCache (ParentCache.CacheStartup native)
    else ParentCache.loadReplayCache (ParentCache.CacheInitialization action)) :: IO (Either SomeException Int32)
  seen <- readIORef effects
  trace <- readIORef calls
  pure (either (const (-1)) id result,seen,trace)

loadedDifferential :: Property
loadedDifferential = forAll (arbitrary :: Gen Word32) $ \bits -> forAll (choose (0,4)) $ \status -> ioProperty $ do
  (expected,effects,_) <- loadedCapture False bits status 0 0
  (actual,seen,_) <- loadedCapture True bits status 0 0
  let c = loadedFixture bits
  pure (conjoin [(actual,seen) === (expected,effects),R.decode ParentCache.loadedCache (encodeLoaded c) === Right c])

loadedFraming :: Property
loadedFraming = once $ ioProperty $ do
  checks <- mapM (\(bits,status) -> do
    (_,_,calls) <- loadedCapture True bits status 0 0
    failures <- mapM (\(at,kind) -> do
      (failed,_,trace) <- loadedCapture True bits status at kind
      pure (counterexample (show (bits,status,at,kind))
        (conjoin [failed === -1,trace === take at calls ++ sessionFaultTail 100 20 20 (take at calls)])))
      [(at,kind) | at <- [1..length calls],kind <- [0..2]]
    pure (conjoin failures)) [(bits,status) | bits <- [0,1,2,4,8,16,32,256,512,4095],status <- [0..4]]
  let bytes = encodeLoaded (loadedFixture 0)
  pure (conjoin (checks ++ [property (isLeft (R.decode ParentCache.loadedCache (B.take n bytes))) | n <- [0..B.length bytes-1]]))

data BootSlot = BootSlot Word8 Bool Bool B.ByteString B.ByteString Word32 Int64

bootstrapCapture :: Bool -> Int -> Int -> Int -> IO (Int32,[(Word32,B.ByteString)],[(Word32,Word64)])
bootstrapCapture migrated mode fault kind = do
  effects <- newIORef []
  calls <- newIORef []
  cursor <- newIORef (0 :: Int)
  preimage <- newIORef (0 :: Int)
  inserted <- newIORef S.empty
  let zero = B.replicate 32 0
      hash = B.replicate 32 1
      ordinary = BootSlot 3 True True hash hash 0 1
      slots = case mode of
        4 -> [BootSlot 24 True True hash hash 0 1]
        5 -> [BootSlot 3 False True hash hash 0 1]
        6 -> [BootSlot 3 True False hash hash 0 1]
        7 -> [BootSlot 3 True True zero hash 0 1]
        8 -> [BootSlot 3 True True hash zero 0 0]
        9 -> [BootSlot 3 True True hash zero maxBound 1]
        10 -> [ordinary,ordinary]
        15 -> [BootSlot 3 True True hash zero maxBound 0]
        16 -> []
        17 -> [BootSlot 3 True True hash hash 0 (-1)]
        18 -> [ordinary,BootSlot 24 True True hash hash 0 1]
        19 -> [BootSlot 3 True True hash hash 0 0]
        _ -> [ordinary]
      yes b = if b then 1 else 0
      expected = if mode == 2 then zero else hash
      digest = if mode == 3 then zero else hash
      record step input = modifyIORef' effects (++[(step,input)])
      report message = record 5 (B.pack (map (fromIntegral . fromEnum) message)) >> pure 0
      action :: Word32 -> IO Int64
      action step = do
        index <- readIORef cursor
        pre <- readIORef preimage
        let BootSlot slot hasActive hasCtip active ctip vout amount = slots !! index
        case step of
          301 -> pure (yes (mode `notElem` [1,11,12,13]))
          305 -> pure (yes (R.nonzero expected))
          306 -> record 13 B.empty >> pure (yes (expected == digest))
          311 -> pure (yes (index < length slots))
          312 -> pure (yes (slot /= 24))
          313 -> pure (yes hasActive)
          314 -> pure (yes hasCtip)
          319 -> pure (yes (R.nonzero active))
          323 -> pure (yes (R.nonzero ctip))
          326 -> pure (yes (vout == maxBound))
          327 -> pure (yes (amount == 0))
          342 -> pure (yes (mode /= 12))
          308 -> report "parent replay bootstrap state does not match its identity commitment"
          316 -> report "parent replay bootstrap contains an invalid global slot"
          321 -> report "parent replay bootstrap contains a null active proposal"
          329 -> report "parent replay bootstrap has a malformed absent CTIP"
          339 -> report "parent replay bootstrap repeats a global slot"
          344 -> report "authenticated parent genesis unexpectedly has a predecessor"
          _ | step `elem` [307,315,320,328,336,338,343] -> record 307 B.empty >> pure (if step == 336 then 0 else 1)
          _ -> do
            record step B.empty
            case step of
              310 -> writeIORef cursor 0 >> pure 1
              330 -> do
                seen <- readIORef inserted
                writeIORef inserted (S.insert slot seen)
                pure (yes (not (S.member slot seen)))
              331 -> modifyIORef' cursor (+1) >> pure 1
              335 -> pure (yes (mode /= 14))
              341 -> pure (yes (mode /= 11))
              346 -> pure (yes (mode /= 13))
              700 -> writeIORef preimage 0 >> pure 1
              707 -> pure (yes (pre < length slots))
              714 -> let BootSlot _ _ _ _ treasury _ _ = slots !! pre in pure (yes (R.nonzero treasury))
              718 -> modifyIORef' preimage (+1) >> pure 1
              _ -> pure 1
      native step argument input = do
        when (step < 1000 && ((step `notElem` [10,143] && argument /= 0) ||
          (step `notElem` [5,125] && not (B.null input)))) (error "invalid bootstrap request")
        modifyIORef' calls (++[(step,argument)])
        index <- readIORef cursor
        let BootSlot slot hasActive hasCtip active ctip vout amount = slots !! index
        reply <- case step of
          5 -> record 5 input >> pure B.empty
          10 -> wordLE 8 . fromIntegral <$> action (fromIntegral argument)
          12 -> pure expected
          13 -> record 13 B.empty >> pure digest
          14 -> pure (B.singleton 24 <> wordLE 8 (fromIntegral (length slots)))
          15 -> pure (B.pack [slot,yes hasActive,yes hasCtip])
          16 -> pure active
          17 -> pure (ctip <> wordLE 4 (fromIntegral vout) <> wordLE 8 (fromIntegral amount))
          18 -> pure (if mode == 12 then hash else zero)
          21 -> record 335 B.empty >> pure (wordLE 8 2100000000000000)
          22 -> pure B.empty
          23 -> record 346 B.empty >> pure blockParameters
          24 -> pure B.empty
          _ | step >= 1000 && step <= 21481 -> pure (blockReply (mode /= 13) (step-1000) argument)
          _ | step >= 100 && step <= 143 -> pure (sessionReply R.ResetSession (if mode == 14 then 0 else 1)
            (storeTip 100 hash) B.empty (step-100) argument)
          _ -> error "unknown bootstrap request"
        count <- length <$> readIORef calls
        if count /= fault then pure reply else case kind of
          0 -> pure (B.snoc reply 0)
          1 -> pure (if B.null reply then B.singleton 0 else B.init reply)
          _ -> ioError (userError "bootstrap callback fault")
  result <- try (if migrated then ParentCache.rebuildReplayCache (ParentCache.CacheStartup native)
    else ParentCache.rebuildReplayCache (ParentCache.CacheInitialization action)) :: IO (Either SomeException Int32)
  seen <- readIORef effects
  trace <- readIORef calls
  pure (either (const (-1)) id result,seen,trace)

bootstrapDifferential :: Property
bootstrapDifferential = once $ ioProperty $ do
  cases <- mapM (\mode -> do
    (expected,effects,_) <- bootstrapCapture False mode 0 0
    (actual,seen,calls) <- bootstrapCapture True mode 0 0
    faults <- mapM (\(at,kind) -> do
      (failed,_,trace) <- bootstrapCapture True mode at kind
      let prefix = take at calls
          cleanup = [sessionFaultTail 100 22 22 prefix ++ cleanupTail | cleanupTail <- blockFaultTails 1000 23 24 prefix]
      pure (counterexample (show (mode,at,kind,trace)) (conjoin [failed === -1,
        property (trace `elem` map (prefix ++) cleanup)])))
      [(at,kind) | at <- [1..length calls],kind <- [0..2]]
    pure (counterexample (show mode) (conjoin (((actual,seen) === (expected,effects)):faults)))) [0..19]
  pure (conjoin cases)

data ConfirmationCase = ConfirmationCase Int Bool Bool Bool Word32 Word32 Word32
  deriving Show

confirmationFrames :: ConfirmationCase -> Word32 -> Word64 -> B.ByteString
confirmationFrames (ConfirmationCase mode budget snapshot explicit height through depth) step index = case step of
  0 -> flag budget
  1 -> flag (mode /= 1)
  3 -> flag (mode /= 2) <> key <> w through <> hash 8 <>
    flag (mode /= 7) <> hash (if mode == 8 then 9 else 1) <> w activation <> wordLE 8 epoch
  4 -> flag snapshot <> (if snapshot then w through <> wordLE 8 (if mode == 6 then 4 else epoch) <> flag explicit else B.empty)
  5 -> flag (mode /= 10)
  7 -> record <> hash (if mode == 14 then 9 else 8) <>
    wordLE 8 (if mode == 15 then 101 else 100) <> B.pack [1,if mode == 16 then 52 else 51]
  8 -> confirmationDepthSnapshot depth
  9 -> if mode == 18 then flag False else flag True <> hash (if mode == 19 then 9 else 8)
  16 -> if mode == 3 then B.init key <> B.singleton 9 else key
  18 -> wordLE 8 (if mode == 5 then 4 else epoch)
  100 -> B.pack [1,1]
  125 -> B.singleton 1
  126 -> B.singleton 1 <> hash 1 <> w 0
  127 -> B.pack [1,if mode == 11 then 0 else 1]
  128 -> if mode == 12 then B.pack [1,0] else B.pack [1,1] <> record
  143 -> B.singleton 1 <> wordLE 4 index
  200 -> B.singleton 1 <> wordLE 8 0
  242 -> B.singleton 1 <> wordLE 8 64
  _ | step >= 200 && step <= 245 -> B.singleton 1 <> wordLE 8 1
  _ -> B.empty
  where
    flag b = B.singleton (if b then 1 else 0)
    w = wordLE 4 . fromIntegral
    hash n = B.singleton n <> B.replicate 31 0
    key = B.pack [1,24,1] <> hash 1 <> hash 2 <> hash 3 <>
      B.concat (map (wordLE 2) [2,1,4,3,6,5]) <> w 5
    epoch = if mode == 4 then 0 else 5
    activation | mode == 9 = if through < maxBound then through+1 else maxBound
               | mode == 17 = if height < maxBound then height+1 else maxBound
               | otherwise = 0
    record = hash (if mode == 13 then 0 else 1) <> w 0 <> hash 8 <> w height <> wordLE 8 100 <> B.pack [1,51]

confirmationTrace :: Word32 -> B.ByteString -> [String]
confirmationTrace step input = case step of
  1 -> ["try-lock"]
  2 -> ["lock"]
  9 -> ["parent"]
  10 -> ["revoke"]
  11 -> ["clear"]
  12 -> ["rebuild"]
  13 -> ["publish"]
  14 -> ["fence"]
  15 -> [C.unpack input]
  125 -> [C.unpack input]
  127 -> ["exists"]
  128 -> ["read"]
  _ -> []

confirmationProgram :: DSL (ParentCache.ConfirmedDeposit ())
confirmationProgram = ParentCache.AuthenticateConfirmation (ParentCache.MatchConfirmation ParentCache.ReadConfirmation)

runConfirmation :: ConfirmationCase -> Int -> Bool -> IO (Either SomeException Int32,[(Word32,Word64,B.ByteString,B.ByteString)])
runConfirmation config bad fault = do
  calls <- newIORef []
  let native step index input = do
        n <- length <$> readIORef calls
        let reply = confirmationFrames config step index
        modifyIORef' calls (++[(step,index,input,reply)])
        when (n == bad && fault) (fail "confirmation callback fault")
        pure (if n == bad then B.snoc reply 0 else reply)
  result <- try @SomeException $ continue @(ParentCache.ConfirmedDeposit ()) ParentCache.ConfirmationReply $
    execute (ParentCache.ConfirmedDeposit 1000 native) confirmationProgram
  events <- readIORef calls
  pure (result,events)

-- Retained scalar orchestration is independent of the new fold and frames.
referenceConfirmation :: ConfirmationCase -> IO (Int32,[String])
referenceConfirmation (ConfirmationCase mode budget snapshot explicit height through depth) = do
  events <- newIORef []
  let record :: String -> IO Int64
      record text = modifyIORef' events (++[text]) >> pure 1
      yes b = pure (if b then 1 else 0)
      anchored = budget && snapshot
      target = anchored && explicit
      activation | mode == 9 = if through < maxBound then through+1 else maxBound
                 | mode == 17 = if height < maxBound then height+1 else maxBound
                 | otherwise = 0
      required = max 1 depth
      action step = case step of
        1 -> yes budget
        2 -> record "try-lock" >> yes (mode /= 1)
        3 -> record "authenticated parent replay cache is busy warming"
        4 -> record "lock"
        5 -> yes (mode `notElem` [2,3,4,5])
        6 -> record "authenticated parent replay cache is not warmed"
        8 -> yes budget
        9 -> yes snapshot
        11 -> yes (mode /= 6)
        12 -> record "authenticated parent replay cache changed during validation"
        13 -> if mode `elem` [7,8] || activation > through
          then record ("configured Elements slot proposal is not active at parent height " ++ show through) >> pure 0 else pure 1
        14 -> yes (mode /= 10)
        15 -> record "persistent authenticated parent replay index is not open"
        16 -> do
          _ <- record "exists"
          unless (mode == 11) $ do
            _ <- record "read"
            when (mode == 12) $ record "persistent parent replay deposit record is malformed" >> pure ()
            when (mode == 13) $ record "persistent parent replay deposit record is internally inconsistent" >> pure ()
          pure 1
        17 -> yes (mode `elem` [12,13])
        18 -> record "revoke"
        19 -> record "clear"
        20 -> record "rebuild"
        21 -> yes (mode == 11)
        22 -> record (if target then "deposit is not a genesis-replay-derived canonical CTIP increase before the block's authenticated parent anchor"
          else "deposit is not present in the currently warmed parent replay snapshot")
        23 -> yes (mode /= 14)
        24 -> yes (mode /= 15)
        25 -> yes (mode /= 16)
        26 -> record "deposit does not exactly match the genesis-replay-derived canonical CTIP increase"
        27 -> yes (height >= activation)
        28 -> record ("native deposit at parent height " ++ show height ++ " predates Elements proposal activation at height " ++ show activation)
        30 -> yes (toInteger through-toInteger height+1 >= toInteger required)
        31 -> record ("deposit at parent height " ++ show height ++ " does not have " ++ show required ++
          " confirmations through authenticated parent height " ++ show through)
        32 -> yes (not anchored)
        33 -> record "parent" >> yes (mode /= 18)
        34 -> yes (mode /= 19)
        35 -> record "revoke"
        36 -> record "authenticated parent replay cache is stale after a parent reorganization"
        37 -> yes budget
        38 -> record "publish"
        39 -> record "fence"
        43 -> yes target
        _ -> pure 1
  result <- ParentReplay.runStore 93 action
  seen <- readIORef events
  pure (result,seen)

confirmationDifferential :: Property
confirmationDifferential = forAll scenario $ \config -> ioProperty $ do
  (expected,effects) <- referenceConfirmation config
  (actual,seen) <- runConfirmation config (-1) False
  pure $ counterexample (show (actual,seen)) $ conjoin
    [either (const False) (==expected) actual === True,
     concat [confirmationTrace step input | (step,_,input,_) <- seen] === effects]
  where
    scenario = ConfirmationCase <$> choose (0,19) <*> arbitrary <*> arbitrary <*> arbitrary
      <*> boundary <*> boundary <*> boundary
    boundary = frequency [(3,elements [0,1,5,6,100,maxBound-1,maxBound]),(1,arbitrary)]

newtype FoldTrace a = FoldTrace [String]

confirmationFold :: Property
confirmationFold = once $ ioProperty $ do
  let algebra = ParentCache.ConfirmationAlgebra (FoldTrace ["snapshot"])
        (\(FoldTrace xs) -> FoldTrace (xs++["match"])) (\(FoldTrace xs) -> FoldTrace (xs++["authenticate"]))
      FoldTrace stages = foldOperation algebra confirmationProgram
      mismatch = interpret (SomeOperation (R.Store undefined undefined))
        (undefined :: DSL (ParentCache.ConfirmedDeposit ()))
      wrongIndex = interpret (SomeOperation (ParentCache.ConfirmedDeposit 1000 undefined :: ParentCache.ConfirmedDeposit ParentCache.ConfirmationView))
        (undefined :: DSL (ParentCache.ConfirmedDeposit ()))
  cases <- mapM (\config -> do
    (good,calls) <- runConfirmation config (-1) False
    faults <- mapM (\(at,fault) -> do
      (result,seen) <- runConfirmation config at fault
      pure $ counterexample (show (at,fault,result,seen)) $ conjoin
        [property (either (const True) (<0) result), seen === take (at+1) calls])
      [(at,fault) | (at,(step,_,_,_)) <- zip [0..] calls, step < 100 && step /= 17, fault <- [False,True]]
    pure (conjoin (property (either (const False) (>=0) good):faults)))
    [ConfirmationCase mode budget snapshot True 90 100 6 | mode <- [0..19], (budget,snapshot) <- [(False,False),(True,False),(True,True)]]
  pure (conjoin ([stages === ["snapshot","match","authenticate"], property (isNothing mismatch),property (isNothing wrongIndex)]++cases))

data CandidateCase = CandidateCase Int Word32 Word32 Word32 [Word32] Int deriving Show

candidateProgram :: DSL (ParentCache.DepositCandidates ())
candidateProgram = ParentCache.FilterCandidates (ParentCache.ScanCandidates ParentCache.ReadCandidateSnapshot)

runCandidates :: CandidateCase -> Int -> Bool
  -> IO (Either SomeException Int32, [Int], Maybe Int, [String], [(Word32,Word64)])
runCandidates (CandidateCase mode through activation depth heights after) bad throwing = do
  calls <- newIORef []
  position <- newIORef (max 0 after)
  staged <- newIORef []
  page <- newIORef []
  cursor <- newIORef Nothing
  publishedCursor <- newIORef Nothing
  selected <- newIORef []
  messages <- newIORef []
  let flag b = B.singleton (if b then 1 else 0)
      w = wordLE 4 . fromIntegral
      hash n = B.singleton n <> B.replicate 31 0
      key = B.pack [1,24,1] <> hash 1 <> hash 2 <> hash 3 <>
        B.concat (map (wordLE 2) [2,1,4,3,6,5]) <> w 5
      report input = modifyIORef' messages (++[C.unpack input]) >> pure B.empty
      scan step input = do
        n <- readIORef position
        case step of
          0 -> pure (flag True)
          8 -> pure (wordLE 8 64)
          25 -> report input
          26 -> pure (if after < 0 then flag False else flag True <> outpoint after)
          29 -> writeIORef page [] >> writeIORef publishedCursor Nothing >> pure B.empty
          30 -> pure B.empty
          31 -> pure (flag (n < length heights))
          32 -> pure (B.pack [1,100])
          33 -> pure (flag True <> outpoint n)
          34 -> pure (flag True <> outpoint n <> hash 8 <> w (heights !! n) <>
            wordLE 8 (if mode == 9 then 0 else 100) <> B.pack [1,51])
          35 -> modifyIORef' staged (++[n]) >> pure B.empty
          36 -> modifyIORef' position (+1) >> pure B.empty
          37 -> readIORef staged >>= writeIORef cursor . Just . last >> pure B.empty
          38 -> do
            readIORef staged >>= writeIORef page
            readIORef cursor >>= writeIORef publishedCursor
            pure B.empty
          _ -> fail ("unexpected candidate scan effect " ++ show step)
      native step index input = do
        at <- length <$> readIORef calls
        modifyIORef' calls (++[(step,index)])
        when (at == bad && throwing) (fail "candidate callback fault")
        reply <- case step of
          0 -> pure (flag (mode /= 1))
          1 -> pure (flag (mode /= 2) <> key <> w through <> hash 8 <>
            flag (mode /= 7) <> hash (if mode == 8 then 9 else 1) <> w activation <>
            wordLE 8 (if mode == 5 then 0 else 5))
          2 -> pure (if mode == 3 then B.init key <> B.singleton 9 else key)
          3 -> pure (flag (mode /= 4))
          4 -> pure (wordLE 8 (if mode == 6 then 4 else 5))
          5 -> pure (wordLE 8 1000)
          6 -> pure B.empty
          7 -> pure (confirmationDepthSnapshot depth)
          8 -> wordLE 8 . fromIntegral . length <$> readIORef page
          9 -> do entries <- readIORef page; pure (w (heights !! (entries !! fromIntegral index)))
          10 -> do entries <- readIORef page; modifyIORef' selected (++[entries !! fromIntegral index]); pure B.empty
          11 -> report input
          143 -> pure (B.singleton 1 <> wordLE 4 (if index == 4 then 0 else index))
          134 | mode == 10 -> report (C.pack "parent deposit scan failed: read fault") >> pure (B.singleton 0 <> wordLE 4 0)
          _ | step >= 100 -> B.cons 1 <$> scan (step-100) input
            | otherwise -> fail ("unexpected candidate effect " ++ show step)
        pure (if at == bad then B.snoc reply 0 else reply)
  result <- try @SomeException $ continue @(ParentCache.DepositCandidates ()) ParentCache.CandidateReply $
    execute (ParentCache.DepositCandidates native) candidateProgram
  (,,,,) result <$> readIORef selected <*> readIORef publishedCursor <*> readIORef messages <*> readIORef calls

candidateDifferential :: Property
candidateDifferential = forAll scenario $ \config@(CandidateCase mode through activation depth heights after) -> ioProperty $ do
  (result,selected,cursor,messages,calls) <- runCandidates config (-1) False
  let remaining = [max 0 (after+1)..length heights-1]
      page = take 64 remaining
      unavailable = mode `elem` [1..6]
      inactive = mode `elem` [7,8] || activation > through
      corrupt = mode `elem` [9,10] && not (null page)
      success = not (unavailable || inactive || corrupt)
      eligible i = let h = heights !! i in h >= activation && h <= through &&
            toInteger through-toInteger h+1 >= max 1 (toInteger depth)
      expectedMessage
        | unavailable = ["authenticated parent deposit index is unavailable"]
        | inactive = ["configured Elements slot proposal is not active at parent height " ++ show through]
        | corrupt = [if mode == 9 then "malformed parent deposit scan record" else "parent deposit scan failed: read fault"]
        | otherwise = []
  pure $ counterexample (show (result,selected,cursor,messages,calls)) $ conjoin
    [either (const False) (==if success then 1 else 0) result === True,
     selected === if success then filter eligible page else [],
     cursor === if success && length remaining > 64 then Just (last page) else Nothing,
     messages === expectedMessage,
     property (success || all ((/=7) . fst) calls),
     property (not success || elem (6,0) (takeWhile (/=(7,0)) calls))]
  where
    boundary = frequency [(3,elements [0,1,5,6,100,maxBound-1,maxBound]),(1,arbitrary)]
    scenario = do
      count <- chooseInt (0,75)
      CandidateCase <$> choose (0,10) <*> boundary <*> boundary <*> boundary
        <*> vectorOf count boundary <*> chooseInt (-1,count+1)

candidateFoldAndFaults :: Property
candidateFoldAndFaults = once $ ioProperty $ do
  let FoldTrace stages = foldOperation (ParentCache.CandidateAlgebra (FoldTrace ["snapshot"])
        (\(FoldTrace xs) -> FoldTrace (xs++["scan"])) (\(FoldTrace xs) -> FoldTrace (xs++["filter"]))) candidateProgram
      mismatch = interpret (SomeOperation (R.Store undefined undefined))
        (undefined :: DSL (ParentCache.DepositCandidates ()))
      wrongIndex = interpret (SomeOperation (ParentCache.DepositCandidates undefined :: ParentCache.DepositCandidates ParentCache.CandidateSnapshot))
        (undefined :: DSL (ParentCache.DepositCandidates ()))
  cases <- mapM (\config -> do
    (_,_,_,_,calls) <- runCandidates config (-1) False
    faults <- mapM (\(at,throwing) -> do
      (result,_,_,_,seen) <- runCandidates config at throwing
      let (step,_) = calls !! at
          tails | step >= 100 && step < 143 = [[(143,4),(6,0)],[(6,0)]]
                | step == 143 = [[(6,0)]]
                | otherwise = [[]]
      pure $ counterexample (show (at,throwing,result,seen)) $ conjoin
        [property (either (const True) (/=1) result),
         take (at+1) seen === take (at+1) calls,
         property (drop (at+1) seen `elem` tails)]) [(at,fault) | at <- [0..length calls-1], fault <- [False,True]]
    pure (conjoin faults)) [CandidateCase mode 100 1 6 [0,1,90,99,101] (-1) | mode <- [0..10]]
  pure (conjoin ([stages === ["snapshot","scan","filter"],property (isNothing mismatch),property (isNothing wrongIndex)]++cases))

properties :: [(String,Property)]
properties =
  [ ("Replay records / canonical CompactSize round trip and truncations",compact)
  , ("Replay records / noncanonical and oversized collections",bounds)
  , ("Replay store / generic capability composition and lazy mismatch",dispatch)
  , ("Replay append / strict reply framing stops every subsequent effect",framing)
  , ("Replay lookup / strict reply framing and missing-result distinction",lookupFraming)
  , ("Replay scan / variable pages, exclusive cursors and atomic publication",scanPages)
  , ("Replay scan / strict framing stops at every effect",scanFraming)
  , ("Replay lifecycle / strict framing preserves load/reset effect order",lifecycleFraming)
  , ("Replay sessions / recoverable faults, completion framing and no later effects",sessionFailures)
  , ("Replay lifecycle / truncated identity and tip records reject before effects",lifecycleTruncation)
  , ("Parent cache / generic capabilities preserve stage rejection and lazy mismatch",cacheComposition)
  , ("Parent block session / parameter and completion framing, native scope lifetime",blockSessionFraming)
  , ("Parent cache / strict framing and durable-before-published effects",cacheFraming)
  , ("Parent cache / generated snapshot heights and truncation rejection",cacheSnapshotTruncation)
  , ("Parent milestone / capability stages and lazy mismatches",milestoneComposition)
  , ("Parent milestone / strict framing and every callback fault",milestoneFraming)
  , ("Parent milestone / generated heights and truncated snapshots",milestoneTruncation)
  , ("Parent BMM / capability composition and lazy mismatches",bmmComposition)
  , ("Parent BMM / exact framing and publication-before-mismatch",bmmFraming)
  , ("Parent BMM / direct cache composition and callback failures",bmmCacheComposition)
  , ("Parent BMM / generated slots, hashes and duplicate scans",bmmGenerated)
  , ("Parent BMM / complete cache advancement and publication",cacheBmmProgress)
  , ("Parent launch / generated identities match retained scalar effects",launchDifferential)
  , ("Parent launch / strict framing, truncation, faults and lazy mismatch",launchFraming)
  , ("Deposit admission / generated identities match scalar decisions and effects",withMaxSuccess 10000 admissionGenerated)
  , ("Deposit admission / strict framing, truncation, faults and lazy mismatch",admissionFraming)
  , ("Confirmed deposit / indexed fold matches scalar policy and effects",withMaxSuccess 10000 confirmationDifferential)
  , ("Confirmed deposit / class fold, typed continuation, framing and lazy mismatch",confirmationFold)
  , ("Deposit candidates / generated eligibility, unfiltered cursor and ordered rejection",withMaxSuccess 10000 candidateDifferential)
  , ("Deposit candidates / class fold, continuation, lazy mismatch and every callback fault",candidateFoldAndFaults)
  , ("Parent startup / direct load and both rebuild paths, cleanup on every failure",startupCleanup)
  , ("Parent cache load / generated states match legacy policy and effects",loadedDifferential)
  , ("Parent cache load / strict framing, truncated metadata and every callback fault",loadedFraming)
  , ("Parent bootstrap / legacy effects, slot rejection, genesis and every callback fault",bootstrapDifferential)
  ]

