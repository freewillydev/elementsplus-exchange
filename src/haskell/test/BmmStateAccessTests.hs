{-# LANGUAGE FlexibleInstances, MultiParamTypeClasses, TypeApplications, TypeFamilies #-}
module BmmStateAccessTests (properties) where

import qualified Bmm as H
import Control.Exception (SomeException, try, throwIO)
import Control.Monad (forM, forM_, unless, when)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Except (runExceptT, throwE)
import Control.Operation
import Control.Operation.Validation (Check(..), validate)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.Int (Int32)
import Data.IORef
import Data.Maybe (isNothing, fromMaybe)
import Data.Word (Word32, Word64)
import qualified Drivechain as FFI
import Foreign.Ptr (nullFunPtr, nullPtr)
import Test.QuickCheck hiding (output)
import Withdrawal (readLE, wordLE)
import Workflow (NativeBytes)

type Fixture = [(Word32,[Word64])]
type Event = (Word32,Word64,B.ByteString)
base :: Fixture
base = [(s,[1]) | s <- [1..6]] ++ [(10,[1,0]),(11,[1,117]),(12,[3,0]),
  (20,[]),(21,[]),(22,[3]),(23,[1,100,11,1,0,1,11,11]),(24,[0]),
  (25,[1..11]),(30,[0]),(31,[0]),(32,[0])]
replace :: Word32 -> [Word64] -> Fixture -> Fixture
replace step value fixture = (step,value):filter ((/=step).fst) fixture

actual :: Int -> NativeBytes -> IO Int32
actual mode native = execute (H.StoredBmmState native) $ case mode of
  0 -> H.ReadParentState
  1 -> H.EffectiveParentState
  _ -> H.PrepareParentContext

-- The old native branch order and catch region, using unchanged pure rules.
reference :: Int -> NativeBytes -> IO Int32
reference mode native = do
  result <- case mode of
    0 -> load
    1 -> do
      network <- yes 30
      if network then pure (Left "native Elements requires its authenticated parent replay, not signet BMM state") else do
        found <- load
        case found of
          Right False -> do
            public <- yes 31
            if public then checkpoint 0 >> pure (Right True) else do
              private <- yes 32
              if private then checkpoint 1 >> pure (Right True)
                else pure (Left "authenticated BMM parent-chain state is missing")
          _ -> pure found
    _ -> do
      valid <- validState
      if not valid then pure (Left "BMM parent-chain state is malformed") else do
        times <- wordsAt 25
        let median = validate (H.ParentMedian (map fromIntegral times))
        if median < 0 then pure (Left "authenticated BMM parent median time past is zero")
          else native 26 0 (wordLE 8 (fromIntegral median)) >> pure (Right True)
  either (\message -> native 90 0 (C.pack message) >> pure 0) (pure . fromIntegral . fromEnum) result
  where
    checkpoint profile = do
      let (fields,hash) = validate (H.CheckpointPreset profile)
      native 33 (fromIntegral profile) (B.pack hash <> B.concat (map (wordLE 4 . fromIntegral) fields))
    wordsAt step = do
      reply <- native step 0 B.empty
      let owned = step >= 20 && step <= 25
          bytes = if owned then B.drop 1 reply else reply
      when (owned && B.take 1 reply /= B.singleton 1) (ioError (userError "native payload decoding failed"))
      pure [readLE (B.take 8 (B.drop i bytes)) | i <- [0,8..B.length bytes-1]]
    yes step = (==[1]) <$> wordsAt step
    validState = do
      private <- yes 24
      fields <- wordsAt 23
      let (preset,_,_) = validate (H.ConsensusPreset (if private then 1 else 0))
          interval = validate (H.DifficultyInterval (fromIntegral (head preset)) (fromIntegral (preset!!1)))
      case fields of
        [hash,height,time,bits,start,startTime,count,latest] -> pure $
          validate (H.ParentState (fromIntegral hash) interval (fromIntegral height) (fromIntegral time)
            (fromIntegral bits) (fromIntegral start) (fromIntegral startTime) count (fromIntegral latest))==0
        _ -> error "invalid reference state fixture"
    load = do
      present <- yes 1
      if not present then pure (Right False) else runExceptT $ do
        forM_ [2..6] $ \step -> lift (yes step) >>= \ok ->
          unless ok (throwE "persisted BMM state has invalid asset or value encoding")
        forM_ [(10,6),(11,7),(12,8)] $ \(step,phase) -> do
          values <- lift (wordsAt step)
          let code = case values of
                [facts,opcode] -> validate (H.Codec phase (fromIntegral facts) opcode 0)
                _ -> error "invalid reference script fixture"
          unless (code==0)
            (throwE "persisted BMM state script is malformed")
        body <- lift $ try @SomeException $ runExceptT $ do
          _ <- lift (wordsAt 20 >> wordsAt 21)
          payload <- lift (wordsAt 22)
          unless (payload==[3]) (throwE "persisted BMM state payload is invalid")
          valid <- lift validState
          unless valid (throwE "BMM parent-chain state is malformed")
          pure True
        either (const (throwE "persisted BMM state payload cannot be decoded")) (either throwE pure) body

capture :: (Int -> NativeBytes -> IO Int32) -> Int -> Fixture -> Int -> Maybe (Word32,B.ByteString)
  -> IO (Either String Int32,[Event],String,[Event])
capture run mode fixture fault altered = do
  events <- newIORef []
  effects <- newIORef []
  diagnostic <- newIORef "sentinel"
  poisoned <- newIORef Nothing
  let native step index input = do
        readIORef poisoned >>= maybe (pure ()) throwIO
        prior <- readIORef events
        let event = (step,index,input)
        modifyIORef' events (++[event])
        let owned = step >= 20 && step <= 25
        result <- try $ do
          when (length prior==fault) (ioError (userError "state callback fault"))
          unless ((index==0 || (step==33 && index==1)) && (B.null input || step `elem` [26,33,90]))
            (ioError (userError "invalid state callback request"))
          when (step==90) (writeIORef diagnostic (C.unpack input))
          when (step `elem` [26,33]) (modifyIORef' effects (++[event]))
          let bytes = (if owned then B.singleton 1 else B.empty) <>
                B.concat (map (wordLE 8) (fromMaybe [1] (lookup step fixture)))
          pure $ case altered of Just (target,change) | step==target -> change; _ -> bytes
        case result of
          Left err | owned && mode/=2 -> pure (B.singleton 0)
                   | otherwise -> writeIORef poisoned (Just (err :: SomeException)) >> throwIO err
          Right bytes -> pure bytes
  result <- try (run mode native) :: IO (Either SomeException Int32)
  trace <- readIORef events
  errorText <- readIORef diagnostic
  published <- readIORef effects
  pure (either (Left . show) Right result,trace,errorText,published)

compareFixture :: Int -> Fixture -> IO Property
compareFixture mode fixture = do
  expected@(_,trace,_,_) <- capture reference mode fixture (-1) Nothing
  observed <- capture actual mode fixture (-1) Nothing
  faults <- forM [0..length trace-1] $ \fault -> do
    old <- capture reference mode fixture fault Nothing
    new <- capture actual mode fixture fault Nothing
    pure (counterexample (show fault) (new===old))
  pure (counterexample (show (mode,fixture)) (conjoin ((observed===expected):faults)))

routes :: Property
routes = once $ ioProperty $ do
  let fieldScenarios = [replace 23 (take index fields++[value]++drop (index+1) fields) base |
        let fields = fromMaybe [] (lookup 23 base),
        (index,value) <- [(0,0),(1,0),(2,0),(3,0),(4,101),(4,1),(5,0),(6,10),(6,12),(7,10)]]
      scenarios = [base,replace 25 (replicate 10 0++[11]) base,replace 24 [1] base] ++ fieldScenarios ++
        [replace step [0] base | step <- [1..6]] ++
        [replace step values base | (step,values) <- [(10,[0,0]),(10,[1,79]),(11,[1,116]),
          (11,[0,0]),(12,[1,0]),(12,[3,1]),(22,[0]),(22,[1]),(22,[2])]] ++
        [replace 1 [0] (replace 30 [network] (replace 31 [public] (replace 32 [private] base))) |
          network <- [0,1],public <- [0,1],private <- [0,1]]
  conjoin <$> mapM (uncurry compareFixture) [(mode,fixture) | mode <- [0..2],fixture <- scenarios]

generated :: Property
generated = forAll ((,,,) <$> chooseInt (0,2) <*> chooseInt (0,7) <*> (arbitrary :: Gen Word32) <*> arbitrary) $
  \(mode,index,value,private) -> ioProperty $ do
    let fields = fromMaybe [] (lookup 23 base)
        bounded = if index==0 then fromIntegral (value `mod` 2) else fromIntegral value
    compareFixture mode (replace 24 [if private then 1 else 0]
      (replace 23 (take index fields++[bounded]++drop (index+1) fields) base))

frames :: Property
frames = once $ ioProperty $ do
  let malformed step = [B.empty,B.replicate 7 0,B.replicate 100 0] ++ map encode invalidWords
        where
          encode words' = (if step >= 20 && step <= 25 then B.singleton 1 else B.empty) <>
            B.concat (map (wordLE 8) words')
          invalidWords
            | step `elem` [1,2,3,4,5,6,24,30,31,32] = [[2]]
            | step `elem` [10,11,12] = [[4,0],[1,256]]
            | step == 23 = [[2,100,11,1,0,1,11,11],[1,0x100000000,11,1,0,1,11,11]]
            | step == 25 = [replicate 11 0x100000000]
            | otherwise = []
  checks <- forM [0..2] $ \mode -> do
    (_,trace,_,_) <- capture actual mode base (-1) Nothing
    forM [(step,bytes) | (step,_,_) <- trace, step `notElem` [26,90],
      bytes <- malformed step] $ \change -> do
        (result,_,_,published) <- capture actual mode base (-1) (Just change)
        pure (conjoin [property (either (const True) (==0) result),published===[]])
  absent <- mapM (\mode -> FFI.elements_hs_replay_store mode 0 nullFunPtr nullPtr) [37,38,39,40]
  pure (conjoin (concat checks++[absent===replicate 4 (-1)]))

data Probe = Probe (Either String Bool) [Bool] (IORef [Word32])
instance H.StateLoading Probe where
  loadParentState (Probe value _ events) = modifyIORef' events (++[1]) >> pure value
instance H.CheckpointSelection Probe where
  checkpointFact (Probe _ flags events) step = modifyIORef' events (++[step]) >> pure (flags!!fromIntegral (step-30))
  publishCheckpoint (Probe _ _ events) private = modifyIORef' events (++[if private then 35 else 34])
reuse :: Property
reuse = once $ ioProperty $ do
  checks <- forM [(Right True,[False,False,False],Right True,[30,1]),
    (Left "bad",[False,True,True],Left "bad",[30,1]),
    (Right False,[False,True,True],Right True,[30,1,31,34]),
    (Right False,[False,False,True],Right True,[30,1,31,32,35])] $ \(value,flags,expected,trace) -> do
      events <- newIORef []
      result <- H.effectiveParentState (Probe value flags events)
      observed <- readIORef events
      pure (conjoin [result===expected,observed===trace])
  pure (conjoin (checks++[property (isNothing (interpret (SomeOperation (Check (H.NextBlockHeight 0 0)))
    (undefined :: DSL H.StoredBmmState)))]))

properties :: [(String,Property)]
properties = [("BMM stored state / procedural routes and exception boundaries",routes),
  ("BMM stored state / generated field mutations",generated),
  ("BMM stored state / malformed replies and ABI rejection",frames),
  ("BMM stored state / capability reuse and lazy mismatch",reuse)]
