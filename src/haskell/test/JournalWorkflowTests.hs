{-# LANGUAGE FlexibleInstances, MultiParamTypeClasses, TypeFamilies #-}
module JournalWorkflowTests (properties) where

import qualified Bmm
import Control.Exception (SomeException, throwIO, try)
import Control.Monad (forM, unless, when)
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
import Test.QuickCheck hiding (output)
import qualified Withdrawal as H
import Workflow (NativeBytes)

money :: Int64
money = 2100000000000000
type Event = (Word32, B.ByteString)
data Fixture = Fixture B.ByteString B.ByteString B.ByteString [(Word32,Word64)] deriving Show
bundle :: B.ByteString
bundle = B.pack [2,0,0,0,0,1,0,9,8,7]
digest :: B.ByteString
digest = B.replicate 32 3
facts :: B.ByteString
facts = H.wordLE 4 1 <> B.singleton 2 <> H.wordLE 8 100000 <> H.wordLE 8 1000 <>
  H.wordLE 4 24 <> H.wordLE 8 1234 <> B.pack [0,7] <> B.take 7 bundle <> digest
base :: Fixture
base = Fixture facts bundle digest []
mutate :: Int -> B.ByteString -> B.ByteString -> B.ByteString
mutate offset bytes original = B.take offset original <> bytes <> B.drop (offset+B.length bytes) original
fact :: Int -> B.ByteString -> Fixture
fact offset bytes = Fixture (mutate offset bytes facts) bundle digest []

capture :: (NativeBytes -> IO Int32) -> Fixture -> Int -> Maybe (Word32,B.ByteString)
  -> IO (Either String Int32,[Event])
capture run (Fixture fields transaction hash replies) fault altered = do
  events <- newIORef []
  poisoned <- newIORef Nothing
  let native step index input = do
        readIORef poisoned >>= maybe (pure ()) throwIO
        prior <- readIORef events
        modifyIORef' events (++[(step,input)])
        result <- try $ do
          when (length prior==fault) (ioError (userError "journal callback fault"))
          unless (index==0 && (B.null input || step `elem` [0,103,105]))
            (ioError (userError "unexpected journal callback request"))
          when (step==0) (ioError (userError (C.unpack input)))
          when (step==103 && input/=B.take 4 transaction<>B.drop 6 transaction)
            (ioError (userError "unexpected normalized journal bundle"))
          let bytes = case step of
                101 -> fields
                102 -> transaction
                103 -> hash
                _ -> H.wordLE 8 (maybe 1 id (lookup step replies))
          pure $ case altered of Just (changed,replacement) | changed==step -> replacement; _ -> bytes
        case result of
          Left err -> writeIORef poisoned (Just (err :: SomeException)) >> throwIO err
          Right bytes -> pure bytes
  result <- try (run native) :: IO (Either SomeException Int32)
  trace <- readIORef events
  pure (either (Left . show) Right result,trace)

actual :: Bool -> NativeBytes -> IO Int32
actual reading native = execute (H.WithdrawalJournal money native)
  (if reading then H.ReadJournal else H.ValidateJournal)

-- Old procedural ordering, with the unchanged pure rules as the rule oracle.
reference :: Bool -> NativeBytes -> IO Int32
reference reading native = if not reading then fromIntegral . fromEnum <$> valid else do
  open <- yes 1
  if not open then effect 2 >> pure 0 else do
    effect 3
    magic <- yes 4
    if not magic then effect 5 >> pure 0 else do
      checksum <- yes 6
      if not checksum then effect 7 >> pure 0 else do
        accepted <- valid
        if not accepted then effect 9 >> pure 0 else effect 10 >> pure 1
  where
    yes step = (==1) . H.readLE <$> native step 0 B.empty
    effect step = native step 0 B.empty >> pure ()
    rule action = H.withdrawal (fromIntegral (fromEnum action)+1) money
    reject message = native 105 0 (C.pack message) >> pure False
    valid = do
      fields <- native 101 0 B.empty
      case rule H.JournalAdmission (B.take 42 fields) of
        Left message -> reject message
        Right _ -> do
          bytes <- native 102 0 B.empty
          let normalized = B.take 4 bytes <> B.drop 6 bytes
          hash <- native 103 0 normalized
          either reject (const (pure True)) (rule H.JournalIdentity (hash<>B.drop 42 fields))

scenarios :: [Fixture]
scenarios = [base] ++ [Fixture facts bundle digest [(step,0)] | step <- [1,4,6]] ++
  [fact offset bytes | (offset,bytes) <- [(0,H.wordLE 4 2),(4,B.singleton 5),
    (33,B.singleton 1),(5,H.wordLE 8 0),(5,H.wordLE 8 (fromIntegral money+1)),
    (13,H.wordLE 8 0),(13,H.wordLE 8 100000),(21,H.wordLE 4 256),
    (33,B.singleton 2),(33,B.singleton 4),(33,B.singleton 8),(33,B.singleton 16),
    (25,H.wordLE 8 0),(34,B.singleton 6),(39,B.pack [1,0]),(42,B.replicate 32 4)]]

differential :: Property
differential = once $ ioProperty $ do
  checks <- forM [(reading,s) | reading <- [False,True],s <- scenarios] $ \(reading,s) -> do
    expected@(_,trace) <- capture (reference reading) s (-1) Nothing
    observed <- capture (actual reading) s (-1) Nothing
    faults <- forM [0..length trace-1] $ \fault -> do
      old <- capture (reference reading) s fault Nothing
      new@(_,prefix) <- capture (actual reading) s fault Nothing
      pure (conjoin [old === new,prefix === take (fault+1) trace])
    pure (counterexample (show (reading,s)) (conjoin ((observed===expected):faults)))
  pure (conjoin checks)

generated :: Property
generated = forAll ((,,,) <$> arbitrary <*> chooseInt (0,73) <*> arbitrary <*> elements [1,4,6]) $
  \(reading,offset,byte,step) -> ioProperty $ do
    let s = Fixture (mutate offset (B.singleton byte) facts) bundle digest [(step,1)]
    old <- capture (reference reading) s (-1) Nothing
    new <- capture (actual reading) s (-1) Nothing
    pure (new===old)

frames :: Property
frames = once $ ioProperty $ do
  (_,trace) <- capture (actual True) base (-1) Nothing
  let malformed = [(101,B.empty),(101,B.take 73 facts),(101,facts<>B.singleton 0),
        (102,B.empty),(102,B.pack [2,0,0,0,1,0,0]),(103,B.empty),(103,B.replicate 33 0)] ++
        [(step,bytes) | step <- [1,3,4,6,10],bytes <- [B.empty,B.replicate 9 0,H.wordLE 8 4294967296]]
  checks <- forM malformed $ \change@(step,_) -> do
    (result,observed) <- capture (actual True) base (-1) (Just change)
    let prefix = takeWhile ((/=step).fst) trace
    pure (counterexample (show change) (conjoin [property (either (const True) (const False) result),
      take (length prefix+1) observed === take (length prefix+1) trace,
      property (all ((==0).fst) (drop (length prefix+1) observed))]))
  absent <- forM [31,32,33,34,40] $ \kind -> FFI.elements_hs_replay_store kind (fromIntegral money) nullFunPtr nullPtr
  rejections <- forM [B.empty,B.replicate 9 0,H.wordLE 8 0,H.wordLE 8 2] $ \bytes -> do
    (result,observed) <- capture (actual True) (fact 5 (H.wordLE 8 0)) (-1) (Just (105,bytes))
    pure (conjoin [property (either (const True) (const False) result),
      map fst observed === [1,3,4,6,101,105,0]])
  pure (conjoin (checks ++ rejections ++ [absent === replicate 5 (-1)]))

data Probe = Probe (IORef [Word32]) Bool
instance H.JournalValidation Probe where
  validateJournal (Probe events valid) = modifyIORef' events (++[8]) >> pure valid
instance H.JournalStorage Probe where
  observeJournal (Probe events _) step = modifyIORef' events (++[step]) >> pure 1

dispatch :: Property
dispatch = once $ ioProperty $ do
  checks <- forM [False,True] $ \valid -> do
    events <- newIORef []
    result <- H.readWithdrawalJournal (Probe events valid)
    trace <- readIORef events
    pure (conjoin [result === (if valid then 1 else 0),trace === [1,3,4,6,8,if valid then 10 else 9]])
  pure (conjoin (checks ++ [property (isNothing (interpret (SomeOperation (Check (Bmm.NextBlockHeight 0 0)))
    (undefined :: DSL H.WithdrawalJournal)))]))

persist :: Bool -> NativeBytes -> IO Int32
persist clearing native = execute (H.WithdrawalJournal money native)
  (if clearing then H.ClearJournal else H.WriteJournal)

-- The former native control order, including the lifetime/catch boundaries.
persistReference :: Bool -> NativeBytes -> IO Int32
persistReference clearing native = if clearing then do
  present <- yes 1
  if not present then pure 1 else do
    removed <- yes 2
    if removed then effect 4 >> pure 1 else effect 3 >> pure 0
  else do
    valid <- reference False native
    if valid == 0 then effect 209 >> pure 0 else do
      effect 201
      effect 202
      open <- yes 1
      stored <- if not open then effect 2 >> pure False else do
        effect 3
        flushed <- yes 4
        if not flushed then effect 5 >> pure False else do
          effect 6
          renamed <- yes 7
          if renamed then pure True else effect 8 >> pure False
      effect 203
      if not stored then pure 0 else effect 204 >> effect 205 >> pure 1
  where
    effect step = native step 0 B.empty >> pure ()
    yes step = (==1) . H.readLE <$> native step 0 B.empty

persistence :: Property
persistence = once $ ioProperty $ do
  checks <- forM [(clearing,s) | clearing <- [False,True],
    s <- [base,fact 5 (H.wordLE 8 0)] ++ [Fixture facts bundle digest [(step,0)] |
      step <- if clearing then [1,2] else [1,4,7]]] $
    \(clearing,s) -> do
      expected@(_,trace) <- capture (persistReference clearing) s (-1) Nothing
      observed <- capture (persist clearing) s (-1) Nothing
      faults <- forM [0..length trace-1] $ \fault -> do
        old <- capture (persistReference clearing) s fault Nothing
        new@(status,prefix) <- capture (persist clearing) s fault Nothing
        pure (conjoin [new===old,prefix===take (fault+1) trace,
          property (either (const True) (const False) status)])
      pure (conjoin ((observed===expected):faults))
  pure (conjoin checks)

persistenceFrames :: Property
persistenceFrames = once $ ioProperty $ do
  checks <- forM [False,True] $ \clearing -> do
    (_,trace) <- capture (persist clearing) base (-1) Nothing
    forM [(step,bytes) | (step,_) <- trace,step/=101,step/=102,step/=103,
      bytes <- [B.empty,B.replicate 9 0,H.wordLE 8 4294967296]] $ \change@(step,_) -> do
      (status,observed) <- capture (persist clearing) base (-1) (Just change)
      let prefix = takeWhile ((/=step).fst) trace
      pure (counterexample (show (clearing,change)) (conjoin [
        property (either (const True) (<0) status),
        take (length prefix+1) observed===take (length prefix+1) trace,
        property (all ((==0).fst) (drop (length prefix+1) observed))]))
  effects <- forM [201,202,203,204,205] $ \step -> do
    (status,trace) <- capture (persist False) base (-1) (Just (step,H.wordLE 8 0))
    pure (conjoin [property (either (const True) (<0) status),fst (last trace)===step])
  invalidTransitions <- forM [1,3,4,6,7] $ \step -> do
    (status,trace) <- capture (persist False) base (-1) (Just (step,H.wordLE 8 2))
    pure (conjoin [status===Right (-1),property (all ((/=203).fst) trace),fst (last trace)===step])
  (invalidClear,clearTrace) <- capture (persist True) base (-1) (Just (4,H.wordLE 8 0))
  pure (conjoin (concat checks++effects++invalidTransitions++[
    invalidClear===Right (-1),map fst clearTrace===[1,2,4]]))

persistenceReuse :: Property
persistenceReuse = once $ ioProperty $ do
  results <- forM [False,True] $ \valid -> do
    events <- newIORef []
    result <- H.writeWithdrawalJournal (Probe events valid)
    trace <- readIORef events
    pure (conjoin [result===(if valid then 1 else 0),
      trace===(if valid then [8,201,202,1,3,4,6,7,203,204,205] else [8,209])])
  events <- newIORef []
  cleared <- H.clearWithdrawalJournal (Probe events False)
  trace <- readIORef events
  pure (conjoin (results++[cleared===1,trace===[1,2,4]]))

properties :: [(String,Property)]
properties = [("Withdrawal journal / differential routes and callback faults",differential),
  ("Withdrawal journal / generated field mutations",generated),
  ("Withdrawal journal / strict frames and callback rejection",frames),
  ("Withdrawal journal / capability reuse and lazy payload mismatch",dispatch),
  ("Withdrawal journal persistence / procedural order and every callback fault",persistence),
  ("Withdrawal journal persistence / malformed replies and effects",persistenceFrames),
  ("Withdrawal journal persistence / capability composition",persistenceReuse)]
