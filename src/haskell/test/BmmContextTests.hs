{-# LANGUAGE FlexibleInstances, MultiParamTypeClasses, TypeFamilies #-}
module BmmContextTests (properties) where

import qualified Bmm
import Control.Exception (SomeException, finally, throwIO, try)
import Control.Monad (forM, forM_, unless, when)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Except (ExceptT(..), runExceptT, throwE)
import Control.Operation
import Control.Operation.Validation (Check(..))
import qualified Data.ByteString as B
import Data.Int (Int32)
import Data.IORef
import Data.List (findIndex)
import Data.Maybe (isNothing)
import Data.Word (Word32, Word64)
import qualified Drivechain as FFI
import Foreign.Ptr (nullFunPtr, nullPtr)
import qualified ParentCache as H
import Test.QuickCheck
import Withdrawal (wordLE)
import Workflow (NativeBytes)

type Event = (Word32,Word64)
data Entry = Entry { ident :: Int, epoch :: Word64, sameParent :: Bool, sameSlot :: Bool,
  canonical :: Bool, sameCritical :: Bool, timedOut :: Bool } deriving (Eq,Show)
data Scenario = Scenario { positive :: [Entry], negative :: [Entry],
  overrides :: [(Event,Word64)], untrusted :: [Bool] } deriving Show
data Cache = Cache { edges :: [Entry], rejects :: [Entry], selectedNegative :: Bool,
  writeIndex :: Int, selected :: Entry, published :: [Word32], revoked :: Bool,
  clearedReplay :: Bool, rebuild :: Bool, replayHeld :: Bool } deriving (Eq,Show)

entry :: Entry
entry = Entry 1 7 True True True True False
base :: Scenario
base = Scenario [] [] [] [False,False]
at :: Word32 -> Word64 -> Scenario -> Scenario
at step value s = s {overrides=((step,0),value):overrides s}

capture :: (NativeBytes -> IO Int32) -> Scenario -> Int -> Maybe (Event,B.ByteString)
  -> IO (Either String Int32,[Event],Cache)
capture run s fault altered = do
  cache <- newIORef (Cache (positive s) (negative s) False 0 entry [] False False False False)
  events <- newIORef []
  poisoned <- newIORef Nothing
  let native step index input = do
        readIORef poisoned >>= maybe (pure ()) throwIO
        seen <- readIORef events
        modifyIORef' events (++[(step,index)])
        result <- try $ do
          when (length seen == fault) (ioError (userError "BMM callback fault"))
          unless (B.null input) (ioError (userError "unexpected BMM input"))
          c <- readIORef cache
          let active = if selectedNegative c then rejects c else edges c
              forward = fromIntegral index
              reverseIndex = length (edges c)-1-forward
              replace i v xs = take i xs ++ [v] ++ drop (i+1) xs
              change f = modifyIORef' cache f >> pure 1
              setActive xs = change $ \a -> if selectedNegative a then a {rejects=xs} else a {edges=xs}
              bool b = if b then 1 else 0
              observe = pure $ case step of
                0 -> if elem index [14,18,19] then 2 else 3
                6 -> 7
                11 -> epoch (active !! forward)
                12 -> bool (timedOut (rejects c !! forward))
                16 -> fromIntegral (length (edges c))
                17 -> bool (sameParent (edges c !! reverseIndex))
                18 -> bool (sameSlot (edges c !! reverseIndex))
                20 -> bool (canonical (selected c))
                21 -> bool (sameCritical (selected c))
                23 -> 7
                24 -> epoch (selected c)
                27 -> bool (untrusted s !! min 1 (length (filter ((==27).fst) seen)))
                31 -> 7
                34 -> 0
                38 -> 101
                39 -> 101
                40 -> 100
                44 -> fromIntegral (length (rejects c))
                45 -> bool (sameParent (rejects c !! forward))
                46 -> bool (sameSlot (rejects c !! forward))
                48 -> 0
                52 -> fromIntegral (length (rejects c))
                54 -> 100
                55 -> 99
                58 -> 100
                62 -> 101
                73 -> 7
                75 -> fromIntegral (length (edges c))
                78 -> 0
                _ -> 1
          value <- case step of
            1 -> change (\a -> a {published=[]})
            7 -> change (\a -> a {edges=[]})
            8 -> change (\a -> a {rejects=[]})
            10 -> do
              modifyIORef' cache (\a -> a {selectedNegative=index==1})
              pure (fromIntegral (length (if index==1 then rejects c else edges c)))
            13 -> change (\a -> a {writeIndex=forward})
            14 -> do
              _ <- setActive (replace (writeIndex c) (active !! forward) active)
              change (\a -> a {writeIndex=writeIndex c+1})
            15 -> setActive (take (writeIndex c) active)
            19 -> change (\a -> a {selected=edges c !! reverseIndex})
            26 -> change (\a -> a {published=[26]})
            28 -> change (\a -> a {replayHeld=True})
            35 -> change (\a -> a {revoked=True})
            36 -> change (\a -> a {clearedReplay=True})
            37 -> change (\a -> a {rebuild=True})
            43 -> change (\a -> a {replayHeld=False})
            47 -> change (\a -> a {selected=rejects c !! forward})
            51 -> change (\a -> a {rejects=rejects a++[entry {ident=99}]})
            53 -> change (\a -> a {rejects=drop 1 (rejects a)})
            68 -> change (\a -> a {published=published a++[68]})
            70 -> change (\a -> a {published=published a++[70]})
            71 -> change (\a -> a {published=published a++[71]})
            72 -> change (\a -> a {published=published a++[72]})
            74 -> change (\a -> a {edges=edges a++[entry {ident=99}]})
            76 -> change (\a -> a {edges=drop 1 (edges a)})
            _ -> observe
          let bytes = wordLE 8 (maybe value id (lookup (step,index) (overrides s)))
          pure $ case altered of Just (event,replacement) | event==(step,index) -> replacement; _ -> bytes
        case result of
          Left err -> writeIORef poisoned (Just (err :: SomeException)) >> throwIO err
          Right bytes -> pure bytes
  result <- try (run native) :: IO (Either SomeException Int32)
  -- The surrounding native ownership scope releases both locks on all exits.
  modifyIORef' cache (\c -> c {replayHeld=False})
  trace <- readIORef events
  final <- readIORef cache
  pure (either (Left . show) Right result,trace,final)

actual :: NativeBytes -> IO Int32
actual native = execute (H.BmmContext native) H.AuthenticateBmmContext

-- Procedural specification transcribed from the sealed pre-migration C++.
-- It shares native observations, not production capabilities or routing helpers.
reference :: NativeBytes -> IO Int32
reference native = either id (const 0) <$> runExceptT body
  where
    readValue step index = liftIO $ do
      bytes <- native step index B.empty
      unless (B.length bytes==8) (ioError (userError "reference malformed scalar"))
      pure (sum [fromIntegral byte * 256^i | (i,byte) <- zip [0::Int ..] (B.unpack bytes)] :: Word64)
    val step = readValue step 0
    effect step index = readValue step index >>= \v -> unless (v==1) (throwE (-1))
    act step = effect step 0
    flag step index = readValue step index >>= \v -> case v of
      0 -> pure False
      1 -> pure True
      _ -> throwE (-1)
    yes step = flag step 0
    failAt code = readValue 0 code >>= \v -> throwE (fromIntegral v)
    require code good = unless good (failAt code)
    available step = yes step >>= \good -> unless good (throwE 3)
    prune current kind = do
      count <- readValue 10 kind
      let indices = take (fromIntegral count) [0..]
      -- Record first-hole movement separately from the predicate stream.
      hole <- liftIO (newIORef Nothing)
      forM_ indices $ \i -> do
        expired <- if kind==1 then flag 12 i else pure False
        oldEpoch <- readValue 11 i
        firstHole <- liftIO (readIORef hole)
        case firstHole of
          Nothing | expired || oldEpoch/=current -> effect 13 i >> liftIO (writeIORef hole (Just i))
          Just _ | not expired && oldEpoch==current -> effect 14 i
          _ -> pure ()
      firstHole <- liftIO (readIORef hole)
      when (isNothing firstHole) (effect 13 count)
      act 15
    search size parent slot = do
      count <- val size
      found <- liftIO (newIORef Nothing)
      forM_ (take (fromIntegral count) [0..]) $ \i -> do
        prior <- liftIO (readIORef found)
        when (isNothing prior) $ do
          p <- flag parent i
          when p $ flag slot i >>= \s -> when s (liftIO (writeIORef found (Just i)))
      liftIO (readIORef found)
    reject = do
      effect 51 5
      count <- val 52
      when (count>64) (act 53)
    indexed current = do
      act 28
      ExceptT (finally (runExceptT admission) (native 43 0 B.empty >> pure ()))
      where
        revoke = mapM_ act [35,36,37]
        admission = do
          yes 29 >>= require 6
          forM_ [1..14] $ \i -> flag 30 i >>= require 7
          val 31 >>= require 7 . (==current)
          yes 32 >>= require 8
          act 33
          corrupt <- yes 34
          when corrupt (revoke >> throwE 3)
          absent <- yes 78
          when absent (failAt 9)
          successor <- val 38
          tip <- val 39
          sane <- if successor<=0xffffffff && tip<=0xffffffff && successor<=tip
            then (<successor) <$> val 40 else pure False
          unless sane (revoke >> failAt 10)
          yes 41 >>= require 11
          yes 42 >>= require 11
    body = do
      act 1
      act 2
      bounded <- yes 3
      if bounded then yes 4 >>= require 1 else act 5
      current <- val 6
      when (current==0) (act 7 >> act 8 >> failAt 2)
      act 9
      prune current 0
      prune current 1
      cached <- search 16 17 18
      case cached of
        Just i -> do
          effect 19 i
          yes 20 >>= require 3
          yes 21 >>= require 4
          available 22
          checked <- val 23
          require 5 (checked>0)
          val 24 >>= require 5 . (==checked)
          act 25
          act 26
        Nothing -> do
          peer <- yes 27
          when peer (indexed current)
          peerAgain <- yes 27
          unless peerAgain $ do
            rejected <- search 44 45 46
            case rejected of Nothing -> pure (); Just i -> effect 47 i >> failAt 12
          status <- val 48
          when (status>2) (throwE (-1))
          when (status==1) (available 49)
          when (status==2) (throwE 3)
          when (status==1) (act 50 >> reject >> throwE 2)
          height <- val 54
          checkpoint <- val 55
          when (height<checkpoint) (act 56 >> reject >> failAt 14)
          available 57
          parent <- val 58
          require 15 (parent<0xffffffff)
          flag 59 (parent+1) >>= \good -> unless good (throwE 3)
          available 60
          available 61
          val 62 >>= require 16 . (==parent+1)
          yes 63 >>= require 16
          act 64
          available 65
          act 66
          available 67
          act 68
          committed <- yes 69
          act (if committed then 70 else 71)
          act 72
          final <- val 73
          require 17 (final>0 && final==current)
          act 74
          count <- val 75
          when (count>8) (act 76)
          require 18 committed
          yes 77 >>= require 19

routes :: [Scenario]
routes = [base,base {untrusted=[True,True]},base {untrusted=[True,False]},
  base {untrusted=[False,True]},base {positive=[entry]},
  base {positive=[entry {canonical=False},entry {ident=2}]},
  base {negative=[entry,entry {ident=2}]},
  base {positive=replicate 8 (entry {sameParent=False})},
  at 48 1 base {negative=replicate 64 (entry {sameParent=False})},
  base {positive=[entry {epoch=0},entry {sameParent=False},entry {epoch=8},entry],
    negative=[entry {epoch=0},entry {timedOut=True},entry {sameSlot=False}]}] ++
  [at step value s | (step,values,s) <-
    [(3,[0],base),(4,[0],base),(6,[0,1,maxBound],base),(20,[0],base {positive=[entry]}),
     (21,[0],base {positive=[entry]}),(22,[0],base {positive=[entry]}),
     (23,[0,8,maxBound],base {positive=[entry]}),
     (29,[0],peer),(31,[0,8],peer),(32,[0],peer),(34,[1],peer),(78,[1],peer),
     (38,[0,100,102,0x100000000],peer),(39,[0,100,0x100000000],peer),
     (40,[101,maxBound],peer),(41,[0],peer),(42,[0],peer),
     (48,[1,2,3,maxBound],base),(49,[0],at 48 1 base),
     (54,[0,98],base),(57,[0],base),(58,[0,0xfffffffe,0xffffffff,0x100000000,maxBound],base),
     (60,[0],base),(61,[0],base),(62,[0,100,102,maxBound],base),(63,[0],base),
     (65,[0],base),(67,[0],base),(69,[0],base),(73,[0,8,maxBound],base),(77,[0],base)],
    value <- values] ++
  [peer {overrides=[((30,i),0)]} | i <- [1..14]] ++ [base {overrides=[((59,101),0)]}]
  where peer=base {untrusted=[True,True]}

workflow :: Property
workflow = once $ ioProperty $ do
  comparisons <- forM routes $ \s -> do
    expected@(_,trace,_) <- capture reference s (-1) Nothing
    result <- capture actual s (-1) Nothing
    failures <- forM [0..length trace-1] $ \fault -> do
      wanted <- capture reference s fault Nothing
      observed <- capture actual s fault Nothing
      pure (counterexample ("fault "++show fault++" "++show s) (observed===wanted))
    pure (conjoin (counterexample (show s) (result===expected):failures))
  pure (conjoin comparisons)

cacheLists :: Property
cacheLists = forAll (chooseInt (0,16) >>= \n -> vectorOf n ((,,,) <$> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary)) $ \flags ->
  ioProperty $ do
    let records = [entry {ident=i,epoch=if e then 7 else 8,sameParent=p,sameSlot=s,timedOut=t}
                  | (i,(e,p,s,t)) <- zip [0..] flags]
        scenario = base {positive=records,negative=reverse records}
    expected <- capture reference scenario (-1) Nothing
    observed <- capture actual scenario (-1) Nothing
    pure (observed===expected)

frames :: Property
frames = once $ ioProperty $ do
  cases <- forM [base,base {positive=[entry]},base {untrusted=[True,True]}] $ \s -> do
    (_,trace,_) <- capture actual s (-1) Nothing
    forM [(event,bad) | event <- trace,bad <- [B.empty,B.singleton 1,B.replicate 9 0]] $ \change@(event,_) -> do
      (status,seen,_) <- capture actual s (-1) (Just change)
      let reached = maybe [] (\i -> take (i+1) trace) (findIndex (==event) trace)
      pure (counterexample (show (event,status)) (conjoin
        [property (either (const True) (/=0) status),take (length reached) seen===reached]))
  badFlags <- forM [3,4,20,21,22,27,29,30,32,34,41,42,49,57,59,60,61,63,65,67,69,77,78] $ \step -> do
    let s | elem step [20,21,22] = base {positive=[entry]}
          | step==49 = at 48 1 base
          | otherwise = base {untrusted=[True,True]}
        index | step==30 = 1 | step==59 = 101 | otherwise = 0
    (result,trace,_) <- capture actual s (-1) (Just ((step,index),wordLE 8 2))
    pure (counterexample (show step) (conjoin [result===Right (-1),property (elem (step,index) trace)]))
  nullStatus <- FFI.elements_hs_replay_store 29 0 nullFunPtr nullPtr
  pure (conjoin (concat cases++badFlags++[nullStatus=== -1]))

data Probe = Probe (IORef [String]) Bool Bool
instance H.BmmCacheAdmission Probe where
  prepareBmmCache (Probe events allowed _) = do
    liftIO (modifyIORef' events (++["admit"]))
    unless allowed (throwE 3)
    pure 7
instance H.BmmCacheRouting Probe where
  routeBmmCache (Probe events _ cached) value =
    liftIO (modifyIORef' events (++["route "++show value])) >> pure cached
instance H.BmmEdgeAuthentication Probe where
  authenticateBmmEdge (Probe events _ _) value =
    liftIO (modifyIORef' events (++["authenticate "++show value]))
instance H.BmmContextPublication Probe where
  publishBmmContext (Probe events _ _) value =
    liftIO (modifyIORef' events (++["publish "++show value]))

dispatch :: Property
dispatch = once $ ioProperty $ do
  checks <- forM [(False,False),(True,False),(True,True)] $ \(allowed,cached) -> do
    events <- newIORef []
    result <- runExceptT (H.authenticateBmmContext (Probe events allowed cached))
    trace <- readIORef events
    pure (conjoin [result === (if allowed then Right () else Left 3),
      trace === ["admit"]++(if allowed then ["route 7"]++(if cached then [] else ["authenticate 7","publish 7"]) else [])])
  pure (conjoin (property (isNothing (interpret (SomeOperation (Check (Bmm.NextBlockHeight 0 0)))
    (undefined :: DSL H.BmmContext))):checks))

properties :: [(String,Property)]
properties =
  [("BMM context / whole routes, cache mutations and every callback fault",workflow),
   ("BMM context / generated positive and negative cache ordering",cacheLists),
   ("BMM context / strict scalar frames and booleans",frames),
   ("BMM context / capability reuse and lazy payload mismatch",dispatch)]
