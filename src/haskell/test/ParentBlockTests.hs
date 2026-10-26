{-# LANGUAGE TypeFamilies #-}
module ParentBlockTests (preludeMessages, preludeFaults, preludeAdmission, preludeM8, preludeLazy, preludeMalformed,
  blockStages, blockLazy, blockWhole, blockFaults, blockMalformed, blockRejections, blockTreasury) where

import Control.Exception (SomeException, try)
import Control.Operation
import Control.Operation.Validation
import Control.Monad (when)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Except (runExceptT, throwE)
import Data.Bits (testBit)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.Int (Int32, Int64)
import Data.IORef (IORef, newIORef, readIORef, modifyIORef', writeIORef)
import Data.List (group)
import Data.Maybe (listToMaybe)
import Data.Word (Word8, Word32, Word64)
import qualified ParentBlock as P
import qualified ParentReplay as R
import Test.QuickCheck
import Withdrawal (wordLE)

data Row = Row Word8 Word8 Word8 deriving Show

body :: Word8 -> B.ByteString
body seed = B.pack (take 32 [seed..]) <> B.replicate (max 0 (32-length (take 32 [seed..]))) seed

payload :: Row -> B.ByteString
payload (Row kind slot seed) = case kind of
  0 -> B.empty
  1 -> B.pack [0xd5,0xe0,0xc4,0xaf,slot] <> body seed
  2 -> B.pack [0xd6,0xe1,0xc5,0xdf,slot] <> body seed
  3 -> B.pack [0xd4,0x5a,0xa9,0x43,slot] <> body seed
  4 -> B.pack [0xd7,0x7d,0x17,0x76,1,seed,254,255]
  _ -> B.pack [0xd1,0x61,0x73,0x68,slot] <> body seed

frame :: Row -> B.ByteString
frame (Row kind slot seed) = B.pack [kind,if kind == 4 then 0 else slot,if kind == 4 then 2 else 0] <>
  (if kind == 4 then B.replicate 32 0 else if kind == 1 || kind == 5 then B.reverse (body seed) else body seed) <>
  (if kind == 4 then B.concat (map (wordLE 2) [vote seed,65534,65535]) else B.empty)
  where vote 255 = 65535; vote 254 = 65534; vote n = fromIntegral n

duplicateErrors :: [String]
duplicateErrors = ["parent block contains a duplicate M1 proposal message",
  "parent block contains multiple M2 ACK messages for one slot",
  "parent block contains multiple M4 withdrawal ACK messages",
  "parent block contains multiple M7 commitments for one slot"]

-- Independent ordered-list oracle, without production parsers or flow tables.
collectReference :: [Row] -> ([B.ByteString],Maybe String,[(Word8,B.ByteString)])
collectReference = go [] [] [] False []
  where
    go published _ _ _ accepted [] = (published,Nothing,accepted)
    go published proposals acks m4 accepted (row@(Row kind slot seed):rest)
      | kind == 0 = go published proposals acks m4 accepted rest
      | kind == 1 && (slot,seed) `elem` proposals = rejected 0
      | kind == 2 && slot `elem` acks = rejected 1
      | kind == 4 && m4 = rejected 2
      | kind == 5 && slot `elem` map fst accepted = rejected 3
      | otherwise = go (published++[frame row])
          (if kind == 1 then (slot,seed):proposals else proposals)
          (if kind == 2 then slot:acks else acks) (m4 || kind == 4)
          (if kind == 5 then (slot,B.reverse (body seed)):accepted else accepted) rest
      where rejected code = (published,Just (duplicateErrors !! code),accepted)

parameters :: Word64 -> Int64 -> Int64 -> B.ByteString
parameters flags slot value = B.concat (map (wordLE 8) [fromIntegral slot,flags,fromIntegral value,1000]) <>
  B.concat (replicate 3 (wordLE 2 10 <> wordLE 2 5))

parent :: B.ByteString
parent = B.replicate 32 91

m8 :: Word8 -> Word8 -> Bool -> B.ByteString
m8 slot seed fresh = B.pack [106,68,0,191,0,slot] <> body seed <> (if fresh then parent else B.replicate 32 90)

type Trace = [(Word64,Word64,B.ByteString)]
runFixture :: B.ByteString -> Word64 -> B.ByteString -> B.ByteString -> [Row] -> [B.ByteString] -> Int
  -> IO (Int32,[B.ByteString],[String],Trace)
runFixture config coinbase slots prior rows requests fault = do
  seen <- newIORef []
  crossings <- newIORef 0
  published <- newIORef []
  diagnostics <- newIORef []
  selected <- newIORef 0
  let native step index input = do
        previous <- readIORef crossings
        modifyIORef' crossings (+1)
        modifyIORef' seen ((fromIntegral step,index,input):)
        when (previous == fault) (ioError (userError "injected prelude callback failure"))
        case step of
          0 -> pure config
          1 -> pure (wordLE 8 coinbase)
          2 -> pure slots
          3 -> pure prior
          10 -> pure (wordLE 8 (fromIntegral (length rows)))
          11 -> writeIORef selected (fromIntegral index) >> pure B.empty
          12 -> pure (wordLE 8 1)
          13 -> payload . (rows !!) <$> readIORef selected
          14 -> pure (B.reverse input)
          15 -> modifyIORef' published (++ [input]) >> pure B.empty
          20 -> pure (wordLE 8 (fromIntegral (length requests)+1))
          21 -> pure (requests !! (fromIntegral index-1))
          22 -> pure parent
          30 -> pure (wordLE 8 0)
          200 -> modifyIORef' diagnostics (++ [C.unpack input]) >> pure B.empty
          _ -> ioError (userError "unexpected prelude callback")
  result <- try (execute (P.Prelude native) P.CheckPrelude) :: IO (Either SomeException Int32)
  (,,,) (either (const (-1)) id result) <$> readIORef published <*> readIORef diagnostics <*> (reverse <$> readIORef seen)

fixtures :: Gen ([Row],[B.ByteString])
fixtures = do
  pool <- vectorOf 4 (Row <$> choose (0,5) <*> elements [0,24,42,255] <*> arbitrary)
  rows <- resize 12 (listOf (elements pool))
  padding <- elements [0,1,256,257]
  requests <- resize 5 (listOf (oneof [pure B.empty,m8 <$> elements [0,24,42,255] <*> arbitrary <*> arbitrary]))
  -- Also exercise M8 success with a matching display-order M7.
  paired <- arbitrary
  let final = rows ++ replicate padding (Row 0 0 0)
  pure (if paired then (Row 5 24 13:final,m8 24 13 True:requests) else (final,requests))

preludeMessages :: Property
preludeMessages = withMaxSuccess 300 $ forAll fixtures $ \(rows,requests) -> ioProperty $ do
  let (expected,errorMessage,accepted) = collectReference rows
      check script
        | B.null script = Nothing
        | lookup (B.index script 5) accepted /= Just (B.reverse (B.take 32 (B.drop 6 script))) =
            Just ("BIP301 M8 for slot " ++ show (B.index script 5) ++ " was not accepted by this block's M7")
        | B.drop 38 script /= parent = Just ("BIP301 M8 for slot " ++ show (B.index script 5) ++ " references an expired parent block")
        | otherwise = Nothing
      finalError = case errorMessage of Just message -> Just message; Nothing -> listToMaybe [e | Just e <- map check requests]
  (status,published,errors,trace) <- runFixture (parameters 19 24 0) 6 B.empty B.empty rows requests (-1)
  pure $ conjoin [published === expected,errors === maybe [] (:[]) finalError,
    status === maybe 0 (const 1) finalError,
    property (errorMessage == Nothing || null [() | (step,_,_) <- trace,step == 20 || step == 21])]

preludeFaults :: Property
preludeFaults = withMaxSuccess 300 $ forAll fixtures $ \(rows,requests) -> forAll (choose (0,90 :: Int)) $ \fault -> ioProperty $ do
  baseline@(_,_,_,trace) <- runFixture (parameters 19 24 0) 6 B.empty B.empty rows requests (-1)
  actual@(status,_,_,observed) <- runFixture (parameters 19 24 0) 6 B.empty B.empty rows requests fault
  pure $ if fault >= length trace then actual === baseline
    else conjoin [status === -1,observed === take (fault+1) trace]

preludeAdmission :: Property
preludeAdmission = forAll gen $ \(flags,slot,value,coinbase,other,prior) -> ioProperty $ do
  let bit = testBit flags
      validBalance present amount = if present then amount >= 0 && amount <= 1000 else amount == 0
      expected
        | not (bit 0) = Just "unsupported parent-state replay rules"
        | slot < 0 || slot > 255 || not (bit 1) = Just "invalid slot or proposal identity for parent-state replay"
        | (bit 2 && bit 3) || (bit 4 && bit 5) = Just "parent-state replay began with an inconsistent active proposal"
        | testBit coinbase 0 || not (testBit coinbase 1 && testBit coinbase 2) = Just "parent-state replay block has no coinbase transaction"
        | not (validBalance (bit 5) value) = Just "parent-state replay began with malformed CTIP state"
        | not (B.null other) = Just "parent-state replay began with malformed global slot state"
        | not (B.null prior) = Just "parent-state replay has malformed prior M4 action for slot 42"
        | otherwise = Nothing
  (status,published,errors,_) <- runFixture (parameters flags slot value) coinbase other prior [] [] (-1)
  pure $ conjoin [status === maybe 0 (const 1) expected,errors === maybe [] (:[]) expected,published === []]
  where gen = (,,,,,) <$> frequency [(2,choose (0,63)),(3,pure 19),(2,pure 43)] <*>
          elements [-1,0,24,255,256] <*> elements [-1,0,1,1000,1001] <*>
          frequency [(3,pure 6),(1,choose (0,7))] <*>
          elements [B.empty,B.pack [42,3] <> wordLE 8 0] <*> elements [B.empty,B.pack [42,0]]

preludeM8 :: Property
preludeM8 = forAll ((,,,) <$> arbitrary <*> arbitrary <*> arbitrary <*> choose (0,72 :: Int)) $ \(slot,seed,fresh,width) ->
  let script = m8 slot seed fresh
      expected = Just (slot,B.reverse (body seed),if fresh then parent else B.replicate 32 90)
      altered = B.take width (script <> B.pack [0,0])
      nonminimal = B.pack [106,76,68] <> B.drop 2 script
  in conjoin [P.parseM8 script === expected,P.parseM8 nonminimal === Nothing,
       P.parseM8 altered === if width == 70 then expected else Nothing]

preludeLazy :: Property
preludeLazy = conjoin
  [ (() <$ interpret (SomeOperation (undefined :: Check R.Distance)) (undefined :: DSL P.Prelude)) === Nothing
  , (() <$ interpret (SomeOperation (undefined :: P.Prelude)) P.CheckPrelude) === Just ()
  ]

preludeMalformed :: Property
preludeMalformed = once $ ioProperty $ do
  let config = parameters 19 24 0
      fixtures' = [(B.take width (config <> B.singleton 0),6,B.empty,B.empty) | width <- [0..43]++[45]] ++
        [(parameters 64 24 0,6,B.empty,B.empty),(config,8,B.empty,B.empty),
         (config,6,B.singleton 0,B.empty),(config,6,B.replicate 2561 0,B.empty),
         (config,6,B.pack [42,4] <> wordLE 8 0,B.empty),
         (config,6,B.empty,B.singleton 0),(config,6,B.empty,B.replicate 513 0),
         (config,6,B.empty,B.pack [42,8])]
  results <- mapM (\(params,coinbase,slots,prior) -> runFixture params coinbase slots prior [] [] (-1)) fixtures'
  badHash <- try (P.parseMessage (\step _ _ -> pure $ case step of
    11 -> B.empty
    12 -> wordLE 8 1
    13 -> payload (Row 1 24 7)
    14 -> B.replicate 31 0
    _ -> error "unexpected hash probe action") 0) :: IO (Either SomeException B.ByteString)
  pure $ conjoin (property (either (const True) (const False) badHash) :
    [conjoin [status === -1,published === [],errors === []] | (status,published,errors,_) <- results])

data StageProbe = StageProbe Int (IORef [Int])
stage :: Int -> StageProbe -> P.Checked ()
stage number (StageProbe failure seen) = do
  lift (modifyIORef' seen (++ [number]))
  when (number == failure) (throwE 1)
instance P.ReplayPreparation StageProbe where prepareBlock = stage 0
instance P.ReplayMessages StageProbe where replayMessages = stage 1
instance P.ReplayMaintenance StageProbe where
  beforeTreasury = stage 2
  afterTreasury = stage 4
instance P.ReplayTreasury StageProbe where replayTreasury = stage 3

blockStages :: Property
blockStages = forAll (choose (-1,4)) $ \failure -> ioProperty $ do
  seen <- newIORef []
  result <- runExceptT (P.replayBlock (StageProbe failure seen))
  trace <- readIORef seen
  pure $ conjoin [trace === [0..if failure < 0 then 4 else failure],
    result === if failure < 0 then Right () else Left 1]

blockLazy :: Property
blockLazy = conjoin
  [ (() <$ interpret (SomeOperation (undefined :: P.Prelude)) (undefined :: DSL P.Block)) === Nothing
  , (() <$ interpret (SomeOperation (undefined :: P.Block)) P.ReplayBlock) === Just ()
  ]

settings :: Word64
settings = R.replayWord (B.concat (map (wordLE 2) [10,5,10,5]))

type Override = [((Word32,Word64),B.ByteString)]
blockFixture :: Int -> Int -> Int -> Override -> IO (Int32,Trace)
blockFixture messages transactions failure overrides = do
  seen <- newIORef []
  selected <- newIORef 0
  let native step index input = do
        trace <- readIORef seen
        modifyIORef' seen ((fromIntegral step,index,input):)
        when (length trace == failure) (ioError (userError "block callback failed"))
        case lookup (step,index) overrides of
          Just reply -> pure reply
          Nothing -> case (step `div` 4096,step `mod` 4096) of
            (0,0) -> pure (parameters 19 24 0)
            (0,1) -> pure (wordLE 8 6)
            (0,2) -> pure B.empty
            (0,3) -> pure B.empty
            (0,10) -> pure (wordLE 8 (fromIntegral messages))
            (0,11) -> writeIORef selected (fromIntegral index) >> pure B.empty
            (0,12) -> pure (wordLE 8 1)
            (0,13) -> payload . Row 1 24 <$> readIORef selected
            (0,14) -> pure (B.reverse input)
            (0,15) -> pure B.empty
            (0,20) -> pure (wordLE 8 (fromIntegral transactions+1))
            (0,21) -> pure B.empty
            (0,30) -> pure (wordLE 8 0)
            (0,200) -> pure B.empty
            (0,201) -> pure B.empty
            (1,0) -> pure (B.pack [1,2])
            (1,2) -> pure B.empty
            (1,21) -> pure (wordLE 8 0)
            (1,40) -> pure B.empty
            (1,1000) -> pure (wordLE 8 (fromIntegral messages))
            (1,1001) -> pure B.empty
            (2,0) -> pure (B.pack [24,0])
            (2,1) -> pure B.empty
            (2,1000) -> pure B.empty
            (3,1000) -> pure (B.concat (map (wordLE 8) [fromIntegral transactions+1,0,1000]))
            (3,1001) -> pure (wordLE 8 1 <> wordLE 8 1 <> B.pack [24,0])
            (3,1002) -> pure B.empty
            (3,1003) -> pure B.empty
            (3,202) -> pure (wordLE 8 0)
            (3,0) -> pure (wordLE 8 0)
            (4,1000) -> pure (wordLE 8 12)
            (4,10) -> pure (B.pack [42,0,43,1])
            (4,11) -> pure B.empty
            (4,12) -> pure B.empty
            (4,13) -> pure B.empty
            (4,21) -> pure (B.singleton 0)
            (4,27) -> pure (B.singleton 0)
            _ -> ioError (userError ("unexpected block callback " ++ show (step,index)))
  result <- try (execute (P.Block 100 settings 10 5 0xb7 0 native) P.ReplayBlock) :: IO (Either SomeException Int32)
  (,) (either (const (-1)) id result) . reverse <$> readIORef seen

blockWhole :: Property
blockWhole = forAll ((,) <$> choose (0,8) <*> choose (0,8)) $ \(messages,transactions) -> ioProperty $ do
  (result,trace) <- blockFixture messages transactions (-1) []
  let selects step = [index | (actual,index,_) <- trace,actual == step]
      groups = map head (group [step `div` 4096 | (step,_,_) <- trace,step >= 4096])
  pure $ conjoin [result === 0,groups === [1,2,3,4],
    take 3 trace === [(30,1,B.empty),(30,7,B.empty),(201,0,B.empty)],
    selects 4096 === (if messages == 0 then [] else [0..fromIntegral messages-1]),
    selects (3*4096+1001) === [1..fromIntegral transactions],
    [input | (step,_,input) <- trace,step == 4*4096+11] === [B.singleton 42],
    map (\(step,index,_) -> (step,index)) (drop (length trace-4) trace) ===
      [(4*4096+12,0),(4*4096+13,0),(4*4096+21,0),(4*4096+27,0)]]

blockFaults :: Property
blockFaults = withMaxSuccess 300 $ forAll ((,) <$> choose (0,5) <*> choose (0,5)) $ \(messages,transactions) ->
  forAll (choose (0,250)) $ \failure -> ioProperty $ do
    baseline@(_,trace) <- blockFixture messages transactions (-1) []
    actual@(result,observed) <- blockFixture messages transactions failure []
    pure $ if failure >= length trace then actual === baseline
      else conjoin [result === -1,observed === take (failure+1) trace]

blockMalformed :: Property
blockMalformed = once $ ioProperty $ do
  let cases = [((4096+1000,0),B.singleton 0),((4096,0),B.singleton 1),
        ((8192,0),B.pack [24,2]),((8193,24),B.singleton 1),
        ((12288+1000,0),B.replicate 23 0),
        ((12288+1000,0),B.concat (map (wordLE 8) [2,4,1000])),
        ((12288+1001,1),B.replicate 15 0),
        ((12288+1001,1),wordLE 8 1 <> wordLE 8 1 <> B.pack [24,2]),
        ((12288+1002,0),B.singleton 0),
        ((16384+1000,0),wordLE 8 16),((16384+10,0),B.pack [42,64]),
        ((16384+11,0),B.singleton 0),((16384+12,0),B.singleton 0),
        ((16384+21,0),B.pack [0,0]),((201,0),B.singleton 0)]
  outcomes <- mapM (\override -> blockFixture 1 1 (-1) [override]) cases
  pure $ conjoin [counterexample (show key) (conjoin [result === -1,
    property (not (null trace)),
    let (step,index,_) = last trace in (step,index) === (fromIntegral (fst key),snd key)])
    | ((key,_),(result,trace)) <- zip cases outcomes]

blockRejections :: Property
blockRejections = once $ ioProperty $ do
  inactive <- blockFixture 1 1 (-1) [((4096,0),B.pack [3,2])]
  future <- blockFixture 1 1 (-1) [((8193,24),wordLE 4 101 <> wordLE 4 0)]
  replaced <- blockFixture 1 1 (-1) [((16384+1000,0),wordLE 8 13)]
  pure $ conjoin [fst inactive === 1,last (snd inactive) === (5097,0x201,B.empty),
    fst future === 1,last (snd future) === (9192,0x118,B.empty),
    fst replaced === 1,last (snd replaced) ===
      (200,0,C.pack "parent slot no longer has the required active proposal")]

-- Exercise the new internal parsers and block-scoped M6 state through real
-- treasury rules. Native replies are only object getters/effect acknowledgments.
blockTreasury :: Property
blockTreasury = forAll ((,,) <$> arbitrary <*> arbitrary <*> elements [0xb4,0xb7]) $ \(withdrawal,single,opcode) -> ioProperty $ do
  seen <- newIORef []
  selected <- newIORef (0 :: Word64)
  let native step index input = do
        current <- readIORef selected
        modifyIORef' seen (++ [(current,step,index,input)])
        let word = pure . wordLE 8
            value = if withdrawal then 90 else 110
        case step of
          30 -> word 0
          _ | step < 12288 -> ioError (userError "unexpected treasury group")
          _ -> case step-12288 of
            1000 -> pure (B.concat (map (wordLE 8) [3,3,1000]))
            1001 -> writeIORef selected index >> pure (wordLE 8 1 <> wordLE 8 (if withdrawal then 1 else 2) <> B.pack [24,1])
            1002 -> pure B.empty
            1003 -> pure (if index == 0 then B.pack [opcode,1,24,0x51] else B.pack [106,1,42])
            1004 -> pure B.empty
            1005 -> pure B.empty
            1006 -> pure B.empty
            1007 -> word 1
            1008 -> pure B.empty
            0 -> word $ case index of
              0 -> 1; 1 -> 1; 2 -> 1; 3 -> if withdrawal then 1 else 0
              4 -> 100; 5 -> value; 6 -> 0; 7 -> 3; _ -> error "unexpected treasury fact"
            102 -> word 100
            304 -> word value
            503 -> word 100
            505 -> word value
            601 -> word 0
            605 -> word 6
            704 -> word 4
            903 -> word value
            action | action `elem` [101,103,104,202,203,303,305,401,402,403,501,502,506,507,
                603,604,606,609,610,611,612,702,703,705,800,901,905,906] -> word 1
            action -> ioError (userError ("unexpected treasury callback " ++ show action))
  status <- runExceptT (P.replayTreasury (P.Block 100 settings 10 5 (fromIntegral opcode) (if single then 1 else 0) native))
  trace <- readIORef seen
  let rejected = withdrawal && single
      publications action = [index | (index,step,_,_) <- trace,step == 12288+action]
  pure $ conjoin [status === if rejected then Left 1 else Right (),
    publications (if withdrawal then 609 else 705) === if rejected then [1] else [1,2],
    property (null [() | (_,step,_,_) <- trace,step `elem` map (+12288) [201,301,302,607,608,701,902]]),
    if rejected then let (_,step,code,_) = last trace in (step,code) === (13296,0x607) else property True]
