{-# LANGUAGE FlexibleInstances, MultiParamTypeClasses, TypeFamilies #-}
module WalletWithdrawalTests (properties) where

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
import Test.QuickCheck hiding (output, verbose)
import qualified Withdrawal as H
import Withdrawal (wordLE, readLE)
import Workflow (NativeBytes)

money :: Int64
money = 2100000000000000
type Event = (Word32,Word64,B.ByteString)
data Scenario = Scenario { observations :: [(Word32,Word64)], amount :: Int64,
  fee :: Int64, parentByte :: Word32, outputCount :: Int, explicitOutput :: Bool } deriving Show
data State = State { held :: Bool, plan :: B.ByteString, commits :: Int,
  published :: [Word32], selected :: B.ByteString } deriving (Eq,Show)
base :: Scenario
base = Scenario [] 100000 1000 1 1 True
at :: Word32 -> Word64 -> Scenario -> Scenario
at step value s = s {observations=(step,value):observations s}
script :: B.ByteString
script = B.pack [0,20] <> B.replicate 20 2
asset :: B.ByteString
asset = B.replicate 32 3
parent :: Scenario -> B.ByteString
parent s = B.replicate 32 (fromIntegral (parentByte s))
valueAt :: Scenario -> Word32 -> Word64
valueAt s step = maybe defaultValue id (lookup step (observations s))
  where defaultValue = case step of
          2 -> 3
          22 -> 0
          23 -> 0
          24 -> 0
          26 -> 0
          102 -> 44
          109 -> 22
          113 -> 8
          _ -> 1
effectiveFee :: Scenario -> Int64
effectiveFee s = if valueAt s 26==1 then 0 else fee s

capture :: (NativeBytes -> IO Int32) -> Scenario -> Int -> Maybe (Word32,B.ByteString)
  -> IO (Either String Int32,[Event],State)
capture run s fault altered = do
  state <- newIORef (State False B.empty 0 [] B.empty)
  events <- newIORef []
  poisoned <- newIORef Nothing
  let native step index input = do
        readIORef poisoned >>= maybe (pure ()) throwIO
        trace <- readIORef events
        modifyIORef' events (++[(step,index,input)])
        result <- try $ do
          when (length trace==fault) (ioError (userError "withdrawal callback fault"))
          when (step==0) (ioError (userError (if index==0 then C.unpack input else
            show (fromIntegral (readLE (B.take 4 input)) :: Int32)++":"++C.unpack (B.drop 4 input))))
          unless (index==0) (ioError (userError "unexpected withdrawal index"))
          unless (case step of
            21 -> B.length input==8
            29 -> B.length input>=8
            47 -> B.length input==4
            _ -> B.null input) (ioError (userError "unexpected withdrawal frame"))
          st <- readIORef state
          when (step>=5 && not (held st)) (ioError (userError "wallet lock not held"))
          case step of
            4 -> modifyIORef' state (\v -> v {held=True})
            29 -> modifyIORef' state (\v -> v {plan=input})
            41 -> modifyIORef' state (\v -> v {commits=commits v+1})
            47 -> modifyIORef' state (\v -> v {selected=input})
            48 -> modifyIORef' state (\v -> v {published=published v++[48]})
            49 -> modifyIORef' state (\v -> v {published=published v++[49]})
            _ -> pure ()
          when (step `elem` [104,110,112,114]) (ioError (userError ("destination failure "++show step)))
          let burn = plan st
              burnScript = B.drop 8 burn
              record n = wordLE 4 n <> asset <> B.pack [1,if explicitOutput s then 1 else 0,1,1] <>
                B.take 8 burn <> B.singleton 1
              bytes = case step of
                20 -> wordLE 8 (fromIntegral (amount s)) <> wordLE 4 31 <> B.singleton 1
                21 -> C.pack "0.00000294"
                28 -> wordLE 8 (fromIntegral (amount s)) <> wordLE 8 (fromIntegral (effectiveFee s)) <> parent s <> script
                46 -> asset <> parent s <> B.take 8 burn <> wordLE 8 (fromIntegral (amount s)) <>
                  wordLE 8 (fromIntegral (effectiveFee s)) <> wordLE 4 (fromIntegral (B.length burnScript)) <>
                  burnScript <> B.concat [record (fromIntegral n) | n <- [2..1+outputCount s]]
                _ -> wordLE 8 (valueAt s step)
          pure $ case altered of Just (changed,replacement) | changed==step -> replacement; _ -> bytes
        case result of
          Left err -> writeIORef poisoned (Just (err :: SomeException)) >> throwIO err
          Right bytes -> pure bytes
  result <- try (run native) :: IO (Either SomeException Int32)
  modifyIORef' state (\v -> v {held=False})
  trace <- readIORef events
  final <- readIORef state
  pure (either (Left . show) Right result,trace,final)

actual :: NativeBytes -> IO Int32
actual native = execute (H.WalletWithdrawal money native) H.WithdrawFromWallet

-- Procedural order from the sealed old wallet RPC, using only unchanged pure
-- rules, not the new workflow classes, destination transition or interpreter.
reference :: NativeBytes -> IO Int32
reference native = do
  yes 1 >>= guardAt 0
  val 2 >>= guardAt 1 . (==3)
  loaded <- yes 3
  if not loaded then pure 0 else do
    mapM_ effect [4,5,10]
    hex <- yes 101
    if hex then do
      size <- val 102
      when (size>256) (effect 104)
      valid <- yes 103
      if valid then effect 106 else effect 104
    else do
      valid <- yes 105
      if valid then effect 108 else effect 110
    size <- val 109
    unless (size>0 && size<=128) (effect 112)
    yes 111 >>= \valid -> unless valid (effect 112)
    val 113 >>= \kind -> unless (kind `elem` [2,3,4,5,7,8,9]) (effect 114)
    payout <- native 20 0 B.empty >>= rule H.NativePayout
    case signedCode payout of
      -3 -> rpc (-3) "Invalid withdrawal payout amount"
      -8 -> do
        formatted <- native 21 0 (B.drop 4 payout)
        rpc (-8) ("Bitcoin withdrawal payout is dust for this destination (minimum "++C.unpack formatted++")")
      0 -> pure ()
      _ -> ioError (userError "invalid reference payout")
    omittedSubtract <- yes 22
    subtractFee <- if omittedSubtract then pure False else yes 23
    guardAt 2 subtractFee
    omittedVerbose <- yes 24
    verbose <- if omittedVerbose then pure False else yes 25
    yes 26 >>= \omitted -> unless omitted (effect 27)
    burn <- native 28 0 B.empty >>= rule H.NativeBurnPlan >>= decode
    _ <- native 29 0 burn
    yes 30 >>= \enabled -> when enabled (effect 31)
    yes 32 >>= guardAt 3
    mapM_ effect [40,41,42]
    present <- yes 43
    hasTx <- if present then yes 44 else pure False
    unless hasTx (rpc (-4) "Committed withdrawal transaction is unavailable in the wallet")
    selectedOutput <- native 46 0 B.empty >>= rule H.NativeOutputSelection >>= decode
    _ <- native 47 0 selectedOutput
    effect (if verbose then 49 else 48)
    pure 1
  where
    val step = readLE <$> native step 0 B.empty
    yes step = (==1) <$> val step
    effect step = val step >> pure ()
    signedCode bytes = fromIntegral (readLE (B.take 4 bytes)) :: Int32
    rpc :: Int32 -> String -> IO a
    rpc code message = native 0 1 (wordLE 4 (fromIntegral (code :: Int32)) <> C.pack message) >>
      ioError (userError "reference RPC callback returned")
    rule action bytes = either (ioError . userError) pure
      (H.withdrawal (fromIntegral (fromEnum action)+1) money bytes)
    decode bytes = if signedCode bytes==0 then pure (B.drop 4 bytes)
      else rpc (signedCode bytes) (C.unpack (B.drop 4 bytes))
    guardAt stage flag = rule H.NativeGuardResult (B.pack [stage,if flag then 1 else 0]) >>= decode >> pure ()

routes :: [Scenario]
routes = [base,at 101 0 base,at 22 1 (at 24 1 (at 26 1 base)),at 25 0 base,
  at 30 0 base,at 1 0 base,at 2 0 base,at 2 1 base,at 2 2 base,at 3 0 base,
  at 102 257 base,at 103 0 base,at 101 0 (at 105 0 base),at 109 0 base,at 109 129 base,
  at 111 0 base,at 113 6 base,at 23 1 base,at 32 0 base,at 43 0 base,at 44 0 base,
  base {amount=0},base {amount=1},base {amount=293},base {amount=294},
  base {amount=money+1},base {amount=money},base {fee=(-1)},base {fee=money},
  base {parentByte=0},base {outputCount=0},base {outputCount=2},base {explicitOutput=False}]

workflow :: Property
workflow = once $ ioProperty $ do
  checks <- forM routes $ \scenario -> do
    expected@(_,trace,_) <- capture reference scenario (-1) Nothing
    observed <- capture actual scenario (-1) Nothing
    faults <- forM [0..length trace-1] $ \fault -> do
      old <- capture reference scenario fault Nothing
      new@(status,prefix,st) <- capture actual scenario fault Nothing
      pure (conjoin [new === old,prefix === take (fault+1) trace,
        property (either (const True) (const False) status),property (commits st<=1)])
    pure (counterexample (show scenario) (conjoin ((observed === expected):faults)))
  pure (conjoin checks)

generated :: Property
generated = forAll ((,,,,,) <$> elements [0,1,293,294,100000,money-1,money,money+1] <*>
  elements [-1,0,1,1000,money] <*> arbitrary <*> arbitrary <*> chooseInt (0,3) <*>
  elements [(1,0),(2,1),(3,0),(22,1),(23,0),(23,1),(24,1),(25,0),(26,1),(30,0),(32,0),(43,0),(44,0),(101,0),(103,0),(109,128),(113,7)]) $
  \(payout,parentFee,nonzero,explicit,count,(step,value)) -> ioProperty $ do
    let scenario = at step value base {amount=payout,fee=parentFee,parentByte=if nonzero then 1 else 0,
          outputCount=count,explicitOutput=explicit}
    expected <- capture reference scenario (-1) Nothing
    observed <- capture actual scenario (-1) Nothing
    pure (counterexample (show scenario) (observed === expected))

frames :: Property
frames = once $ ioProperty $ do
  (_,trace,_) <- capture actual base (-1) Nothing
  let steps = [step | (step,_,_) <- trace]
      malformed = [(step,bytes) | step <- steps,bytes <- [B.empty,B.singleton 1,B.replicate 9 0]] ++
        [(step,wordLE 8 2) | step <- [1,3,22,23,24,25,26,30,32,43,44]] ++
        [(2,wordLE 8 4),(101,wordLE 8 maxBound)]
  checks <- forM malformed $ \change@(step,_) -> do
    (result,events,st) <- capture actual base (-1) (Just change)
    let prefix = takeWhile (\(s,_,_) -> s/=step) trace
    pure (counterexample (show change) (conjoin [property (either (const True) (const False) result),
      take (length prefix+1) events === take (length prefix+1) trace,
      property (all (\(s,_,_) -> s==0) (drop (length prefix+1) events)),
      property (commits st<=1)]))
  absent <- FFI.elements_hs_replay_store 30 (fromIntegral money) nullFunPtr nullPtr
  unknown <- FFI.elements_hs_replay_store 40 (fromIntegral money) nullFunPtr nullPtr
  pure (conjoin (checks++[absent === -1,unknown === -1]))

data Probe = Probe (IORef [String]) Bool Bool
instance H.WalletAdmission Probe where
  admitWithdrawalWallet (Probe events present _) = modifyIORef' events (++["admit"]) >> pure present
instance H.WalletPreparation Probe where
  prepareWithdrawalWallet (Probe events _ verbose) = modifyIORef' events (++["prepare"]) >> pure verbose
instance H.WalletSubmission Probe where
  submitWithdrawalWallet (Probe events _ _) verbose = modifyIORef' events (++[if verbose then "detailed" else "txid"])

dispatch :: Property
dispatch = once $ ioProperty $ do
  checks <- forM [(present,verbose) | present <- [False,True],verbose <- [False,True]] $ \(present,verbose) -> do
    events <- newIORef []
    status <- H.withdrawFromWallet (Probe events present verbose)
    trace <- readIORef events
    pure (conjoin [status === (if present then 1 else 0),
      trace === ["admit"]++[stage | present,stage <- ["prepare",if verbose then "detailed" else "txid"]]])
  pure (conjoin (checks++[property (isNothing (interpret (SomeOperation (Check (Bmm.NextBlockHeight 0 0)))
    (undefined :: DSL H.WalletWithdrawal)))]))

properties :: [(String,Property)]
properties = [("Wallet withdrawal / differential routes and every callback fault",workflow),
  ("Wallet withdrawal / generated monetary, destination and output routes",generated),
  ("Wallet withdrawal / malformed framing and ABI rejection",frames),
  ("Wallet withdrawal / capability reuse, early return and lazy payload mismatch",dispatch)]
