{-# LANGUAGE FlexibleInstances, MultiParamTypeClasses, TypeFamilies #-}
module ForcedOutputTests (properties) where

import Control.Exception (SomeException, try, throwIO)
import Control.Monad (forM, unless, when)
import Control.Operation
import Control.Operation.Validation (Check(..))
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.IORef
import Data.Int (Int32)
import Data.Maybe (isNothing)
import Data.Word (Word32, Word64)
import qualified Drivechain as FFI
import qualified Exchange as H
import Foreign.Ptr (nullFunPtr, nullPtr)
import Test.QuickCheck hiding (output)
import Withdrawal (wordBE, wordLE)

type Event = (Word32,B.ByteString)
data Fixture = Fixture [Bool] Bool Bool Word64 deriving Show

pin, payload, script, metadata :: B.ByteString
pin = B.replicate 32 7
payload = B.pack [69,67,88,70,3,4,0,32]<>pin
script = B.pack [106,40]<>payload
metadata = B.pack [1,4]<>B.replicate 32 8<>wordBE 8 105<>wordBE 8 0

messages :: [String]
messages = ["Exact forced admission backend is unavailable", "Exact forced output index is invalid",
  "Exact forced output has a noncanonical asset/value/witness", "Exact forced marker framing or economic domain is invalid",
  "Exact forced canonical codec or signature rejected", "Exact forced request is outside its admission lifetime"]

-- Former C++ statement order, independently expressed without the new workflow.
reference :: Bool -> Fixture -> (Bool,[Event],String)
reference admission (Fixture facts frame signature parent) = case [i | (i,False)<-zip [0..7] facts] of
  i:_ -> reject (min i 2) [0..fromIntegral i]
  [] | not frame -> reject 3 ([0..9])
     | not signature -> reject 4 ([0..10])
     | admission && (parent==0 || parent>maxBound-12 || parent>105 || parent<=93) -> reject 5 [0..11]
     | otherwise -> (True,map event ([0..10]++[11 | admission]++[12]),"old error")
  where
    reject which steps = (False,map event steps++[(13,C.pack (messages!!which))],messages!!which)
    event step = (step,case step of 10 -> payload; 12 -> payload<>metadata; _ -> B.empty)

exercise :: Bool -> Fixture -> Int -> Maybe (Word32,B.ByteString)
  -> IO (Either String Bool,[Event],String,Maybe B.ByteString)
exercise admission (Fixture facts frame signature parent) fault altered = do
  events <- newIORef []
  diagnostic <- newIORef "old error"
  publication <- newIORef Nothing
  poisoned <- newIORef Nothing
  let native step index input = do
        readIORef poisoned >>= maybe (pure ()) throwIO
        seen <- readIORef events
        modifyIORef' events (++[(step,input)])
        result <- try $ do
          when (length seen==fault) (ioError (userError "forced native fault"))
          unless (index==0 && (B.null input || step `elem` [10,12,13])) (error "invalid native input")
          when (step==10) (unless (input==payload) (error "wrong signed payload"))
          when (step==12) (writeIORef publication (Just input))
          when (step==13) (writeIORef diagnostic (C.unpack input))
          pure $ case altered of
            Just (changed,replacement) | step==changed -> replacement
            _ | step<=7 -> B.singleton (if facts!!fromIntegral step then 1 else 0)
            _ -> case step of
              8 -> pin
              9 -> if frame then script else B.snoc script 0
              10 -> if signature then B.cons 1 metadata else B.singleton 0
              11 -> wordLE 8 parent
              12 -> B.singleton 1
              13 -> B.singleton 1
              _ -> error "unexpected native step"
        case result of
          Left err -> writeIORef poisoned (Just (err :: SomeException)) >> throwIO err
          Right bytes -> pure bytes
  outcome <- try (execute (H.ForcedOutputSession native) (if admission then H.AdmitForcedOutput else H.CheckForcedOutput))
  trace <- readIORef events
  message <- readIORef diagnostic
  output <- readIORef publication
  pure (either (Left . show . (id :: SomeException -> SomeException)) Right outcome,trace,message,output)

comparison :: Bool -> Fixture -> IO Property
comparison admission fixture = do
  let (accepted,trace,message) = reference admission fixture
  (result,observed,diagnostic,output) <- exercise admission fixture (-1) Nothing
  pure (counterexample (show (admission,fixture)) (conjoin [result===Right accepted,
    observed===trace,diagnostic===message,output===if accepted then Just (payload<>metadata) else Nothing]))

routes :: Property
routes = once $ ioProperty $ do
  let facts = sequence (replicate 8 [False,True])
  checks <- sequence [comparison admission (Fixture flags frame signature parent) |
    flags<-facts,admission<-[False,True],frame<-[False,True],signature<-[False,True],
    parent<-[0,1,93,94,100,105,106,maxBound-12,maxBound-11,maxBound]]
  pure (conjoin checks)

generated :: Property
generated = forAll ((,,,,) <$> arbitrary <*> vectorOf 8 arbitrary <*> arbitrary <*> arbitrary <*> arbitrary) $
  \(admission,facts,frame,signature,parent) -> ioProperty (comparison admission (Fixture facts frame signature parent))

faults :: Property
faults = once $ ioProperty $ do
  let allGood = replicate 8 True
      samples = [Fixture (take i allGood++[False]++drop (i+1) allGood) True True 100 | i<-[0..7]] ++
        [Fixture allGood False True 100,Fixture allGood True False 100,Fixture allGood True True 112,
         Fixture allGood True True 100]
  checks <- forM [(admission,fixture) | admission<-[False,True],fixture<-samples] $ \(admission,fixture) -> do
    let (_,trace,_) = reference admission fixture
    forM [0..length trace-1] $ \fault -> do
      (result,observed,_,published) <- exercise admission fixture fault Nothing
      pure (conjoin [property (either (const True) (const False) result),
        observed===take (fault+1) trace,published===Nothing])
  pure (conjoin (concat checks))

frames :: Property
frames = once $ ioProperty $ do
  let base=Fixture (replicate 8 True) True True 100
      malformed :: Word32 -> [B.ByteString]
      malformed step = case step of
        8 -> [B.empty,B.replicate 31 0,B.replicate 33 0]
        10 -> [B.empty,B.singleton 2,B.replicate 50 1,B.replicate 52 1,B.cons 2 metadata]
        11 -> [B.empty,B.replicate 7 0,B.replicate 9 0]
        _ -> [B.empty,B.singleton 2,B.pack [0,1]]
      (_,trace,_) = reference True base
  checks <- forM [(step,bytes) | step<-[0..8]++[10..12],bytes<-malformed step] $ \changed@(step,_) -> do
    (result,observed,_,_) <- exercise True base (-1) (Just changed)
    pure (counterexample (show changed) (conjoin [property (either (const True) (const False) result),
      observed===take (length (takeWhile ((/=step).fst) trace)+1) trace]))
  -- A rejection acknowledgement is also checked; rejection never publishes.
  rejected <- forM (malformed 13) $ \bytes -> do
    (result,_,_,output) <- exercise True (Fixture (False:replicate 7 True) True True 100) (-1) (Just (13,bytes))
    pure (conjoin [property (either (const True) (const False) result),output===Nothing])
  absent <- mapM (\mode -> FFI.elements_hs_exchange_session mode nullFunPtr nullPtr) [0,1,2,maxBound]
  pure (conjoin (checks++rejected++[absent===replicate 4 (-1 :: Int32)]))

data Probe = Probe (IORef [Word32])
instance H.ForcedOutputFacts Probe where
  forcedOutputFact (Probe events) step = modifyIORef' events (++[step]) >> pure True
  forcedOutputFrame (Probe events) = modifyIORef' events (++[8]) >> pure (Just payload)
  forcedOutputParent (Probe events) = modifyIORef' events (++[11]) >> pure 100
instance H.ForcedAuthentication Probe where
  authenticateForcedPayload (Probe events) bytes = do
    unless (bytes==payload) (error "wrong capability payload")
    modifyIORef' events (++[10]) >> pure (Just metadata)
instance H.ForcedOutputEffects Probe where
  rejectForcedOutput _ _ = error "unexpected capability rejection"
  publishForcedOutput _ _ _ = error "validation must not publish"

reuse :: Property
reuse = once $ ioProperty $ do
  checks <- forM [False,True] $ \admission -> do
    events <- newIORef []
    result <- H.checkForcedOutput admission (Probe events)
    trace <- readIORef events
    pure (conjoin [result===Just (payload,metadata),trace===([0..8]++[10]++[11 | admission])])
  pure (conjoin (checks++[property (isNothing (interpret (SomeOperation (Check (H.Groth16Header 0 B.empty)))
    (undefined :: DSL H.ForcedOutputSession)))]))

properties :: [(String,Property)]
properties = [("forced output / exhaustive validation and publication order",routes),
  ("forced output / generated short circuits and lifetimes",generated),
  ("forced output / every native failure prefix",faults),
  ("forced output / strict native frames and ABI rejection",frames),
  ("forced output / reusable capabilities and lazy mismatch",reuse)]
