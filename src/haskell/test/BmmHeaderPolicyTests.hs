{-# LANGUAGE FlexibleInstances, MultiParamTypeClasses, TypeFamilies #-}
module BmmHeaderPolicyTests (properties) where

import qualified Bmm as H
import Control.Exception (SomeException, throwIO, try)
import Control.Monad (forM, unless, when, void)
import Control.Operation
import Control.Operation.Validation (Check(..), validate)
import Data.Bits ((.|.), testBit)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.Int (Int32, Int64)
import Data.IORef
import Data.Maybe (isNothing)
import Data.Word (Word32, Word64)
import qualified Drivechain as FFI
import Foreign.Ptr (nullFunPtr, nullPtr)
import Test.QuickCheck hiding (output)
import Withdrawal (readLE, wordLE)
import Workflow (NativeBytes)

data Fixture = Fixture Word32 Word32 Bool Bool Int64 Int64 Word32 deriving Show
type Event = (Word32,B.ByteString)
base :: Fixture
base = Fixture 50 2 False True 99 100 1

capture :: (NativeBytes -> IO Int32) -> Fixture -> Int -> Maybe (Word32,B.ByteString)
  -> IO (Either String Int32,[Event])
capture run (Fixture facts flags private present height activation ancestry) fault altered = do
  events <- newIORef []
  poisoned <- newIORef Nothing
  let native step index input = do
        readIORef poisoned >>= maybe (pure ()) throwIO
        prior <- readIORef events
        modifyIORef' events (++[(step,input)])
        result <- try $ do
          when (length prior==fault) (ioError (userError "header callback fault"))
          unless (index==0 && (B.null input || step `elem` [0,11]))
            (ioError (userError "unexpected header callback input"))
          when (step==0) (ioError (userError (C.unpack input)))
          let values = case step of
                1 -> [fromIntegral flags]
                2 -> [fromIntegral (fromEnum private)]
                3 -> [fromIntegral (fromEnum present),fromIntegral height,fromIntegral activation]
                4 -> [fromIntegral ancestry]
                10 -> [fromIntegral facts]
                11 -> [1]
                _ -> error "unexpected header callback"
              bytes = B.concat (map (wordLE 8) values)
          pure $ case altered of Just (changed,replacement) | step==changed -> replacement; _ -> bytes
        case result of
          Left err -> writeIORef poisoned (Just (err :: SomeException)) >> throwIO err
          Right bytes -> pure bytes
  result <- try (run native) :: IO (Either SomeException Int32)
  trace <- readIORef events
  pure (either (Left . show) Right result,trace)

actual :: Bool -> NativeBytes -> IO Int32
actual checking native = execute (H.HeaderPolicy native) (if checking then H.CheckHeaderPolicy else H.ProofIsRequired)

-- Former native branch order; pure consensus rules are the unchanged oracle.
reference :: Bool -> NativeBytes -> IO Int32
reference checking native = if not checking then required else do
  facts <- fromIntegral <$> scalar 10
  let preflight = validate (H.Header facts)
  result <- if preflight/=6 then pure preflight else do
    need <- required
    pure (validate (H.Header (facts .|. (if need==1 then 64 else 0) .|. 256)))
  if result==0 then pure 1 else do
    void (native 11 0 (C.pack (messages !! (fromIntegral result-1))))
    pure 0
  where
    scalar step = readLE <$> native step 0 B.empty
    abort message = native 0 0 (C.pack message) >> ioError (userError message)
    required = do
      flags <- fromIntegral <$> scalar 1
      if validate (H.Activation 0 flags 0 0)/=2 then pure 0 else do
        private <- scalar 2
        result <- if private==0 then do
          ancestry <- fromIntegral <$> scalar 4
          pure (validate (H.Activation 2 ancestry 0 0))
          else do
            fields <- native 3 0 B.empty
            let field n = readLE (B.take 8 (B.drop (8*n) fields))
            pure (validate (H.Activation 1 (fromIntegral (field 0)) (fromIntegral (field 1)) (fromIntegral (field 2))))
        case result of
          -2 -> abort "-ecxprivatebmmcheckpoint requires an explicit -ecxprivatebmmactivationheight"
          -3 -> abort "invalid -ecxprivatebmmactivationheight"
          _ -> pure result
    messages = ["historical signet BMM proof is not valid on native Elements",
      "public-signet height 2 does not match its immutable checkpoint",
      "public-signet descendant does not signal deterministic BMM proof",
      "deterministic BMM header has no proof commitment",
      "deterministic BMM proof cannot activate outside the public-signet checkpoint"]

compareFixture :: Bool -> Fixture -> IO Property
compareFixture checking fixture = do
  expected@(_,trace) <- capture (reference checking) fixture (-1) Nothing
  observed <- capture (actual checking) fixture (-1) Nothing
  faults <- forM [0..length trace-1] $ \fault -> do
    old <- capture (reference checking) fixture fault Nothing
    new@(_,prefix) <- capture (actual checking) fixture fault Nothing
    pure (conjoin [new===old,prefix===take (fault+1) trace])
  pure (counterexample (show (checking,fixture)) (conjoin ((observed===expected):faults)))

routes :: Property
routes = once $ ioProperty $ do
  let settings = [(False,True,99,100,a) | a <- [0..3]] ++
        [(True,p,h,a,0) | (p,h,a) <- [(False,99,100),(True,99,100),(True,98,100),
          (True,100,100),(True,0,0),(True,0,-1),(True,maxBound,2147483647),
          (True,minBound,1),(True,2147483645,2147483646),(True,maxBound,1),
          (True,0,minBound),(True,0,maxBound)]]
      fixtures = [Fixture facts flags private present height activation ancestry |
        facts <- [0..255],not (testBit facts 6),flags <- [0..3],
        (private,present,height,activation,ancestry) <- settings]
  checks <- mapM (compareFixture True) fixtures
  standalone <- mapM (compareFixture False) [Fixture 0 flags private present height activation ancestry |
    flags <- [0..3],(private,present,height,activation,ancestry) <- settings]
  pure (conjoin (checks++standalone))

generated :: Property
generated = forAll ((,,,,) <$> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary) $
  \(checking,private,present,height,activation) ->
    forAll (elements [0..255] `suchThat` (not . (`testBit` 6))) $ \facts ->
      forAll (choose (0,3)) $ \ancestry -> ioProperty $
        compareFixture checking (Fixture facts 2 private present height activation ancestry)

frames :: Property
frames = once $ ioProperty $ do
  let samples = [base,Fixture 2 2 True True 99 100 0,Fixture 2 2 False True 0 0 1]
  checks <- forM samples $ \fixture -> do
    (_,trace) <- capture (actual True) fixture (-1) Nothing
    forM [(step,bytes) | (step,_) <- trace, bytes <-
      if step==3 then [B.empty,B.replicate 23 0,B.replicate 25 0,wordLE 8 2<>B.replicate 16 0]
      else [B.empty,B.replicate 7 0,B.replicate 9 0,wordLE 8 (maxBound :: Word64)]] $ \change@(step,_) -> do
        (result,observed) <- capture (actual True) fixture (-1) (Just change)
        let prefix = takeWhile ((/=step).fst) trace
        pure (counterexample (show change) (conjoin [property (either (const True) (const False) result),
          take (length prefix+1) observed===take (length prefix+1) trace,
          property (all ((==0).fst) (drop (length prefix+1) observed))]))
  rejects <- forM [(10,wordLE 8 64),(11,wordLE 8 0)] $ \change -> do
    (result,_) <- capture (actual True) (Fixture 2 2 False True 0 0 1) (-1) (Just change)
    pure (property (either (const True) (const False) result))
  absent <- mapM (\mode -> FFI.elements_hs_replay_store mode 0 nullFunPtr nullPtr) [35,36,40]
  pure (conjoin (concat checks++rejects++[absent===replicate 3 (-1)]))

data Probe = Probe Word32 Bool (IORef [Int32])
instance H.ProofRequirement Probe where
  requiresProof (Probe _ required events) = modifyIORef' events (++[6]) >> pure required
instance H.HeaderObservation Probe where
  headerFacts (Probe facts _ events) = modifyIORef' events (++[10]) >> pure facts
  rejectHeader (Probe _ _ events) code = modifyIORef' events (++[code])

reuse :: Property
reuse = once $ ioProperty $ do
  checks <- forM [(0,False,1,[10]),(1+16,True,0,[10,1]),
    (2,True,0,[10,6,3]),(2+16+32,True,1,[10,6]),(2+16+32,False,0,[10,6,5])] $
    \(facts,required,expected,trace) -> do
      events <- newIORef []
      result <- H.checkHeaderPolicy (Probe facts required events)
      observed <- readIORef events
      pure (conjoin [result===expected,observed===trace])
  pure (conjoin (checks++[property (isNothing (interpret (SomeOperation (Check (H.NextBlockHeight 0 0)))
    (undefined :: DSL H.HeaderPolicy)))]))

properties :: [(String,Property)]
properties = [("BMM header policy / exhaustive routes and callback failures",routes),
  ("BMM header policy / generated activation boundaries",generated),
  ("BMM header policy / strict frames and ABI rejection",frames),
  ("BMM header policy / capability reuse and lazy mismatch",reuse)]
