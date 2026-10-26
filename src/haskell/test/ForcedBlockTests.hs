{-# LANGUAGE FlexibleInstances, MultiParamTypeClasses, TypeFamilies #-}
module ForcedBlockTests (properties) where

import Control.Exception (SomeException, try)
import Control.Monad (forM, unless, when)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Except (runExceptT, throwE)
import Control.Operation
import Control.Operation.Validation (Check(..))
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.Either (isLeft)
import Data.IORef
import Data.Maybe (isNothing)
import Data.Word (Word8, Word32, Word64)
import qualified Drivechain as FFI
import qualified Exchange as E
import qualified ExchangeForcedV3Block as H
import Foreign.Ptr (nullFunPtr, nullPtr)
import Test.QuickCheck hiding (output)
import Withdrawal (wordBE, wordLE)

type Event = (Word32,Word64,B.ByteString)

pin, asset, economics, previous, payload, script, metadata, header :: B.ByteString
pin = B.replicate 32 7
asset = B.replicate 32 9
economics = B.replicate 50 0<>asset<>B.replicate 177 0
previous = B.singleton 3<>pin<>B.replicate 32 8<>B.replicate 16 0<>
  B.replicate 32 8<>B.replicate 32 0
payload = B.pack [69,67,88,70,3,4,0,32]<>pin
script = B.pack [106,40]<>payload
metadata = B.pack [1,4]<>B.replicate 32 8<>wordBE 8 105<>wordBE 8 0
header = B.concat (map (wordBE 8) [3,4,100,100,100,0,0,0,0])<>
  B.replicate 64 6<>B.pack [0,0]

-- The native differential test checks real tagged hashes and signatures.
-- Here deterministic hash projections expose exact effect ordering instead.
digest :: B.ByteString -> B.ByteString
digest bytes = B.replicate 32 (1+fromIntegral (B.foldl' (\n b -> n+fromIntegral b) (0::Word64) bytes `mod` 250))

txid :: Word64 -> B.ByteString
txid index = B.replicate 32 (fromIntegral index+1)

event :: Word32 -> Event
event step = (step,0,B.empty)

reference :: [[Word8]] -> ([Event],B.ByteString)
reference rows = (prefix++scan False++effects++[(207,0,result)],result)
  where
    prefix = map event [100,101,102,103]++[(208,0,economics)]++map event [104,105,106]
    scan admission = event 200:concat
      [(201,t,B.empty):concat [[(202,t,wordBE 8 o),event 203]++
        [event step | admission && kind==1,step<-[0..9]] |
        (o,kind)<-zip [0..] outputs] | (t,outputs)<-zip [0..] rows]
    -- Former C++ nested loop: classify, validate, construct entry, hash twice,
    -- update local state; publish only after all outputs have succeeded.
    advance (state,trace) (t,o,kind) =
      let select=[(202,t,wordBE 8 o),event 203]
      in if kind/=1 then (state,trace++select) else
        let entry = maybe (error "reference entry") id (H.entryBytes
              (state<>txid t<>wordBE 8 4<>wordBE 8 100<>wordBE 4 o<>payload))
            stepBytes=B.take 48 (B.drop 33 state)<>digest entry
            next=maybe (error "reference update") id (H.nextState
              (state<>digest stepBytes<>wordBE 8 100<>B.singleton 4))
        in (next,trace++select++map event [0..9]++[(10,0,payload),event 11,event 205,
          (208,1,entry),(208,2,stepBytes)])
    transaction (state,trace) (t,outputs) = foldl advance
      (state,trace++[(201,t,B.empty)]) [(t,o,k) | (o,k)<-zip [0..] outputs]
    (result,effects)=foldl transaction (previous,[event 200]) (zip [0..] rows)

exercise :: Bool -> [[Word8]] -> Int -> Maybe (Word32,B.ByteString)
  -> IO (Either String Bool,[Event],Maybe B.ByteString,String)
exercise cursor rows fault altered = do
  events <- newIORef []
  selected <- newIORef (Nothing :: Maybe (Word64,Word64))
  publication <- newIORef Nothing
  diagnostic <- newIORef "unchanged"
  let native step index input = do
        seen <- readIORef events
        modifyIORef' events (++[(step,index,input)])
        when (length seen==fault) (ioError (userError "native source failure"))
        unless (index==0 || step `elem` [201,202,208]) (error "unexpected callback index")
        selection <- readIORef selected
        let (t,o)=maybe (error "output not selected") id selection
            kind=rows!!fromIntegral t!!fromIntegral o
        normal <- case step of
          100 -> pure (B.singleton 1)
          101 -> pure (B.singleton 1)
          102 -> pure header
          103 -> pure economics
          104 -> pure pin
          105 -> pure asset
          106 -> pure previous
          107 -> pure (txid 0<>B.replicate 32 8<>B.replicate 16 0)
          200 -> pure (wordBE 8 (fromIntegral (length rows)))
          201 -> pure (wordBE 8 (fromIntegral (length (rows!!fromIntegral index))))
          202 -> do
            unless (B.length input==8) (error "selection size")
            writeIORef selected (Just (index,fromInteger (B.foldl' (\n b -> n*256+fromIntegral b) 0 input)))
            pure (B.singleton 1)
          203 -> pure (case kind of 1 -> script; 2 -> B.pack [106,29,69,67,88,67]; _ -> B.empty)
          204 -> pure (B.pack [106,29,69,67,88,67,3]<>B.replicate 24 0)
          205 -> pure (txid t)
          206 -> pure (if any (elem 2) rows then txid 0<>B.replicate 24 0 else B.replicate 56 0)
          207 -> writeIORef publication (Just input) >> pure (B.singleton 1)
          208 -> pure (if index==0 then pin else digest input)
          8 -> pure pin
          9 -> pure script
          10 -> do
            unless (input==payload) (error "incorrect signed payload")
            pure (B.cons 1 metadata)
          11 -> pure (wordLE 8 100)
          13 -> writeIORef diagnostic (C.unpack input) >> pure (B.singleton 1)
          _ | step<=7 || step==14 -> pure (B.singleton 1)
          _ -> error "unexpected callback step"
        pure $ case altered of
          Just (changed,bytes) | step==changed -> bytes
          _ -> normal
  outcome <- try (execute (H.ForcedBlockSession native) (if cursor then H.CheckBlockCursor else H.AppendBlockSource))
  trace <- readIORef events
  output <- readIORef publication
  message <- readIORef diagnostic
  pure (either (Left . show . (id :: SomeException -> SomeException)) Right outcome,trace,output,message)

generated :: Property
generated = forAll (resize 4 (listOf (resize 5 (listOf (elements [0,1]))))) $ \rows -> ioProperty $ do
  let (trace,state)=reference rows
  (result,observed,output,message)<-exercise False rows (-1) Nothing
  pure (conjoin [result===Right True,observed===trace,output===Just state,message==="unchanged"])

faults :: Property
faults = once $ ioProperty $ do
  checks <- forM [[],[[]],[[0,1],[1,0]],[[2]],[[2,2]],[[2,2,2]]] $ \rows ->
    forM [False,True] $ \cursor -> do
      (_,trace,_,_)<-exercise cursor rows (-1) Nothing
      forM [0..length trace-1] $ \fault -> do
        (result,observed,output,_)<-exercise cursor rows fault Nothing
        pure (counterexample (show (cursor,rows,fault)) (conjoin
          [property (isLeft result),observed===take (fault+1) trace,output===Nothing]))
  pure (conjoin (concat (concat checks)))

frames :: Property
frames = once $ ioProperty $ do
  let sourceSizes=[(102,138),(103,259),(104,32),(105,32),(106,145),(200,8),(201,8),(205,32),(208,32)]
      badSized=[(step,B.replicate size 1) | (step,size0)<-sourceSizes,size<-[0,size0-1,size0+1]]
      badBool=[(step,bytes) | step<-[100,101,202],bytes<-[B.empty,B.singleton 2,B.pack [0,1]]]
      variants=badSized++badBool++[(102,B.take 137 header<>B.singleton 2)]
  (_,trace,_,_)<-exercise False [[1]] (-1) Nothing
  checks<-forM variants $ \changed@(step,_) -> do
    (result,observed,output,_)<-exercise False [[1]] (-1) (Just changed)
    pure (counterexample (show changed) (conjoin [property (isLeft result),output===Nothing,
      observed===take (1+length (takeWhile (\(s,_,_) -> s/=step) trace)) trace]))
  cursorChecks<-forM [0,55,57] $ \size -> do
    (result,trace0,_,_)<-exercise True [[2]] (-1) (Just (206,B.replicate size 1))
    pure (conjoin [property (isLeft result),trace0===[event 206]])
  absent<-mapM (\mode -> FFI.elements_hs_exchange_session mode nullFunPtr nullPtr) [2,3,maxBound]
  pure (conjoin (checks++cursorChecks++[absent===replicate 3 (-1)]))

rejections :: Property
rejections = once $ ioProperty $ do
  let cases=[(100,B.singleton 0,"ECXFv3 carry requires"),(101,B.singleton 0,"ECXFv3 carry requires"),
        (102,B.replicate 8 255<>B.drop 8 header,"ECXFv3 carry requires"),
        (104,B.replicate 32 0,"ECXFv3 carry economics"),
        (105,B.replicate 32 0,"ECXFv3 carry economics"),
        (106,B.replicate 145 0,"ECXFv3 previous header"),
        (0,B.singleton 0,"Exact forced admission backend"),
        (10,B.singleton 0,"Exact forced canonical codec"),
        (11,wordLE 8 106,"Exact forced request is outside")]
  (_,trace,_,_)<-exercise False [[1]] (-1) Nothing
  checks<-forM cases $ \(step,bytes,message) -> do
    (result,observed,output,diagnostic)<-exercise False [[1]] (-1) (Just (step,bytes))
    pure (conjoin [result===Right False,output===Nothing,
      property (take (length message) diagnostic==message),
      observed===take (1+length (takeWhile (\(s,_,_) -> s/=step) trace)) trace++[(13,0,C.pack diagnostic)]])
  cursorChecks<-forM [1,2,3] $ \count -> do
    (result,trace0,output,_)<-exercise True [replicate count 2] (-1) Nothing
    let profileReads=length [() | (14,_,_)<-trace0]
    pure (conjoin [result===Right (count==1),output===Nothing,profileReads===count])
  pure (conjoin (checks++cursorChecks))

newtype Probe = Probe (IORef [(Word64,Word64)])
instance H.BlockOutputs Probe where
  blockTransactions _ = pure 3
  transactionOutputs _ index = pure (index+1)
  selectBlockOutput (Probe events) tx output = modifyIORef' events (++[(tx,output)])
  selectedMarker _ = error "fold does not inspect markers"
  selectedCursorProfile _ = error "fold does not validate profiles"
  selectedTransaction _ = error "fold does not inspect transactions"
  selectedScript _ = error "fold does not inspect scripts"
  selectedAdmission _ = error "fold does not authenticate"
  expectedCursor _ = error "fold does not inspect cursor"

reuse :: Property
reuse = once $ ioProperty $ do
  checks<-forM [-1..5] $ \fault -> do
    events<-newIORef []
    result<-runExceptT (H.foldBlockOutputs (Probe events) (0::Int) $ \n _ -> do
      when (n==fault) (throwE (Just "stop"))
      liftIO (pure (n+1)))
    trace<-readIORef events
    let expected=[(0,0),(1,0),(1,1),(2,0),(2,1),(2,2)]
    pure (conjoin [result===if fault<0 then Right 6 else Left (Just "stop"),
      trace===if fault<0 then expected else take (fault+1) expected])
  pure (conjoin (checks++[property (isNothing (interpret
    (SomeOperation (Check (E.Groth16Header 0 B.empty))) (undefined :: DSL H.ForcedBlockSession)))]))

properties :: [(String,Property)]
properties = [("forced block / ordered source workflow",generated),
  ("forced block / every native exception prefix",faults),
  ("forced block / strict native frames",frames),
  ("forced block / first error and complete cursor scan",rejections),
  ("forced block / reusable capability fold and lazy mismatch",reuse)]
