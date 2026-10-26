module CustodyPolicyTests (properties) where

import Control.Exception (SomeException,try)
import Control.Monad (forM,when)
import Control.Operation
import Control.Operation.Validation
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.Either (isLeft)
import Data.IORef
import Data.Maybe (isNothing)
import Data.Word (Word8,Word32,Word64)
import qualified Drivechain as FFI
import qualified ExchangeCustody as H
import Foreign.Ptr (nullFunPtr,nullPtr)
import Test.QuickCheck hiding (output)
import Withdrawal (wordBE)

type Event=(Word32,Word64,B.ByteString)
hash :: Word8 -> B.ByteString
hash=B.replicate 32
outpoint :: Word8 -> Word64 -> B.ByteString
outpoint h n=hash h<>wordBE 4 n
input :: Word8 -> B.ByteString
input kind=case kind `mod` 5 of
  0 -> outpoint 1 0
  1 -> outpoint 1 1
  2 -> outpoint 2 0
  3 -> outpoint 2 2
  _ -> outpoint 3 0
diagnostic :: B.ByteString
diagnostic=C.pack "custody reserved singleton/vault spend must preserve the coupled pair"

reference :: [Word8] -> (Bool,[Event])
reference raw=(ok,prefix++scan++[(16,0,diagnostic) | not ok])
  where
    kinds=map (`mod` 5) raw
    reserved=length (filter (<2) kinds)
    pair=take 2 kinds==[0,1] && reserved==2
    descendant=2 `elem` kinds
    ok=not descendant && (reserved==0 || pair)
    simple steps=[(s,0,B.empty) | s<-steps]
    prefix=simple [0,1,3,19,4]++[(5,i,B.empty) | i<-take (length kinds) [0..]]++simple [6..13]
    visit _ []=[]
    visit i (k:ks)=(5,i,B.empty):
      if k==3 then visit (i+1) ks else (14,i,B.empty):
        if k==2 then [(15,0,B.empty),(15,1,B.empty)] else visit (i+1) ks
    scan=(4,0,B.empty):visit 0 kinds

exercise :: [Word8] -> Int -> Maybe (Word32,B.ByteString)
  -> IO (Either String Bool,[Event])
exercise rows fault alteration=do
  events<-newIORef []
  let native step index bytes=do
        before<-readIORef events
        modifyIORef' events (++[(step,index,bytes)])
        when (length before==fault) (ioError (userError "injected native failure"))
        case alteration of
          Just (changed,replacement) | changed==step -> pure replacement
          _ -> pure $ case step of
            0 -> B.pack [1,1]<>wordBE 8 1<>wordBE 8 1
            1 -> B.singleton 1
            3 -> B.singleton 1
            19 -> outpoint 1 0<>hash 4<>wordBE 8 1000<>hash 5
            4 -> wordBE 8 (fromIntegral (length rows))
            5 -> input (rows!!fromIntegral index)
            6 -> wordBE 8 2
            7 -> B.singleton 1
            8 -> hash 4
            9 -> B.singleton 1
            10 -> wordBE 8 1000
            11 -> B.singleton 1
            12 -> hash 5
            13 -> B.singleton 1
            14 -> if rows!!fromIntegral index `mod` 5==2 then hash 2<>wordBE 8 2 else B.empty
            15 -> outpoint 1 index
            16 -> B.singleton 1
            _ -> error "unexpected native read"
  result<-try (maybe (error "dispatch mismatch") id (interpret
    (SomeOperation (H.CustodyPolicySession native)) H.CheckReservedPolicy))
  trace<-readIORef events
  pure (either (Left . show) Right (result::Either SomeException Bool),trace)

generated :: Property
generated=forAll (resize 30 arbitrary) $ \rows -> ioProperty $ do
  (result,trace)<-exercise rows (-1) Nothing
  let (expected,events)=reference rows
  pure (conjoin [result===Right expected,trace===events])

faults :: Property
faults=once $ ioProperty $ do
  let rows=[0,1,3,4,2,4];(_,trace)=reference rows
  results<-forM [0..length trace-1] $ \fault -> do
    (result,observed)<-exercise rows fault Nothing
    pure (conjoin [property (isLeft result),observed===take (fault+1) trace])
  pure (conjoin results)

frames :: Property
frames=once $ ioProperty $ do
  let fields=[(0,18),(1,1),(3,1),(19,108),(4,8),(5,36),(6,8),(7,1),(8,32),
              (9,1),(10,8),(11,1),(12,32),(13,1),(14,40),(15,36),(16,1)]
      (_,trace)=reference [2]
  results<-forM [(step,size) | (step,width)<-fields,size<-[0..width+1],size/=width,
                  not (step==14 && size==0)] $ \(step,size) -> do
    (result,observed)<-exercise [2] (-1) (Just (step,B.replicate size 1))
    pure (conjoin [property (isLeft result),
      observed===take (1+length (takeWhile (\(s,_,_)->s/=step) trace)) trace])
  absent<-mapM (\mode -> FFI.elements_hs_exchange_session mode nullFunPtr nullPtr) [4,5,6,maxBound]
  pure (conjoin (results++[absent===replicate 4 (-1)]))

shortCircuit :: Property
shortCircuit=once $ ioProperty $ do
  let cases=[(7,B.singleton 0,[8..12]),(8,hash 9,[9..12]),
             (9,B.singleton 0,[10..12]),(10,wordBE 8 maxBound,[11,12]),
             (11,B.singleton 0,[12])]
  checks<-forM cases $ \(step,bytes,skipped) -> do
    (result,trace)<-exercise [0,1,4] (-1) (Just (step,bytes))
    pure (conjoin [result===Right False,property (all (\(s,_,_)->s `notElem` skipped) trace),
      property (any (\(s,_,_)->s==14) trace),last trace===(16,0,diagnostic)])
  disabled<-exercise [2] (-1) (Just (0,B.pack [0,1]<>wordBE 8 1<>wordBE 8 1))
  missing<-exercise [2] (-1) (Just (1,B.singleton 0))
  pure (conjoin (checks++[disabled===(Right True,[(0,0,B.empty)]),
    missing===(Right False,[(0,0,B.empty),(1,0,B.empty),(16,0,C.pack
      "custody reserved-pair policy lacks authenticated predecessor")])]))

budget :: Property
budget=forAll ((,,,) <$> chooseInteger (0,450) <*> chooseInteger (0,450) <*>
  chooseInteger (0,66) <*> elements [0,99,100,101,toInteger (maxBound::Word64)]) $ \(count,cursor,used,parent) ->
  let state=B.singleton 3<>hash 7<>hash 8<>be 16 count<>hash 8<>be 16 cursor<>
        be 8 100<>be 4 used<>be 4 0
      bytes=state<>be 8 parent
      accepted=[n | n<-[0..64],validate (H.CustodyBudget (bytes<>wordBE 8 n))]
      expected=if null accepted then Nothing else Just (last accepted)
      be :: Int -> Integer -> B.ByteString
      be width n=B.pack [fromInteger (n `div` 256^i `mod` 256) | i<-[width-1,width-2..0]]
  in H.custodyBudget bytes===expected

newtype Probe=Probe (IORef [Word64])
instance H.CustodyInputs Probe where
  custodyInputCount _=pure 3
  custodyInput (Probe events) i=modifyIORef' events (++[i]) >> pure (outpoint 1 i)

reuse :: Property
reuse=once $ ioProperty $ do
  events<-newIORef []
  values<-H.foldCustodyInputs (Probe events) [] (\xs _ bytes -> pure (xs++[bytes]))
  folded<-readIORef events
  writeIORef events []
  found<-H.anyCustodyInput (Probe events) (\i _ -> pure (i==1))
  stopped<-readIORef events
  let mismatch=isNothing (interpret (SomeOperation (Check (H.CustodyValues B.empty)))
        (undefined :: DSL H.CustodyPolicySession))
  pure (conjoin [values===map (outpoint 1) [0..2],folded===[0..2],property found,
    stopped===[0,1],property mismatch])

properties :: [(String,Property)]
properties=[("custody policy / complete scan and lookup order",generated),
  ("custody policy / every native exception prefix",faults),
  ("custody policy / strict frames and absent bridge",frames),
  ("custody policy / lazy output checks and first error",shortCircuit),
  ("custody policy / direct budget equals accepted search",budget),
  ("custody policy / reusable input fold and lazy mismatch",reuse)]
