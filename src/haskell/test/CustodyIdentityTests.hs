{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module CustodyIdentityTests (properties) where

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
import Withdrawal (wordBE,wordLE)

type Event=(Word32,Word64,B.ByteString)
hash :: Word8 -> B.ByteString
hash=B.replicate 32
replace :: Int -> B.ByteString -> B.ByteString -> B.ByteString
replace at value bytes=B.take at bytes<>value<>B.drop (at+B.length value) bytes
be :: Int -> Integer -> B.ByteString
be width n=B.pack [fromInteger (n `div` 256^i `mod` 256) | i<-[width-1,width-2..0]]
pins,economics,genesis,values :: B.ByteString
pins=B.concat (map hash [1..11])
economics=replace 50 (hash 7) (B.replicate 259 0)
genesis=wordLE 2 6<>hash 20<>hash 21<>wordLE 4 0<>hash 22<>hash 23<>
  B.concat (map hash [1,9,2,3,4,5,6,7,8,12,12])<>B.replicate 32 0<>
  wordLE 8 0<>wordLE 8 1000<>B.singleton 0
values=foldl (\b (at,value)->replace at value b) (B.replicate 791 0)
  ([(0,wordBE 4 25)]++[(4+32*i,hash (fromIntegral (30+i))) | i<-[0..20]]++
   [(at,hash value) | (at,value)<-[(4,2),(68,22),(100,21),(228,23),(260,3),
     (292,4),(324,5),(420,6),(484,7),(516,8),(580,12),(612,12)]]++
   [(at,wordBE 8 1) | at<-[676,684,692,708,716,724,732,740]]++[(700,wordBE 8 1000)])

newtype Probe=Probe H.CustodyIdentitySession
  deriving (H.CustodyIdentityFacts,H.CustodyIdentityEffects)

run :: Int -> H.CustodyIdentitySession -> IO Bool
run 4 value=H.decodeCustodyIdentity (Probe value)
run mode value=maybe (error "identity dispatch mismatch") id $
  interpret (SomeOperation value) (case mode of
    0->H.CheckCustodyAvailability
    1->H.CheckProjectionIdentity
    2->H.CheckGenesisIdentity
    _->H.DecodeProjectionIdentity)

exercise :: Int -> B.ByteString -> [(Word32,B.ByteString)] -> Int
  -> IO (Either String Bool,[Event],Maybe B.ByteString)
exercise mode public changes fault=do
  events<-newIORef []
  published<-newIORef Nothing
  let native step index bytes=do
        before<-readIORef events
        modifyIORef' events (++[(step,index,bytes)])
        when (length before==fault) (ioError (userError "injected identity failure"))
        case lookup step changes of
          Just altered->pure altered
          Nothing->case step of
            0->pure (B.singleton 1)
            1->pure pins
            2->pure (B.concat (map hash [100..103]))
            3->pure economics
            4->pure (hash (if index==0 then 3 else 12))
            5->pure (hash 20)
            6->pure genesis
            7->pure (B.singleton 1)
            8->pure (B.singleton 0)
            9->pure (hash 21<>wordLE 4 0)
            10->pure (B.singleton 3<>hash 3<>hash 12<>B.replicate 16 0<>hash 12<>B.replicate 32 0)
            11->pure (hash 1<>public)
            12->writeIORef published (Just bytes) >> pure (B.singleton 1)
            13->pure (B.singleton 1)
            _->error "unexpected identity callback"
  result<-try (run mode (H.CustodyIdentitySession native))
  trace<-readIORef events
  output<-readIORef published
  pure (either (Left . show) Right (result::Either SomeException Bool),trace,output)

generated :: Property
generated=forAll ((,,,) <$> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary) $
  \(amount,serial,hi,lo) -> ioProperty $ do
    let count=toInteger (hi::Word64)*2^(64::Int)+toInteger (lo::Word64)
        public=replace 700 (wordBE 8 amount) $ replace 740 (wordBE 8 serial) $
          replace 748 (be 16 count<>be 16 count) values
        expected=replace 486 (be 16 count<>be 16 count<>wordLE 8 serial<>wordLE 8 amount) genesis
    (result,trace,output)<-exercise 3 public [] (-1)
    pure (conjoin [result===Right (serial/=0),
      output===(if serial==0 then Nothing else Just expected),
      map (\(s,_,_)->s) trace===(if serial==0 then [0,1,2,3,4,5,11,13] else [0,1,2,3,4,5,11,12])])

faults :: Property
faults=once $ ioProperty $ do
  checks<-forM [0..4] $ \mode->do
    (ok,trace,_)<-exercise mode values [] (-1)
    failures<-forM [0..length trace-1] $ \at->do
      (result,observed,published)<-exercise mode values [] at
      pure (conjoin [property (isLeft result),observed===take (at+1) trace,published===Nothing])
    pure (conjoin ((ok===Right True):failures))
  pure (conjoin checks)

frames :: Property
frames=once $ ioProperty $ do
  let fields=[(0,0,1),(0,1,352),(0,2,128),(0,3,259),(0,4,32),(1,5,32),
              (1,6,535),(2,7,1),(2,8,1),(2,9,36),(2,10,145),(3,11,823),(3,12,1)]
  checks<-forM [(mode,step,size) | (mode,step,width)<-fields,
      size<-[0,width-1,width+1],size/=width,not(step==11 && size==0)] $ \(mode,step,size)->do
    (result,trace,published)<-exercise mode values [(step,B.replicate size 0)] (-1)
    pure (conjoin [property (isLeft result),property (not (null trace)),published===Nothing])
  flags<-forM [0,7,8] $ \step->do
    (result,_,_)<-exercise 2 values [(step,B.singleton 2)] (-1)
    pure (property (isLeft result))
  effects<-forM [(12,[]),(13,[(11,B.empty)])] $ \(step,setup)->do
    (result,_,published)<-exercise 3 values ((step,B.singleton 0):setup) (-1)
    pure (conjoin [property (isLeft result),published===Nothing])
  absent<-mapM (\mode->FFI.elements_hs_exchange_session mode nullFunPtr nullPtr) [6..9]
  pure (conjoin (checks++flags++effects++[absent===replicate 4 (-1)]))

shortCircuit :: Property
shortCircuit=once $ ioProperty $ do
  let cases=[(0,[(0,B.singleton 0)],[0]),
             (0,[(1,replace 32 (hash 0) pins)],[0,1]),
             (0,[(2,hash 1<>B.replicate 96 0)],[0,1,2]),
             (0,[(4,hash 99)],[0,1,2,3,4]),
             (2,[(7,B.singleton 0)],[0,1,2,3,4,7]),
             (2,[(8,B.singleton 1)],[0,1,2,3,4,7,8]),
             (2,[(6,replace 0 (wordLE 2 7) genesis)],[0,1,2,3,4,7,8,5,6]),
             (2,[(9,hash 21<>wordLE 4 1)],[0,1,2,3,4,7,8,5,6,9]),
             (3,[(5,hash 0)],[0,1,2,3,4,5,13]),
             (3,[(11,B.empty)],[0,1,2,3,4,5,11,13])]
  checks<-forM cases $ \(mode,changes,expected)->do
    (result,trace,published)<-exercise mode values changes (-1)
    pure (conjoin [result===Right False,map (\(s,_,_)->s) trace===expected,published===Nothing])
  (_,trace,_)<-exercise 3 values [(11,B.empty)] (-1)
  pure (conjoin (checks++[last trace===(13,0,C.pack "exact custody requires canonical annex8/PublicValues25")]))

reuse :: Property
reuse=once $ ioProperty $ do
  direct<-exercise 3 values [] (-1)
  alternative<-exercise 4 values [] (-1)
  let mismatch=isNothing (interpret (SomeOperation (Check (H.CustodyValues B.empty)))
        (undefined::DSL H.CustodyIdentitySession))
  pure (conjoin [direct===alternative,property mismatch])

properties :: [(String,Property)]
properties=[("custody identity / full-width projection and scalar encoding",generated),
  ("custody identity / exception prefixes and atomic publication",faults),
  ("custody identity / strict frames and missing callbacks",frames),
  ("custody identity / lazy rejection and diagnostics",shortCircuit),
  ("custody identity / capability reuse and lazy payload mismatch",reuse)]

