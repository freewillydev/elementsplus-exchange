-- Codec/policy/ABI tests. Metadata fixtures do not substitute for signatures.
module Main where
import Control.Monad (forM_,unless)
import Control.Operation.Validation
import qualified Bmm
import qualified Data.ByteString as B
import Data.Bits ((.&.), (.|.), clearBit, testBit)
import Data.Word (Word64,Word8)
import ExchangeForcedV3
import Drivechain (elements_hs_exchange_forced_v3_bytes,elements_hs_exchange_forced_v3_append)
import Foreign.Marshal.Array (allocaArray,peekArray,pokeArray,withArray)
import Foreign.Ptr (castPtr,nullPtr)
import System.Environment (getArgs)
import Withdrawal (wordBE)

assert :: String -> Bool -> IO ()
assert label condition=unless condition (error label)

main :: IO ()
main = do
  vectorDirs<-getArgs
  forM_ vectorDirs $ \directory -> do
    pin<-B.readFile (directory<>"/pin.bin")
    script<-B.readFile (directory<>"/script.bin")
    payload<-B.readFile (directory<>"/payload.bin")
    metadata<-B.readFile (directory<>"/metadata.bin")
    state<-B.readFile (directory<>"/state.bin")
    cursor<-B.readFile (directory<>"/cursor.bin")
    assert "independent Rust signed frame" (validate (ForcedV3Frame pin script)==Just payload)
    assert "independent Rust signature metadata" (validate (ForcedV3Admission 100 4 metadata))
    assert "independent Rust wide state" (validate (ForcedV3State pin state))
    assert "independent Rust wide cursor" (validate (ForcedV3Cursor cursor)==Just (2^(32::Int),2,9))
  forM_ [0,16384,0x001f4000,0xc01f4000] $ \version ->
    forM_ [1,3,16,33,35] $ \flags -> do
      let old=validate (Bmm.HeaderLayout version flags)
          withoutBit=validate (Bmm.HeaderLayout (clearBit version 14) flags)
          fresh=validate (Bmm.HeaderLayout version (flags .|. 64))
      assert "historic bit14 never changes legacy fields" (fmap snd old==fmap snd withoutBit)
      assert "legacy profile never interprets fresh state" (maybe False (\(_,fields) -> fields .&. 512==0) old)
      assert "explicit fresh profile changes only new state field" (case (old,fresh) of
        (Just (v,a),Just (w,b)) -> v==w && b==a .|. (if testBit version 14 then 512 else 0)
        _ -> False)
  forM_ [48,63,112,127,128] $ \flags ->
    assert "undefined header modes reject" (validate (Bmm.HeaderLayout 16384 flags)==Nothing)
  forM_ [0,1,maxBound] $ \high -> forM_ [0,1,maxBound] $ \low -> do
    let script=forcedV3CursorBytes high low maxBound
    assert "all128 cursor bits roundtrip" (validate (ForcedV3Cursor script)==Just (high,low,maxBound))
    forM_ [0..30] $ \n -> assert "cursor truncation rejects" (validate (ForcedV3Cursor (B.take n script))==Nothing)
    forM_ [0,1,2,4] $ \version ->
      assert "old/unknown cursor version rejects" (validate (ForcedV3Cursor (B.take 6 script<>B.singleton version<>B.drop 7 script))==Nothing)
    assert "nonminimal cursor rejects" (validate (ForcedV3Cursor (B.pack [106,76,29]<>B.drop 2 script))==Nothing)
    B.useAsCString script $ \input -> allocaArray 26 $ \output -> do
      pokeArray output (replicate 26 (165::Word8))
      result<-elements_hs_exchange_forced_v3_bytes 2 31 (castPtr input) nullPtr 24 output
      actual<-peekArray 26 output
      assert "cursor ABI exact24 bytes" (result==24 && B.pack (take 24 actual)==B.drop 7 script && drop 24 actual==[165,165])
  let pin=B.replicate 32 1
      wide n=wordBE 8 (fromInteger (n `div` 2^(64::Int)))<>wordBE 8 (fromInteger n)
      state count cursor admissions work = B.singleton 3<>pin<>B.replicate 32 2<>wide count<>
        B.replicate 32 (if count==cursor then 2 else 3)<>wide cursor<>
        wordBE 8 (if count==0 then 0 else 100)<>wordBE 4 admissions<>wordBE 4 work
      max128=2^(128::Int)-1 :: Integer
  forM_ [0,1,2^(64::Int),max128] $ \count -> do
    let bytes=state count count (if count==0 then 0 else 1) 0
    assert "state preserves wide count/cursor" (validate (ForcedV3State pin bytes))
    forM_ [0..144] $ \n -> assert "state truncation rejects" (not (validate (ForcedV3State pin (B.take n bytes))))
  assert "cursor cannot exceedcount" (not (validate (ForcedV3State pin (state 3 4 1 0))))
  assert "persistedquota64" (not (validate (ForcedV3State pin (state 100 100 65 0))))
  assert "persistedwork64" (not (validate (ForcedV3State pin (state 100 100 1 65))))
  assert "countcarry advances highword" (validate (ForcedV3Append [0,maxBound,0,maxBound,100,1,0,101,4])==Just [1,0,1,0])
  assert "u128 overflow rejects" (validate (ForcedV3Append [maxBound,maxBound,maxBound,maxBound,100,1,0,101,4])==Nothing)
  assert "draining never resets admissions" (validate (ForcedV3Append [0,64,0,64,100,64,0,100,4])==Nothing)
  assert "draining never resets work" (validate (ForcedV3Append [0,1,0,1,100,1,64,100,0])==Nothing)
  assert "pending witness cap" (validate (ForcedV3Append [0,448,0,0,100,1,0,101,4])==Nothing)
  withArray [0,maxBound,0,maxBound,100,1,0,101,4] $ \input -> allocaArray 5 $ \output -> do
    pokeArray output (replicate 5 (777::Word64))
    result<-elements_hs_exchange_forced_v3_append input output
    actual<-peekArray 5 output
    assert "append ABI preserves128 carry and outputguard" (result==1 && actual==[1,0,1,0,777])
  let metadata kind first second=B.pack [1,kind]<>B.replicate 32 9<>wordBE 8 first<>wordBE 8 second
  assert "account expiry strict parent inclusive cap" (validate (ForcedV3Admission 100 3 (metadata 3 (101::Word64) 112)))
  forM_ [(100,112),(101,113),(102,101)] $ \(a,b) ->
    assert "account expiry badedge" (not (validate (ForcedV3Admission 100 3 (metadata 3 (a::Word64) b))))
  assert "clearing expiry inclusive parent exclusive cap" (validate (ForcedV3Admission 100 4 (metadata 4 (111::Word64) 0)))
  assert "clearing expires before cap" (not (validate (ForcedV3Admission 100 4 (metadata 4 (112::Word64) 0))))
  assert "parent addition overflow" (not (validate (ForcedV3Admission maxBound 2 (metadata 2 (0::Word64) maxBound))))
  forM_ [40,75,76,255,256,4104] $ \size -> do
    let body=pin<>B.replicate (size-40) 7
        payload=B.pack [69,67,88,70,3,4]<>wordBE 2 (fromIntegral (B.length body))<>body
        push | size<=75=B.pack [106,fromIntegral size]
             | size<=255=B.pack [106,76,fromIntegral size]
             | otherwise=B.pack [106,77,fromIntegral size,fromIntegral (size `div` 256)]
    assert "minimal frame allwidths" (validate (ForcedV3Frame pin (push<>payload))==Just payload)
    assert "frame wrongpin" (validate (ForcedV3Frame (B.replicate 32 2) (push<>payload))==Nothing)
  putStrLn "PASS: exact forcedV3 framing, height policy,145-byte state,128-bit cursor/carry, persistent budgets and ABI guards"
