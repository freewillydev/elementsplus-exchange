module Main where
import Control.Monad (forM_,unless)
import Control.Operation.Validation
import qualified Data.ByteString as B
import Data.Word (Word8)
import ExchangeForcedV3
import ExchangeForcedV3Block
import Drivechain (elements_hs_exchange_forced_v3_block_bytes)
import Foreign.Marshal.Array (allocaArray,peekArray,pokeArray)
import Foreign.Ptr (castPtr)
import System.Environment (getArgs)
import Withdrawal (wordBE)
assert :: String -> Bool -> IO ()
assert label good=unless good (error label)
run :: Integer -> B.ByteString -> Maybe B.ByteString
run mode bytes=validate(ForcedV3BlockBytes(fromInteger mode,bytes))
main :: IO ()
main=do
  [base,derived]<-getArgs
  state<-B.readFile(base<>"/state.bin")
  payload<-B.readFile(base<>"/payload.bin")
  expected<-B.readFile(derived<>"/entry.bin")
  root<-B.readFile(derived<>"/entry-root.bin")
  next<-B.readFile(derived<>"/next-state.bin")
  let source=state<>B.replicate 32 8<>wordBE 8 4<>wordBE 8 100<>wordBE 4 2<>payload
      advance=state<>root<>wordBE 8 100<>B.singleton 4
  assert "actual shared Rust entry encoding" (run 0 source==Just expected)
  assert "actual shared Rust appended state" (run 1 advance==Just next)
  forM_ [0..B.length source-1] $ \n -> assert "entry truncation rejects" (run 0 (B.take n source)==Nothing)
  let wide count=B.take 65 state<>count<>slice 33 32 state<>count<>B.drop 129 state
      max64=wordBE 8 0<>wordBE 8 maxBound
      rolling=wide max64
      rollover=run 1 (rolling<>root<>wordBE 8 100<>B.singleton 4)
  assert "append rolls high64 without truncation" (fmap (slice 65 16) rollover==Just(wordBE 8 1<>wordBE 8 0))
  assert "u128 overflow rejects" (run 1(wide(B.replicate 16 255)<>root<>wordBE 8 100<>B.singleton 4)==Nothing)
  let fields=wordBE 8 (2^(32::Int))<>wordBE 8 2<>wordBE 8 9
      txid=B.replicate 32 7
      script=forcedV3CursorBytes (2^(32::Int)) 2 9
      binding=txid<>txid<>fields<>wordBE 8 1<>script
  assert "exact cursor/actual txid" (run 3 binding==Just(B.singleton 1))
  forM_ [0..B.length binding-1] $ \i -> do
    let changed=B.take i binding<>B.singleton(if B.index binding i==255 then 0 else B.index binding i+1)<>B.drop(i+1)binding
    assert "every cursor binding byte checked" (run 3 changed==Nothing)
  assert "duplicate cursor rejects" (run 3(txid<>txid<>fields<>wordBE 8 2<>script)==Nothing)
  assert "carry requires no marker" (run 3(B.replicate 96 0)==Just(B.singleton 1))
  assert "unavailable fresh proof rejects" (run 4(B.singleton 1)==Nothing && run 4(B.singleton 0)==Just(B.singleton 1))
  forM_ [B.pack[106,29],B.pack[106,76,29],B.pack[106,77,29,0],B.pack[106,78,29,0,0,0]] $ \prefix -> do
    assert "all reserved cursor pushes classified" (run 2(prefix<>B.pack[69,67,88,67])==Just(B.singleton 2))
    assert "all reserved forced pushes classified" (run 2(prefix<>B.pack[69,67,88,70])==Just(B.singleton 1))
  B.useAsCString source $ \input -> allocaArray 4201 $ \output -> do
    pokeArray output(replicate 4201 (165::Word8))
    size<-elements_hs_exchange_forced_v3_block_bytes 0 (fromIntegral(B.length source)) (castPtr input) 4199 output
    actual<-peekArray 4201 output
    assert "entry ABI guarded output" (fromIntegral size==B.length expected && B.pack(take(fromIntegral size)actual)==expected && all(==165)(drop(fromIntegral size)actual))
  putStrLn "PASS: actual shared Rust entry/state vectors, wide rollover, strict actual-tx cursor, unavailable activation and ABI guards"
