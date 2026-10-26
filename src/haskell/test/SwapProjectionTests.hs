-- Structural/ABI tests; the recording pairing callback is not a real proof.
module Main where

import Control.Monad (unless, forM_)
import Control.Exception (try, SomeException)
import Control.Operation.Validation
import qualified Bmm
import qualified Data.ByteString as B
import Data.Bits (xor)
import Data.IORef
import Data.Word (Word64, Word32, Word8)
import Drivechain (elements_hs_canonical_values, elements_hs_exchange_capital, elements_hs_exchange_successor_binding)
import Exchange
import Foreign.Marshal.Array (allocaArray, withArray, peekArray, pokeArray)
import Foreign.Ptr (castPtr, plusPtr)
import System.Environment (getArgs)
import Withdrawal (wordBE)

assert :: String -> Bool -> IO ()
assert label ok = unless ok (error label)

replace :: Int -> B.ByteString -> B.ByteString -> B.ByteString
replace offset value input = B.take offset input <> value <> B.drop (offset+B.length value) input

data Fingerprint = Fingerprint Word64 Word32
instance Bmm.FingerprintSource Fingerprint where
  fingerprintNumber (Fingerprint enabled _) group index
    | group==0 && index<40 = pure (if index==39 then enabled else 0)
    | otherwise = error "unexpected fingerprint number"
  fingerprintBytes (Fingerprint _ changed) index
    | index<67 = pure (replicate 32 (if index==changed then 2 else 1))
    | otherwise = error "unexpected fingerprint bytes"

main :: IO ()
main = do
  let hashes=B.concat [B.replicate 32 value | value<-[1..40]]
      scalars=B.concat (map (wordBE 8) [30,31,32,100,90,110,2100000000000000,100,2099999999999900,28,0,31])
      signed=B.replicate 15 255 <> B.singleton 223
      wide=B.concat (map (wordBE 16) [8,7,8,10,9,1000,34,9000000,11250,26,27,40,39,38])
      old=B.pack [0,0,0,23] <> hashes <> scalars <> signed <> wide <> B.pack [255,255,255,156,1,0,1]
      previous=B.replicate 32 41
      next=B.replicate 32 42
      values=replace 0 (wordBE 4 24) old <> previous <> next <> B.pack [0,1]
      program=B.concat (map (wordBE 4) [1..8])
      digest=B.replicate 32 43
      annex=B.pack [69,67,88,83,80,49,0,7,2,1,0] <> program <> digest <>
        wordBE 4 356 <> B.replicate 356 165 <> values
      hash input=pure (if input==values then digest else B.replicate 32 0)
      contextHashes=B.concat [B.take 32 (B.drop offset values) | offset<-[36,100,132,164]] <> previous <> B.take 32 (B.drop 1252 values)
      context=[30,31,32,0]
      mutate offset input=replace offset (B.singleton (B.index input offset `xor` 1)) input
  files<-getArgs
  forM_ files $ \path -> do
    independent<-B.readFile path
    assert "independent Rust/Python public values are byte-identical" (independent==values)
  assert "frozen V23 remains canonical" (B.length old==1627 && validate (CanonicalPublicValues 23 old))
  assert "V24 length and canonical fields" (B.length values==1693 && validate (CanonicalPublicValues 24 values))
  assert "exact predecessor context" (validate (SwapSuccessorBinding values contextHashes context)==0)
  assert "V24 cannot impersonate V23" (not (validate (CanonicalPublicValues 23 values)))
  assert "V23 cannot impersonate V24" (not (validate (CanonicalPublicValues 24 old)))
  forM_ [0..1692] $ \size ->
    assert "all truncated values rejected" (not (validate (CanonicalPublicValues 24 (B.take size values))))
  forM_ [1627,1659] $ \offset ->
    assert "zero bridge rejected" (not (validate (CanonicalPublicValues 24 (replace offset (B.replicate 32 0) values))))
  forM_ [1691,1692] $ \offset ->
    assert "nonboolean flag rejected" (not (validate (CanonicalPublicValues 24 (replace offset (B.singleton 2) values))))
  forM_ ([36..67]++[100..195]++[1252..1283]++[1284..1307]++[1627..1658]++[1691]) $ \offset ->
    assert "prior state/header/transaction/BMM/bridge/flag bound"
      (validate (SwapSuccessorBinding (mutate offset values) contextHashes context)/=0)
  assert "same proof rejects a different actual source head"
    (validate (SwapSuccessorBinding values (mutate 160 contextHashes) context)/=0)
  assert "missing actual source head rejects"
    (validate (SwapSuccessorBinding values (replace 160 (B.replicate 32 0) contextHashes) context)/=0)
  let identities=program <> B.concat [B.take 32 (B.drop offset values) | offset<-[4,388,420,452,484,516]]
  assert "new profile identity dispatch" (validate (CapitalIdentity 3 program values identities)==0)
  assert "old profile rejects new bytes" (validate (CapitalIdentity 1 program values identities)/=0)
  assert "new profile rejects old bytes" (validate (CapitalIdentity 3 program old identities)/=0)
  B.useAsCString values $ \v -> do
    status<-elements_hs_canonical_values 24 1693 (castPtr v)
    oldStatus<-elements_hs_canonical_values 23 1693 (castPtr v)
    assert "canonical values ABI keeps profile separation" (status==1 && oldStatus==(-1))
    B.useAsCString contextHashes $ \h -> withArray context $ \c -> do
      bound<-elements_hs_exchange_successor_binding 2 1693 (castPtr v) (castPtr h) c
      assert "new context ABI checks exact predecessor" (bound==0)
    B.useAsCString program $ \p -> B.useAsCString (identities <> B.replicate 96 44) $ \e ->
      allocaArray 916 $ \output -> do
        pokeArray output (replicate 916 (165::Word8))
        projected<-elements_hs_exchange_capital 3 (castPtr p) 1693 (castPtr v) 320 (castPtr e) 914 (output `plusPtr` 1)
        result<-peekArray 916 output
        assert "new projection ABI writes exact capital prefix" (projected==0 && take 4 result==[165,4,0,1] && last result==165)
  let source=B.replicate 32 1 <> wordBE 16 2 <> wordBE 16 1
  assert "V24 retains successor bond source bounds"
    (validate (SourcePredecessor [1,2,1,1,0,0,0] source)==Right (B.take 48 source))
  calls<-newIORef (0::Int)
  let verify _ _ _=modifyIORef' calls (+1) >> pure True
      check input=validate (Groth16Proof 5 input program digest hash verify)
  forM_ [0..2127] $ \size -> check (B.take size annex) >>= assert "all truncated annexes reject"
    . not
  forM_ [0..1692] $ \offset -> check (mutate (435+offset) annex) >>= assert "every changed public byte rejects"
    . not
  forM_ [0..4] $ \kind -> do
    accepted<-validate (Groth16Proof kind annex program digest hash verify)
    assert "old verifiers never accept V24" (not accepted)
  count<-readIORef calls
  assert "rejected inputs never call pairing verifier" (count==0)
  check annex >>= assert "matching V24 reaches verifier"
  denied<-validate (Groth16Proof 5 annex program digest hash (\_ _ _ -> pure False))
  assert "pairing failure is not accepted" (not denied)
  assert "zero-length context rejects without forcing payload"
    (validate (SwapSuccessorBinding B.empty (error "hashes forced") (error "context forced"))==(-1))
  baseline<-Bmm.encodeFingerprint Bmm.ExchangeFormat (Fingerprint 0 maxBound)
  enabled<-Bmm.encodeFingerprint Bmm.ExchangeFormat (Fingerprint 1 maxBound)
  assert "runtime fingerprint binds candidate availability" (baseline/=enabled)
  forM_ [63..66] $ \offset -> do
    changed<-Bmm.encodeFingerprint Bmm.ExchangeFormat (Fingerprint 0 offset)
    assert "runtime fingerprint binds every candidate pin" (baseline/=changed)
  invalid<-try (Bmm.encodeFingerprint Bmm.ExchangeFormat (Fingerprint 2 maxBound)) :: IO (Either SomeException [Word8])
  assert "runtime fingerprint rejects nonboolean availability" (either (const True) (const False) invalid)
  putStrLn "PASS: V24 canonical codec, 1,693 mutations, 2,128 truncations, profile isolation, predecessor bindings and verifier short-circuiting"
