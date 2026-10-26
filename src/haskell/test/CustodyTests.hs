module Main where

import Control.Monad (forM_,unless)
import Control.Operation.Validation
import qualified Data.ByteString as B
import Data.Word (Word8)
import ExchangeCustody
import System.Environment (getArgs)

assert :: String -> Bool -> IO ()
assert label ok=unless ok (error label)
be :: Int -> Integer -> B.ByteString
be width n=B.pack [fromInteger (n `div` (256^i) `mod` 256) | i<-[width-1,width-2..0]]
h :: Word8 -> B.ByteString
h=B.replicate 32
replace :: Int -> B.ByteString -> B.ByteString -> B.ByteString
replace offset x b=B.take offset b<>x<>B.drop (offset+B.length x) b
values :: B.ByteString
values=be 4 25<>B.concat (map h [1..21])<>
  B.concat (map (be 8) [101,1000,77,900,100,90,110,1100,9])<>
  be 16 (2^(64::Int)+2)<>be 16 (2^(64::Int)+1)<>B.pack [0,0,1]<>be 8 100
previous :: B.ByteString
previous=h 2<>h 7<>h 29<>be 16 (2^(64::Int))<>be 8 8<>B.singleton 0
source :: B.ByteString
source=B.singleton 3<>h 9<>h 19<>be 16 (2^(64::Int)+2)<>h 29<>
  be 16 (2^(64::Int))<>be 8 101<>be 4 2<>be 4 0
anchor :: B.ByteString
anchor=h 4<>h 5<>h 6<>h 18<>be 8 101<>be 8 1000<>be 8 77
identity :: B.ByteString
identity=h 99<>h 99<>B.concat (map h [1,9,10,11,14,16,17])

main :: IO ()
main=do
  if and [validate (CustodyReservedSpend (B.pack [a,b,c,d])) == (d==0 && (a==0 || (b==1 && c==1))) |
            a<-[0,1],b<-[0,1],c<-[0,1],d<-[0,1]] &&
       not (validate (CustodyReservedSpend (B.pack [0,2,0,0])))
    then pure () else error "reserved pair policy"

  paths<-getArgs
  forM_ paths $ \path -> B.readFile path >>= \v -> assert "independent Rust791 vector" (validate (CustodyValues v))
  assert "canonical standalone statement" (validate (CustodyValues values))
  assert "independent pins" (validate (CustodyIdentity values identity))
  assert "full-width source continuity" (validate (CustodyTransition values previous source anchor))
  assert "carry preserves processed prefix" (validate (CustodyCarry previous source))
  forM_ [0..790] $ \n -> assert "all truncations reject" (not(validate(CustodyValues(B.take n values))))
  assert "trailing bytes reject" (not(validate(CustodyValues(values<>B.singleton 0))))
  forM_ [4,36..644] $ \offset ->
    assert "every required hash is nonzero" (not(validate(CustodyValues(replace offset (h 0) values))))
  forM_ [780,781,782] $ \offset ->
    assert "invalid enum/bool rejects" (not(validate(CustodyValues(replace offset (B.singleton 4) values))))
  assert "reversed execution band rejects" (not(validate(CustodyValues(replace 716 (be 8 101) values))))
  assert "cursor cannot exceed native head" (not(validate(CustodyValues(replace 764 (be 16 (2^(64::Int)+3)) values))))
  let drained=replace 783 (be 8 0) (replace 612 (h 19) (replace 764 (field 748 16 values) values))
  assert "drained prefix equals head" (validate(CustodyValues drained))
  assert "drained root mismatch rejects" (not(validate(CustodyValues(replace 612 (h 28) drained))))
  forM_ [0..287] $ \offset ->
    assert "all identity bytes bind" (not(validate(CustodyIdentity values (replace offset (B.singleton (B.index identity offset+1)) identity))))
  forM_ [0..151] $ \offset ->
    assert "all native anchor bytes bind" (not(validate(CustodyTransition values previous source (replace offset (B.singleton (B.index anchor offset+1)) anchor))))
  forM_ [0,32,64,96,104,112,120] $ \offset ->
    assert "prior projection lineage binds" (not(validate(CustodyTransition values (replace offset (B.singleton (B.index previous offset+1)) previous) source anchor)))
  assert "same proof different actual head rejects" (not(validate(CustodyTransition values previous (replace 33 (h 30) source) anchor)))
  assert "source configuration binds" (not(validate(CustodyTransition values previous (replace 1 (h 30) source) anchor)))
  assert "source processed root binds on carry" (not(validate(CustodyCarry previous (replace 81 (h 30) source))))
  assert "source processed cursor binds on carry" (not(validate(CustodyCarry previous (replace 113 (be 16 0) source))))
  assert "sequence cannot wrap" (not(validate(CustodyTransition (replace 740 (be 8 1) values) (replace 112 (be 8 (2^(64::Int)-1)) previous) source anchor)))
  let backlog after old remaining parent claimed consumed=source<>after<>
        B.concat(map (be 8) [old,remaining,parent,claimed])<>B.singleton consumed
      consumedOne=replace 113 (be 16 (2^(64::Int)+1)) source
      drainedSource=replace 113 (field 65 16 source) (replace 81 (field 33 32 source) source)
      appended=replace 65 (be 16 (2^(64::Int)+3)) drainedSource
  assert "carry before deadline" (validate(CustodyBacklog(backlog source 100 100 105 100 0)))
  assert "carry at deadline rejects" (not(validate(CustodyBacklog(backlog source 100 100 106 100 0))))
  assert "partial receipt must clear expired head" (not(validate(CustodyBacklog(backlog consumedOne 100 100 106 100 1))))
  assert "partial receipt authenticates younger remaining head" (validate(CustodyBacklog(backlog consumedOne 100 102 106 102 1)))
  assert "draining clears oldest" (validate(CustodyBacklog(backlog drainedSource 100 0 106 0 1)))
  assert "new admissions restart age only after prior drain" (validate(CustodyBacklog(backlog appended 100 0 106 106 1)))
  assert "host cannot fake receipt on carry" (not(validate(CustodyBacklog(backlog consumedOne 100 102 106 102 0))))
  assert "host cannot change oldest alone" (not(validate(CustodyBacklog(backlog source 100 100 105 105 0))))
  assert "remaining oldest cannot move backwards" (not(validate(CustodyBacklog(backlog consumedOne 100 99 105 99 1))))
  assert "pending root cannot carry zero age" (not(validate(CustodyBacklog(backlog source 0 0 105 0 0))))
  assert "pending budget accounts for current-parent quota" (validate(CustodyBudget(source<>be 8 101<>be 8 62)))
  assert "current-parent quota cannot reset" (not(validate(CustodyBudget(source<>be 8 101<>be 8 63))))
  assert "new parent restores tranche budget" (validate(CustodyBudget(source<>be 8 102<>be 8 64)))
  let saturated=replace 65 (be 16 (2^(64::Int)+448)) source
  assert "full pending queue admits zero" (validate(CustodyBudget(saturated<>be 8 102<>be 8 0)))
  assert "full pending queue refuses another" (not(validate(CustodyBudget(saturated<>be 8 102<>be 8 1))))
  putStrLn "PASS: standalone custody791 canonical/pin/lineage/native-source checks, full-width counters and exhaustive truncations"
