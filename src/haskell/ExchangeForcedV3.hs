{-# LANGUAGE TypeFamilies #-}
-- Candidate exact inbox rules. Rust supplies canonical signature metadata;
-- these rules do not authenticate source headers or a settlement receipt.
module ExchangeForcedV3 where

import Control.Monad (guard)
import Control.Operation.Validation
import qualified Data.ByteString as B
import Data.Word (Word8, Word64)
import Withdrawal (wordBE)

integerBE :: B.ByteString -> Integer
integerBE = B.foldl' (\n b -> n*256+fromIntegral b) 0

slice :: Int -> Int -> B.ByteString -> B.ByteString
slice offset width = B.take width . B.drop offset

nonzeroHash :: B.ByteString -> Bool
nonzeroHash b = B.length b==32 && B.any (/=0) b

-- Exact minimal OP_RETURN push. No old marker parser is widened.
data ForcedV3Frame = ForcedV3Frame B.ByteString B.ByteString
instance Validation ForcedV3Frame where
  type ValidationResult ForcedV3Frame = Maybe B.ByteString
  validate (ForcedV3Frame expected script) = do
    guard (nonzeroHash expected && B.length script>=2 && B.length script<=4108 && B.head script==106)
    (offset,size)<-case B.index script 1 of
      n | n<=75 -> pure (2,fromIntegral n)
      76 | B.length script>=3 && B.index script 2>=76 -> pure (3,fromIntegral (B.index script 2))
      77 | B.length script>=4 -> do
        let n=fromIntegral (B.index script 2)+256*fromIntegral (B.index script 3)
        guard (n>255)
        pure (4,n)
      _ -> Nothing
    guard (offset+size==B.length script && size>=40 && size<=4104)
    let payload=B.drop offset script
    guard (B.take 5 payload==B.pack [69,67,88,70,3] && B.index payload 5<=4 &&
      integerBE (slice 6 2 payload)==toInteger(size-8) && slice 8 32 payload==expected)
    pure payload

-- Metadata comes only from the linked canonical Rust signature checker.
-- The native caller must compare its kind with the exact parsed payload.
data ForcedV3Admission = ForcedV3Admission Word64 Word8 B.ByteString
instance Validation ForcedV3Admission where
  type ValidationResult ForcedV3Admission = Bool
  validate (ForcedV3Admission parent kind bytes)
    | B.length bytes/=50 || parent==0 || parent>maxBound-12 = False
    | B.take 2 bytes/=B.pack [1,kind] || not (nonzeroHash (slice 2 32 bytes)) = False
    | otherwise = case kind of
        0 -> first<=height && height<=second
        1 -> first<=height && height<=second
        2 -> first<=height && second==toInteger (maxBound::Word64)
        3 -> height<first && first<=second && second<=height+12
        4 -> height<=first && first<height+12 && second==0
        _ -> False
    where
      first=integerBE (slice 34 8 bytes)
      second=integerBE (slice 42 8 bytes)
      height=toInteger parent

-- Serialized protocol state, including full-width counters and persisted
-- per-parent admission budgets. Roots are opaque until native/proof binding.
data ForcedV3State = ForcedV3State B.ByteString B.ByteString
instance Validation ForcedV3State where
  type ValidationResult ForcedV3State = Bool
  validate (ForcedV3State expected bytes)
    | B.length bytes/=145 || not (nonzeroHash expected) = False
    | B.head bytes/=3 || slice 1 32 bytes/=expected = False
    | not (nonzeroHash headRoot && nonzeroHash processedRoot) || cursor>count = False
    | cursor==count && processedRoot/=headRoot = False
    | count==0 = parent==0 && admissions==0 && work==0
    | otherwise = parent>0 && admissions>0 && admissions<=count && admissions<=64 && work<=64
    where
      headRoot=slice 33 32 bytes
      count=integerBE (slice 65 16 bytes)
      processedRoot=slice 81 32 bytes
      cursor=integerBE (slice 113 16 bytes)
      parent=integerBE (slice 129 8 bytes)
      admissions=integerBE (slice 137 4 bytes)
      work=integerBE (slice 141 4 bytes)

forcedV3CursorBytes :: Word64 -> Word64 -> Word64 -> B.ByteString
forcedV3CursorBytes high low deposits = B.pack [106,29,69,67,88,67,3] <>
  wordBE 8 high <> wordBE 8 low <> wordBE 8 deposits

newtype ForcedV3Cursor = ForcedV3Cursor B.ByteString
instance Validation ForcedV3Cursor where
  type ValidationResult ForcedV3Cursor = Maybe (Word64,Word64,Word64)
  validate (ForcedV3Cursor bytes)
    | B.length bytes/=31 || B.take 7 bytes/=B.pack [106,29,69,67,88,67,3] = Nothing
    | otherwise = Just (readWord 7,readWord 15,readWord 23)
    where readWord offset=fromInteger (integerBE (slice offset 8 bytes))

-- Fields: count(high,low), cursor(high,low), priorparent, priorcount,
-- priorwork, currentparent, kind. Persistent admission budgets never reset
-- merely because the queue was drained. Results: newcount(high,low),count,work.
newtype ForcedV3Append = ForcedV3Append [Word64]
instance Validation ForcedV3Append where
  type ValidationResult ForcedV3Append = Maybe [Word64]
  validate (ForcedV3Append [hi,lo,chi,clo,prior,count,work,parent,kind]) = do
    let total=wide hi lo; cursor=wide chi clo
        next=total+1; width=2^(64::Int)
        cost=case kind of 0 -> 1; 1 -> 64; _ -> 0
        newCount=if parent==prior then toInteger count+1 else 1
        newWork=if parent==prior then toInteger work+cost else cost
    guard (kind<=4 && parent>0 && parent>=prior && total<2^(128::Int)-1 &&
      cursor<=total && total-cursor<448 && count<=64 && work<=64 &&
      (if total==0 then prior==0 && count==0 && work==0 else prior>0 && count>0 && toInteger count<=total) &&
      newCount<=64 && newWork<=64)
    pure (map fromInteger [next `div` width,next `mod` width,newCount,newWork])
    where wide high low=toInteger high*2^(64::Int)+toInteger low
  validate _ = Nothing
