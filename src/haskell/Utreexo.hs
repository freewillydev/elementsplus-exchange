{-# LANGUAGE ForeignFunctionInterface #-}
module Utreexo (elements_hs_utreexo_v1) where

import Data.Word
import Foreign.C.Types
import Foreign.Ptr

type Emit = Ptr () -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Word64 -> IO Word32
type Transition = Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> FunPtr Emit -> Ptr () -> IO Word32
foreign import ccall safe "dynamic" transition :: FunPtr Transition -> Transition
foreign export ccall elements_hs_utreexo_v1 :: FunPtr Transition -> Transition

-- The existing native Coin view remains authoritative. This boundary only
-- admits and sequences the linked Rust accumulator operation.
elements_hs_utreexo_v1 :: FunPtr Transition -> Transition
elements_hs_utreexo_v1 engine source size adds addCount dels delCount emit context
  | engine == nullFunPtr || emit == nullFunPtr = pure 1
  | size /= 0 && source == nullPtr = pure 1
  | addCount /= 0 && adds == nullPtr = pure 1
  | delCount /= 0 && dels == nullPtr = pure 1
  | addCount > fromIntegral (maxBound :: Int) `div` 32 || delCount > fromIntegral (maxBound :: Int) `div` 32 = pure 1
  | otherwise = transition engine source size adds addCount dels delCount emit context
