{-# LANGUAGE FlexibleInstances, ScopedTypeVariables #-}
-- Copyright (c) 2026 The Elements Core developers
-- Distributed under the MIT software license.
module Abi (Handler, handler, dispatch) where

import Control.Exception (SomeException, catch, evaluate)
import Data.Int (Int32, Int64)
import Data.Proxy (Proxy(..))
import Data.Word (Word8, Word32, Word64)
import Foreign.Marshal.Array (peekArray)
import Foreign.Ptr (Ptr, FunPtr, castPtr, castFunPtr, nullPtr)
import Foreign.Storable (poke)

-- Separate lanes preserve data/function pointer representation. These frames are
-- process-local borrows, never serialized consensus data or owned handles.
data Kind = U8 | U32 | U64 | I32 | I64 | Pointer | Callback deriving Eq
type Frame = ([Word64], [Ptr ()], [FunPtr ()])
data Handler = Handler [Kind] (Frame -> IO Word64)

class Argument a where
  kind :: Proxy a -> Kind
  argument :: Frame -> (a, Frame)

scalar :: (Word64 -> a) -> Frame -> (a, Frame)
scalar convert (x:xs, ps, fs) = (convert x, (xs, ps, fs))
scalar _ _ = error "invalid ABI scalar lane"

instance Argument Word8 where
  kind _ = U8
  argument = scalar fromIntegral
instance Argument Word32 where
  kind _ = U32
  argument = scalar fromIntegral
instance Argument Word64 where
  kind _ = U64
  argument = scalar id
instance Argument Int32 where
  kind _ = I32
  argument = scalar fromIntegral
instance Argument Int64 where
  kind _ = I64
  argument = scalar fromIntegral
instance Argument (Ptr a) where
  kind _ = Pointer
  argument (xs,p:ps,fs) = (castPtr p,(xs,ps,fs))
  argument _ = error "invalid ABI pointer lane"
instance Argument (FunPtr a) where
  kind _ = Callback
  argument (xs,ps,f:fs) = (castFunPtr f,(xs,ps,fs))
  argument _ = error "invalid ABI callback lane"

class Invocation f where
  signature :: Proxy f -> [Kind]
  invoke :: f -> Frame -> IO Word64
instance (Argument a, Invocation b) => Invocation (a -> b) where
  signature _ = kind (Proxy :: Proxy a) : signature (Proxy :: Proxy b)
  invoke f frame = let (value, rest) = argument frame in invoke (f value) rest
instance Invocation (IO Int32) where
  signature _ = []
  invoke action _ = fromIntegral <$> action
instance Invocation (IO Int64) where
  signature _ = []
  invoke action _ = fromIntegral <$> action

handler :: forall f. Invocation f => f -> Handler
handler f = Handler (signature (Proxy :: Proxy f)) (invoke f)

dispatch :: [Handler] -> Word32 -> Word32 -> Ptr Word64 -> Word32 -> Ptr (Ptr ())
  -> Word32 -> Ptr (FunPtr ()) -> Ptr Word64 -> IO Int32
dispatch handlers operation scalarCount scalars pointerCount pointers callbackCount callbacks result =
  run `catch` (\(_ :: SomeException) -> pure (-3))
  where
    run
      | toInteger operation >= toInteger (length handlers) || result == nullPtr = pure (-1)
      | otherwise = case handlers !! fromIntegral operation of
          Handler kinds action -> do
            let numeric = filter (\k -> k /= Pointer && k /= Callback) kinds
                matches count ptr expected = toInteger count == toInteger expected && (count == 0 || ptr /= nullPtr)
            if not (matches scalarCount scalars (length numeric) &&
                    matches pointerCount pointers (length (filter (==Pointer) kinds)) &&
                    matches callbackCount callbacks (length (filter (==Callback) kinds)))
              then pure (-1)
              else do
                values <- peekArray (length numeric) scalars
                if not (and (zipWith canonical numeric values)) then pure (-2) else do
                  ps <- peekArray (fromIntegral pointerCount) pointers
                  fs <- peekArray (fromIntegral callbackCount) callbacks
                  value <- action (values,ps,fs) >>= evaluate
                  poke result value
                  pure 0
    canonical U8 value = value <= 255
    canonical U32 value = value <= 0xffffffff
    canonical I32 value = fromIntegral (fromIntegral value :: Int32) == value
    canonical _ _ = True
