{-# LANGUAGE ScopedTypeVariables #-}
module AbiTests (abiRoundTrip, abiRejectsBeforeEffects, abiSignedCanonical, abiExceptionsPreserveResult) where

import Abi (dispatch, handler)
import Data.Int (Int32, Int64)
import Data.IORef (newIORef, modifyIORef', readIORef)
import Data.Word (Word8, Word32, Word64)
import Foreign.Marshal.Array (withArray)
import Foreign.Marshal.Utils (with)
import Foreign.Ptr (Ptr, nullPtr, castPtr)
import Foreign.Storable (peek, poke)
import Test.QuickCheck

abiRoundTrip :: Property
abiRoundTrip = property $ \(a :: Word8) (b :: Word32) (c :: Word64) (d :: Int32) (e :: Int64) -> ioProperty $
  withArray [fromIntegral a,fromIntegral b,c,fromIntegral d,fromIntegral e] $ \scalars ->
  with (0 :: Word64) $ \result -> with (0 :: Int64) $ \storedValue -> withArray [castPtr storedValue] $ \pointers -> do
    let action a' b' c' d' e' ptr = do
          poke ptr (e' :: Int64)
          pure (if (a',b',c',d',e') == (a,b,c,d,e) then (-123 :: Int32) else 7)
    code <- dispatch [handler action] 0 5 scalars 1 pointers 0 nullPtr result
    actual <- peek result
    stored <- peek storedValue
    pure (conjoin [code === 0, actual === fromIntegral (-123 :: Int32), stored === e])

abiRejectsBeforeEffects :: Property
abiRejectsBeforeEffects = property $ \(value :: Word64) -> ioProperty $ do
  calls <- newIORef (0 :: Int)
  let action (_ :: Word8) (_ :: Ptr Word8) = modifyIORef' calls (+1) >> pure (0 :: Int32)
      domains = [handler action]
  withArray [value] $ \scalars -> with (42 :: Word64) $ \result -> withArray [nullPtr] $ \pointers -> do
    wrongCount <- dispatch domains 0 2 scalars 1 pointers 0 nullPtr result
    missing <- dispatch domains 0 1 nullPtr 1 pointers 0 nullPtr result
    unknown <- dispatch domains maxBound 1 scalars 1 pointers 0 nullPtr result
    before <- peek result
    countBefore <- readIORef calls
    ranged <- dispatch domains 0 1 scalars 1 pointers 0 nullPtr result
    countAfter <- readIORef calls
    after <- peek result
    pure (conjoin [wrongCount === -1, missing === -1, unknown === -1,
      before === 42, countBefore === 0,
      ranged === (if value <= 255 then 0 else -2),
      countAfter === (if value <= 255 then 1 else 0),
      after === (if value <= 255 then 0 else 42)])

abiSignedCanonical :: Property
abiSignedCanonical = forAll (frequency [(1,fromIntegral <$> (arbitrary :: Gen Int32)),(1,arbitrary)]) $ \value -> ioProperty $ do
  calls <- newIORef (0 :: Int)
  let canonical = fromIntegral (fromIntegral value :: Int32) == (value :: Word64)
      action (_ :: Int32) = modifyIORef' calls (+1) >> pure (7 :: Int32)
  withArray [value] $ \scalars -> with (42 :: Word64) $ \result -> do
    code <- dispatch [handler action] 0 1 scalars 0 nullPtr 0 nullPtr result
    invoked <- readIORef calls
    stored <- peek result
    pure $ conjoin [code === (if canonical then 0 else -2),
      invoked === (if canonical then 1 else 0), stored === (if canonical then 7 else 42)]

abiExceptionsPreserveResult :: Property
abiExceptionsPreserveResult = once $ ioProperty $ do
  checks <- sequence [with (42 :: Word64) $ \result -> do
    code <- dispatch [handler action] 0 0 nullPtr 0 nullPtr 0 nullPtr result
    stored <- peek result
    pure $ conjoin [code === -3, stored === 42] |
    action <- [ioError (userError "ABI effect failure"), pure (error "ABI lazy result failure")] :: [IO Int32]]
  pure (conjoin checks)
