{-# LANGUAGE FlexibleInstances, MultiParamTypeClasses, TypeApplications, TypeFamilies #-}
module StateStorageTests (properties) where

import qualified Bmm as H
import Control.Exception (SomeException, try)
import Control.Monad (forM, when)
import Control.Operation
import Control.Operation.Validation (Check(..))
import qualified Data.ByteString as B
import Data.Int (Int32)
import Data.IORef
import Data.Maybe (isNothing)
import Data.Word (Word32, Word64)
import qualified Drivechain as FFI
import Foreign.Ptr (nullFunPtr, nullPtr)
import Test.QuickCheck
import Withdrawal (wordLE)
import Workflow (Finalize(..), NativeBytes)

type Event = (Word32, Word64)
events :: Bool -> Int32 -> [Event]
events restore height = [(0,0),(10,0),(11,0),(12,0),(13,0),(14,117),(14,0),(15,0),
  (16,fromIntegral (max 0 (toInteger height - if restore then 1 else 0)))]

run :: Bool -> NativeBytes -> IO Int32
run restore native = execute (H.PersistedOutput restore native) H.PersistOutput

trace :: Bool -> Int32 -> Int -> (Int -> B.ByteString -> B.ByteString) -> IO (Bool,[Event])
trace restore height failure mutate = do
  seen <- newIORef []
  result <- try @SomeException $ run restore $ \step index input -> do
    when (not (B.null input)) (error "unexpected storage payload")
    before <- readIORef seen
    modifyIORef' seen (++[(step,index)])
    when (length before == failure) (ioError (userError "storage fault"))
    let reply = wordLE 8 (if step == 0 then fromIntegral (fromIntegral height :: Word32) else 1)
    pure (mutate (length before) reply)
  seen' <- readIORef seen
  pure (either (const False) (==1) result,seen')

prop_order :: Bool -> Int32 -> Property
prop_order restore height = ioProperty $ do
  (ok,seen) <- trace restore height (-1) (const id)
  pure (ok && seen == events restore height)

prop_faults :: Bool -> Int32 -> Property
prop_faults restore height = ioProperty $ do
  checks <- forM [0..8] $ \failure -> do
    (ok,seen) <- trace restore height failure (const id)
    pure (not ok && seen == take (failure+1) (events restore height))
  pure (and checks)

prop_framing :: Property
prop_framing = once $ ioProperty $ do
  checks <- forM [0..8] $ \failure -> do
    let invalid = if failure == 0 then [B.empty, B.replicate 7 0, B.replicate 9 0, wordLE 8 0x100000000]
          else [B.empty, B.singleton 1, wordLE 8 0, wordLE 8 2, wordLE 8 1 <> B.singleton 0]
    forM invalid $ \bad -> do
      (ok,seen) <- trace False 100 (-1) (\i good -> if i == failure then bad else good)
      pure (not ok && seen == take (failure+1) (events False 100))
  pure (and (concat checks))

-- A non-FFI product uses the same capability algebra, without Operation/Typeable.
data LocalOutput = LocalOutput Int32 (IORef [Event])
instance H.StateReplacement LocalOutput where
  replacementHeight (LocalOutput height seen) = modifyIORef' seen (++[(0,0)]) >> pure height
  clearStoredState (LocalOutput _ seen) = modifyIORef' seen (++[(10,0)])
  prepareStoredState (LocalOutput _ seen) = modifyIORef' seen (++[(15,0)])
instance Finalize LocalOutput where
  type FinalInput LocalOutput = Word32
  type FinalResult LocalOutput = ()
  finalize (LocalOutput _ seen) height = modifyIORef' seen (++[(16,fromIntegral height)])

prop_capability_reuse :: Int32 -> Property
prop_capability_reuse height = ioProperty $ do
  seen <- newIORef []
  H.replaceStoredState (LocalOutput height seen)
  result <- readIORef seen
  pure (result == [(0,0),(10,0),(15,0),(16,fromIntegral (max 0 height))])

prop_lazy_dispatch :: Property
prop_lazy_dispatch = once $ property $ isNothing $
  interpret (SomeOperation (undefined :: Check H.Header))
    (undefined :: DSL H.PersistedOutput)

prop_ffi_rejects_missing_callback :: Property
prop_ffi_rejects_missing_callback = once $ ioProperty $ do
  values <- forM [40,41,42] $ \selector -> FFI.elements_hs_replay_store selector 0 nullFunPtr nullPtr
  pure (all (==(-1)) values)

properties :: [(String,Property)]
properties =
  [("state storage ordered encode and replace",property prop_order)
  ,("state storage all effect fault prefixes",property prop_faults)
  ,("state storage strict metadata and acknowledgements",prop_framing)
  ,("state storage reusable capability algebra",property prop_capability_reuse)
  ,("state storage lazy payload mismatch",prop_lazy_dispatch)
  ,("state storage invalid boundary rejected",prop_ffi_rejects_missing_callback)]
