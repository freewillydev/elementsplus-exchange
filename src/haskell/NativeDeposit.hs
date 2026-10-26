{-# LANGUAGE ConstraintKinds, DataKinds, FlexibleContexts, FlexibleInstances #-}
{-# LANGUAGE GADTs, MultiParamTypeClasses, TypeApplications, TypeFamilies #-}
-- Copyright (c) 2026 The Elements Core developers
-- Distributed under the MIT software license.
module NativeDeposit where

import CapabilityContext (CapabilityContext)
import Control.Monad (unless, when)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Except (runExceptT, throwE)
import Control.Operation
import Control.Operation.Validation (validate)
import Data.Bits ((.&.), (.|.), shiftL, shiftR, testBit)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.Int (Int32, Int64)
import Data.Word (Word8, Word32, Word64)
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (Ptr)
import Foreign.Storable (peek, poke)
import BmmConstants (depositAddressLimit)
import qualified Deposit as D
import ParentReplay (replayWord)
import Withdrawal (wordLE)
import Workflow (NativeBytes)

type Check = D.ConstructionCheck

-- The address decoder remains upstream. This parser only handles the fork's
-- canonical fee envelope; Integer parsing cannot overflow into an accepted fee.
destination :: Int64 -> B.ByteString -> Maybe (B.ByteString, Int64)
destination maximumMoney payload
  | B.null payload || B.length payload > fromIntegral depositAddressLimit = Nothing
  | Just rest <- B.stripPrefix (C.pack "dcfee1:") payload = do
      let (encoded,suffix) = C.break (== ':') rest
      (fee,trailing) <- C.readInteger encoded
      unless (B.null trailing && not (B.null suffix) && fee > 0 &&
        fee <= toInteger maximumMoney && C.pack (show fee) == encoded) Nothing
      pure (B.tail suffix,fromInteger fee)
  | otherwise = Just (payload,0)

data Recipient = Recipient Int64 Int64 Word64 (IO B.ByteString) NativeBytes
class RecipientDecoding op where
  decodeRecipient :: op -> Check Int64
class RecipientEncoding op where
  encodeRecipient :: op -> Check ()
class NativeAssembly op where
  assembleNative :: op -> Int64 -> Check ()

instance RecipientDecoding Recipient where
  decodeRecipient (Recipient maximumMoney _ size source native) = do
    liftIO (D.constructionEffect native 1 B.empty)
    unless (size > 0 && size <= fromIntegral depositAddressLimit) (throwE 1)
    payload <- liftIO source
    unless (fromIntegral (B.length payload) == size) (throwE (-1))
    (address,fee) <- maybe (throwE 1) pure (destination maximumMoney payload)
    valid <- liftIO (native 2 0 address >>= D.constructionWord) >>= D.constructionFlag
    unless valid (throwE 1)
    liftIO (D.constructionEffect native 3 (wordLE 8 (fromIntegral fee)))
    pure fee

instance RecipientEncoding Recipient where
  encodeRecipient (Recipient maximumMoney fee size source native) = do
    -- Encoding historically decodes the original address before checking fees
    -- and length. Index 1 asks the native decoder to use that borrowed string.
    valid <- liftIO (native 2 1 B.empty >>= D.constructionWord) >>= D.constructionFlag
    unless (valid && fee >= 0 && fee <= maximumMoney) (throwE 1)
    let prefix = if fee == 0 then B.empty else C.pack ("dcfee1:" ++ show fee ++ ":")
    unless (toInteger size + toInteger (B.length prefix) <= toInteger depositAddressLimit) (throwE 2)
    address <- liftIO source
    unless (fromIntegral (B.length address) == size) (throwE (-1))
    liftIO (D.constructionEffect native 4 (prefix <> address))

instance NativeAssembly Recipient where
  assembleNative (Recipient maximumMoney amount _ _ native) fee = do
    unless (amount >= 0 && amount <= maximumMoney && amount > fee) (throwE 3)
    liftIO $ do
      D.constructionEffect native 5 B.empty
      D.constructionEffect native 6 (wordLE 8 (fromIntegral (amount-fee)))
      when (fee /= 0) (D.constructionEffect native 7 (wordLE 8 (fromIntegral fee)))
      D.constructionEffect native 8 B.empty
      D.constructionEffect native 9 B.empty

constructNative :: (RecipientDecoding op, NativeAssembly op) => op -> Check ()
constructNative value = decodeRecipient value >>= assembleNative value

type RecipientCapabilities = '[RecipientDecoding, RecipientEncoding, NativeAssembly]
instance Operation Recipient RecipientCapabilities where
  type Context Recipient = CapabilityContext RecipientCapabilities Recipient
  type Outcome Recipient = IO Int32
  data DSL Recipient where
    DecodeRecipient :: Context Recipient => DSL Recipient
    EncodeRecipient :: Context Recipient => DSL Recipient
    ConstructNative :: Context Recipient => DSL Recipient
  interpret operation request = withOperation @Recipient operation $ \value ->
    let run = Just . fmap (either id (const 0)) . runExceptT
    in case request of
      DecodeRecipient -> run (() <$ decodeRecipient value)
      EncodeRecipient -> run (encodeRecipient value)
      ConstructNative -> run (constructNative value)

-- Witness bytes are borrowed; only the existing bounded witness reader touches
-- them. The field accessor is used after that reader accepts a native witness.
data Outputs = Outputs Word64 Word64 Word64 Word64 Int64
  (Word64 -> Word32 -> Ptr Int64 -> IO D.DepositWitness)
  (Word64 -> Int -> IO B.ByteString) NativeBytes
data InputView = InputView [Word8] Word32 Int64 Int64
class DepositInputs op where
  inspectInputs :: op -> Check InputView
class DepositCredits op where
  inspectCredits :: op -> InputView -> Check ()
class FeeFreeEligibility op where
  requireFeeFree :: op -> Check ()

readWitness :: Outputs -> Word64 -> Word32 -> Check (Bool,Int64)
readWitness (Outputs _ _ _ _ _ witness _ _) index mode = D.parseChecked (-5) $
  alloca $ \amount -> do
    poke amount 0
    kind <- witness index mode amount >>= validate
    value <- peek amount
    pure (kind /= 0,value)

inputSnapshot :: NativeBytes -> Word64 -> Check Word32
inputSnapshot native index = do
  flags <- liftIO (D.constructionScalar native 10 index)
  when (flags > 7) (throwE (-1))
  pure (fromIntegral flags)

instance DepositInputs Outputs where
  inspectInputs value@(Outputs inputs index witnesses _ maximumMoney _ field native) = do
    unless (index < inputs && index < witnesses) (throwE 1)
    ins <- mapM (\i -> do
      recognized <- if i < witnesses then fst <$> readWitness value i 0 else pure False
      flags <- inputSnapshot native i
      pure (fromIntegral (fromEnum recognized) .|. (fromIntegral (flags .&. 1) `shiftL` 1)))
      (take (fromIntegral inputs) [0..])
    (isNative,amount) <- readWitness value index 2
    claim <- if isNative then liftIO (field index 3) else pure B.empty
    address <- if isNative then liftIO (field index 7) else pure B.empty
    recipient <- liftIO $ runExceptT $ decodeRecipient
      (Recipient maximumMoney 0 (fromIntegral (B.length address)) (pure address) native)
    (valid,fee) <- case recipient of
      Right fee -> pure (True,fee)
      Left 1 -> pure (False,0)
      Left failure -> throwE failure
    flags <- inputSnapshot native index
    let facts = fromIntegral (fromEnum (not (testBit flags 2))) .|.
          (fromIntegral (fromEnum isNative) `shiftL` 1) .|.
          (fromIntegral (fromEnum (claim == B.singleton 81)) `shiftL` 2) .|.
          (fromIntegral (fromEnum valid) `shiftL` 3)
        exact = (flags .&. 1) .|. 2 .|. ((flags .&. 6) `shiftL` 1) .|.
          (fromIntegral (fromEnum isNative) `shiftL` 4) .|. 32 .|.
          (fromIntegral (fromEnum (claim == B.singleton 81)) `shiftL` 6)
    pure (InputView ins (facts .|. (exact `shiftL` 8)) amount fee)

instance DepositCredits Outputs where
  inspectCredits (Outputs inputs index witnesses count _ _ _ native) (InputView ins facts amount fee) = do
    rows <- mapM (\i -> do
      bytes <- liftIO (native 20 i B.empty)
      unless (B.length bytes == 16) (throwE (-1))
      let flags = replayWord (B.take 8 bytes)
      when (flags .&. 0xffffffffffffe0f0 /= 0) (throwE (-1))
      pure (flags,fromIntegral (replayWord (B.drop 8 bytes)))) (take (fromIntegral count) [0..])
    when (fee > 0 && fee >= amount) (throwE 2)
    D.parseStatus 0x100 (validate (D.DepositOutputs (facts .&. 255) (amount-fee) ins
      [(fromIntegral flags,value) | (flags,value) <- rows]))
    when (fee /= 0) $ D.parseStatus 0x200 (validate
      (D.AuthenticatedDeposit inputs index witnesses (facts `shiftR` 8) amount amount count
        [(fromIntegral (flags `shiftR` 8),value) | (flags,value) <- take 2 rows]))

instance FeeFreeEligibility Outputs where
  requireFeeFree value@(Outputs inputs _ witnesses count _ _ _ native) = do
    unless (inputs == 1 && count == 1 && witnesses == 1) (throwE 3)
    flags <- inputSnapshot native 0
    unless (testBit flags 0 && testBit flags 2) (throwE 3)
    (recognized,_) <- readWitness value 0 0
    unless recognized (throwE 3)

checkOutputs :: (DepositInputs op, DepositCredits op) => op -> Check ()
checkOutputs value = inspectInputs value >>= inspectCredits value

type OutputCapabilities = '[DepositInputs, DepositCredits, FeeFreeEligibility]
instance Operation Outputs OutputCapabilities where
  type Context Outputs = CapabilityContext OutputCapabilities Outputs
  type Outcome Outputs = IO Int32
  data DSL Outputs where
    CheckOutputs :: Context Outputs => DSL Outputs
    CanonicalFeeFree :: Context Outputs => DSL Outputs
  interpret operation request = withOperation @Outputs operation $ \value ->
    let run = Just . fmap (either id (const 0)) . runExceptT
    in case request of
      CheckOutputs -> run (checkOutputs value)
      CanonicalFeeFree -> run (requireFeeFree value >> checkOutputs value)
