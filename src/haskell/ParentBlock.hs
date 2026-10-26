{-# LANGUAGE ConstraintKinds, DataKinds, FlexibleContexts, FlexibleInstances #-}
{-# LANGUAGE GADTs, MultiParamTypeClasses, TypeApplications, TypeFamilies #-}
-- Copyright (c) 2026 The Elements Core developers
-- Distributed under the MIT software license.
module ParentBlock where

import CapabilityContext (CapabilityContext)
import Control.Operation
import Control.Operation.Validation
import Control.Monad (unless, when, forM_)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Except (ExceptT, runExceptT, throwE)
import Data.Bits (testBit)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.Int (Int32, Int64)
import Data.IORef (newIORef, readIORef, writeIORef, modifyIORef')
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import Data.Word (Word8, Word32, Word64)
import qualified Bmm
import qualified ParentReplay as Replay
import Withdrawal (wordLE)
import Workflow (NativeBytes, CommandFlow(..))

type Checked = ExceptT Int32 IO
type AcceptedBmm = Map.Map Word8 B.ByteString
newtype Prelude = Prelude NativeBytes
class ReplayAdmission op where
  admitParent :: op -> Checked ()
class CoinbaseCollection op where
  collectCoinbase :: op -> Checked AcceptedBmm
class BmmRequests op where
  checkBmmRequests :: op -> AcceptedBmm -> Checked ()

-- Only native getters, the upstream script reader, hashing and publication cross
-- this boundary. Rule composition and the temporary M7 map remain in Haskell.
effect :: NativeBytes -> Word32 -> Word64 -> B.ByteString -> IO ()
effect native step index input = do
  result <- native step index input
  unless (B.null result) (ioError (userError "unexpected parent prelude effect reply"))

scalar :: NativeBytes -> Word32 -> Word64 -> IO Word64
scalar native step index = do
  result <- native step index B.empty
  unless (B.length result == 8) (ioError (userError "invalid parent prelude scalar"))
  pure (Replay.replayWord result)

flow :: Word32 -> (Word32 -> IO Int64) -> IO Int32
flow kind = validate . CommandFlow (Replay.storeMaximum kind)
  (\phase result -> validate (Replay.StoreFlow kind phase result))

deadline :: NativeBytes -> IO Int64
deadline native = do
  status <- Replay.runDeadline (fmap fromIntegral . scalar native 30 . fromIntegral)
  pure (if status == 0 then 1 else -1)

reject :: NativeBytes -> String -> Checked a
reject native message = liftIO (effect native 200 0 (C.pack message)) >> throwE 1

require :: NativeBytes -> String -> Bool -> Checked ()
require native message valid = unless valid (reject native message)

bytes :: NativeBytes -> Word32 -> Int -> Checked B.ByteString
bytes native step width = do
  result <- liftIO (native step 0 B.empty)
  unless (B.length result == width) (throwE (-1))
  pure result

-- Admission snapshots contain only total getters. Partial object access stays
-- guarded by the native owner; later snapshots are not requested on rejection.
instance ReplayAdmission Prelude where
  admitParent (Prelude native) = do
    parameters <- bytes native 0 44
    let word offset width = Replay.replayWord (B.take width (B.drop offset parameters))
        slot = fromIntegral (word 0 8) :: Int64
        flags = word 8 8
        bit = testBit flags
        amount = fromIntegral (word 16 8)
        maximumMoney = word 24 8
        record kind present value first second = validate (Replay.Record kind present value first second) == 1
        balance present value = record 18 (if present then 1 else 0) value 0 maximumMoney
        window offset = record 17 0 0 (word (offset+2) 2) (word offset 2)
        facts kind values = liftIO (flow kind (\step -> pure (if values !! fromIntegral (step-1) then 1 else 0)))
    when (flags > 63) (throwE (-1))
    require native "unsupported parent-state replay rules" (bit 0)
    require native "invalid slot or proposal identity for parent-state replay"
      (record 7 0 slot 0 255 && bit 1 && all window [32,36,40])
    consistent <- facts 62 [bit 2,bit 3,bit 4,bit 5]
    require native "parent-state replay began with an inconsistent active proposal" (consistent == 1)
    coinbase <- liftIO (scalar native 1 0)
    when (coinbase > 7) (throwE (-1))
    present <- facts 65 [testBit coinbase 0,testBit coinbase 1,testBit coinbase 2]
    require native "parent-state replay block has no coinbase transaction" (present == 1)
    require native "parent-state replay began with malformed CTIP state" (balance (bit 5) amount)
    slots <- liftIO (native 2 0 B.empty)
    when (B.length slots > 2560 || B.length slots `mod` 10 /= 0) (throwE (-1))
    forM_ [0,10..B.length slots-1] $ \offset -> do
      let other = B.index slots offset
          status = B.index slots (offset+1)
          value = fromIntegral (Replay.replayWord (B.take 8 (B.drop (offset+2) slots)))
      when (status > 3) (throwE (-1))
      valid <- facts 63 [fromIntegral other == slot,testBit status 0,testBit status 1,balance (testBit status 1) value]
      require native "parent-state replay began with malformed global slot state" (valid == 1)
    prior <- liftIO (native 3 0 B.empty)
    when (B.length prior > 512 || odd (B.length prior)) (throwE (-1))
    forM_ [0,2..B.length prior-1] $ \offset -> do
      let status = B.index prior (offset+1)
      when (status > 7) (throwE (-1))
      valid <- facts 64 [testBit status 0,testBit status 1,testBit status 1,testBit status 2]
      require native ("parent-state replay has malformed prior M4 action for slot " ++ show (B.index prior offset)) (valid == 1)

-- Published frames are kind/slot/encoding/hash32 followed by little-endian M4
-- votes. They describe decoded messages, not serialized consensus objects.
parseMessage :: NativeBytes -> Word64 -> IO B.ByteString
parseMessage native index = do
  effect native 11 index B.empty
  single <- flow 31 (fmap fromIntegral . scalar native 12 . fromIntegral)
  case single of
    0 -> pure B.empty
    1 -> do
      payload <- native 13 0 B.empty
      let (kind,encoding,votes) = validate (Replay.Message (B.unpack payload))
          slot = B.index payload 4
      if kind == 0 then pure B.empty else do
        hash <- case kind of
          1 -> native 14 0 (B.drop 5 payload)
          4 -> pure (B.replicate 32 0)
          _ -> pure (B.pack (validate (Bmm.CommitmentBytes 2 (B.unpack payload))))
        unless (B.length hash == 32) (ioError (userError "invalid proposal hash reply"))
        pure (B.pack [fromIntegral kind,if kind == 4 then 0 else slot,fromIntegral encoding] <>
          hash <> B.concat (map (wordLE 2 . fromIntegral) votes))
    _ -> ioError (userError "invalid parent script reader result")

instance CoinbaseCollection Prelude where
  collectCoinbase (Prelude native) = do
    count <- liftIO (scalar native 10 0)
    m1 <- liftIO (newIORef Set.empty)
    m2 <- liftIO (newIORef Set.empty)
    accepted <- liftIO (newIORef Map.empty)
    current <- liftIO (newIORef B.empty)
    let unique entries value = do
          previous <- readIORef entries
          modifyIORef' entries (Set.insert value)
          pure (if Set.member value previous then 0 else 1)
        action step index = do
          message <- readIORef current
          let slot = B.index message 1
              hash = B.take 32 (B.drop 3 message)
          case step of
            1 -> deadline native
            2 -> do
              decoded <- parseMessage native index
              writeIORef current decoded
              pure (if B.null decoded then 0 else fromIntegral (B.head decoded))
            3 -> unique m1 (slot,hash)
            4 -> unique m2 slot
            5 -> do
              previous <- readIORef accepted
              pure (if Map.member slot previous then 0 else 1)
            6 -> modifyIORef' accepted (Map.insert slot hash) >> pure 1
            7 -> effect native 15 index message >> pure 1
            8 -> writeIORef current B.empty >> pure 1
            _ -> pure (-1)
    status <- liftIO (validate (Replay.CoinbaseMessages count action))
    case status of
      0 -> liftIO (readIORef accepted)
      1 -> reject native "parent block contains a duplicate M1 proposal message"
      2 -> reject native "parent block contains multiple M2 ACK messages for one slot"
      3 -> reject native "parent block contains multiple M4 withdrawal ACK messages"
      4 -> reject native "parent block contains multiple M7 commitments for one slot"
      _ -> throwE (-1)

-- M8 deliberately accepts only the exact direct push used by the parent. A
-- malformed lookalike is an ordinary transaction, not a rejected request.
parseM8 :: B.ByteString -> Maybe (Word8,B.ByteString,B.ByteString)
parseM8 script
  | B.length script /= 70 || B.take 5 script /= B.pack [106,68,0,191,0] = Nothing
  | otherwise = Just (B.index script 5,
      B.pack (validate (Bmm.CommitmentBytes 0 (B.unpack (B.take 37 (B.drop 1 script))))),
      B.pack (validate (Bmm.CommitmentBytes 1 (B.unpack (B.drop 38 script)))))

instance BmmRequests Prelude where
  checkBmmRequests (Prelude native) accepted = do
    count <- liftIO (scalar native 20 0)
    current <- liftIO (newIORef Nothing)
    let action 1 _ = deadline native
        action 2 index = do
          request <- parseM8 <$> native 21 index B.empty
          writeIORef current request
          pure (maybe 0 (const 1) request)
        action step _ = do
          request <- readIORef current
          case request of
            Just (slot,critical,parent) -> case step of
              3 -> pure (if Map.lookup slot accepted == Just critical then 1 else 0)
              4 -> do
                expected <- native 22 0 B.empty
                unless (B.length expected == 32) (ioError (userError "invalid parent hash reply"))
                pure (if parent == expected then 1 else 0)
              _ -> pure (-1)
            Nothing -> pure (-1)
    status <- liftIO (validate (Replay.M8Acceptance count action))
    when (status /= 0) $ do
      request <- liftIO (readIORef current)
      case (status,request) of
        (1,Just (slot,_,_)) -> reject native ("BIP301 M8 for slot " ++ show slot ++ " was not accepted by this block's M7")
        (2,Just (slot,_,_)) -> reject native ("BIP301 M8 for slot " ++ show slot ++ " references an expired parent block")
        _ -> throwE (-1)

runPrelude :: (ReplayAdmission op, CoinbaseCollection op, BmmRequests op) => op -> Checked ()
runPrelude value = admitParent value >> collectCoinbase value >>= checkBmmRequests value

type PreludeCapabilities = '[ReplayAdmission, CoinbaseCollection, BmmRequests]
instance Operation Prelude PreludeCapabilities where
  type Context Prelude = CapabilityContext PreludeCapabilities Prelude
  type Outcome Prelude = IO Int32
  data DSL Prelude where
    CheckPrelude :: Context Prelude => DSL Prelude
  interpret operation request = withOperation @Prelude operation $ \value -> case request of
    CheckPrelude -> Just (either id (const 0) <$> runExceptT (runPrelude value))

data Block = Block Word32 Word64 Word32 Word32 Word32 Word32 NativeBytes
class ReplayMessages op where
  replayMessages :: op -> Checked ()
class ReplayTreasury op where
  replayTreasury :: op -> Checked ()
class ReplayMaintenance op where
  beforeTreasury :: op -> Checked ()
  afterTreasury :: op -> Checked ()
class ReplayPreparation op where
  prepareBlock :: op -> Checked ()

scope :: Word32 -> NativeBytes -> NativeBytes
scope group native step = native (4096*group+step)

-- A domain rejection publishes its existing native diagnostic and stops; an
-- interpreter fault must not be converted into a consensus rejection.
checked :: NativeBytes -> Word32 -> Int32 -> Checked ()
checked native diagnostic status
  | status < 0 = throwE status
  | status == 0 = pure ()
  | otherwise = liftIO (effect native diagnostic (fromIntegral status) B.empty) >> throwE 1

instance ReplayPreparation Block where
  prepareBlock (Block _ _ _ _ _ _ native) = do
    ready <- liftIO (deadline native)
    unless (ready == 1) (throwE (-1))
    liftIO (effect native 201 0 B.empty)
    runPrelude (Prelude native)

instance ReplayMessages Block where
  replayMessages (Block height settings _ _ _ _ native) = do
    let messages = scope 1 native
        readMessage step index input = do
          when (step == 0) $ do
            ready <- deadline native
            unless (ready == 1) (ioError (userError "parent message deadline failed"))
          messages step index input
    count <- liftIO (scalar messages 1000 0)
    status <- liftIO (validate (Replay.MessageWorkflow count height settings readMessage))
    checked messages 1001 status

instance ReplayMaintenance Block where
  beforeTreasury (Block height settings maxAge _ _ _ native) = do
    let maintenance = scope 2 native
    status <- liftIO (execute (Replay.Maintenance height settings maxAge 0 maintenance) Replay.BeforeTreasury)
    checked maintenance 1000 status
  afterTreasury (Block _ _ _ _ _ _ native) = do
    let publication = scope 4 native
    flags <- liftIO (scalar publication 1000 0)
    when (flags > 15) (throwE (-1))
    status <- liftIO (execute (Replay.Maintenance 0 0 0 (fromIntegral flags) publication) Replay.AfterTreasury)
    when (status < 0) (throwE status)
    when (status /= 0) (reject native "parent slot no longer has the required active proposal")

instance ReplayTreasury Block where
  replayTreasury (Block _ _ _ threshold opcode single native) = do
    let treasury = scope 3 native
    header <- bytes treasury 1000 24
    let word offset = Replay.replayWord (B.take 8 (B.drop offset header))
        count = word 0
        flags = word 8
        maximumMoney = word 16
        requiredActive = flags == 3
    when (flags > 3 || single > 1) (throwE (-1))
    appliedM6 <- liftIO (newIORef False)
    let visit index = when (index < count) $ do
          ready <- liftIO (deadline native)
          unless (ready == 1) (throwE (-1))
          fields <- liftIO (treasury 1001 index B.empty)
          when (B.length fields < 16) (throwE (-1))
          let inputs = Replay.replayWord (B.take 8 fields)
              outputs = Replay.replayWord (B.take 8 (B.drop 8 fields))
              rows = B.drop 16 fields
          when (B.length rows > 514 || odd (B.length rows) ||
            any ((>1) . B.index rows) [1,3..B.length rows-1]) (throwE (-1))
          let slots = validate (Replay.ActiveSlots rows)
          liftIO (effect treasury 1002 0 slots)
          let parseSlot output publish = do
                script <- treasury 1003 output B.empty
                let slot = if B.length script == 4
                      then Replay.treasurySlot (fromIntegral (Replay.replayWord script)) opcode else -1
                if slot < 0 then pure 0 else effect treasury publish (fromIntegral slot) B.empty >> pure 1
              action step value = case step of
                201 -> deadline native
                301 -> deadline native
                302 -> parseSlot value 1004
                902 -> parseSlot 0 1005
                607 -> fmap (\applied -> if applied then 1 else 0) (readIORef appliedM6)
                608 -> writeIORef appliedM6 True >> pure 1
                701 -> do
                  effect treasury 1006 0 B.empty
                  fromIntegral <$> flow 31 (fmap fromIntegral . scalar treasury 1007 . fromIntegral)
                _ -> do
                  result <- scalar treasury step value
                  if step == 0 && value == 7
                    then if result > 3 then pure (-1) else pure (fromIntegral result + if requiredActive then 4 else 0)
                    else pure (fromIntegral result)
          status <- liftIO (validate (Replay.TransactionReplay (fromIntegral (B.length slots))
            inputs outputs maximumMoney threshold single action))
          checked treasury 1008 status
          visit (index+1)
    visit 1

replayBlock :: (ReplayPreparation op, ReplayMessages op, ReplayMaintenance op, ReplayTreasury op) => op -> Checked ()
replayBlock value = prepareBlock value >> replayMessages value >> beforeTreasury value >>
  replayTreasury value >> afterTreasury value

type BlockCapabilities = '[ReplayPreparation, ReplayMessages, ReplayMaintenance, ReplayTreasury]
instance Operation Block BlockCapabilities where
  type Context Block = CapabilityContext BlockCapabilities Block
  type Outcome Block = IO Int32
  data DSL Block where
    ReplayBlock :: Context Block => DSL Block
  interpret operation request = withOperation @Block operation $ \value -> case request of
    ReplayBlock -> Just (either id (const 0) <$> runExceptT (replayBlock value))
