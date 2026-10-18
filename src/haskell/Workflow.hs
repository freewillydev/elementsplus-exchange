{-# LANGUAGE FlexibleInstances, MultiParamTypeClasses, TypeFamilies, TypeOperators, UndecidableInstances #-}
{-# LANGUAGE ConstraintKinds, FlexibleContexts, GADTs, PolyKinds, BangPatterns #-}
{-# LANGUAGE DataKinds #-}
-- Copyright (c) 2026 The Elements Core developers
-- Distributed under the MIT software license.
module Workflow (Finalize(..), CommandFlow(..), PredicateFlow(..), orderedFacts, runRequiredEffects, runReportedEffects, countMatches) where

import Control.Operation.Validation
import Data.Bits ((.&.), clearBit, shiftR, testBit)
import Data.Int (Int32, Int64)
import Data.Word (Word32, Word64)

-- Terminal actions ignore their reply; committing actions finish only on 1.
-- The wider callback result reserves negative values for adapter exceptions.
data CommandFlow = CommandFlow Int32 (Word32 -> Word32 -> Int32) (Word32 -> IO Int64)
instance Validation CommandFlow where
  type ValidationResult CommandFlow = IO Int32
  validate (CommandFlow maximumStep transition action)
    | maximumStep < 1 || maximumStep > 255 = pure (-1)
    | otherwise = run (transition 0 0)
    where
      run command
        | command <= 0 = pure (if command >= -13 && command <= -10 then -10-command else -1)
        | step < 1 || step > maximumStep || status > 3 || (terminal && committing) ||
            command /= step + flags + (if flags == 0 then 0 else status*256) = pure (-1)
        | otherwise = do
            reply <- action (fromIntegral step)
            if reply < 0 || reply > fromIntegral (maxBound :: Word32) then pure (-1)
            else if terminal || (committing && reply == 1) then pure status
            else run (transition (fromIntegral step) (fromIntegral reply))
        where
          step = command .&. 255
          status = (command `shiftR` 8) .&. 255
          terminal = testBit command 16
          committing = testBit command 17
          flags = if terminal then 65536 else if committing then 131072 else 0

-- Boolean-action protocol: bit 8 makes an action's reply the final result.
-- Preserve invalid-action (-2) versus invalid-transition (-1) diagnostics.
data PredicateFlow = PredicateFlow Bool Word32 Int64 (Word32 -> Word32 -> Int64) (Word32 -> IO Int64)
instance Validation PredicateFlow where
  type ValidationResult PredicateFlow = IO Int32
  validate (PredicateFlow acceptZero start maximumStep transition action) = run (transition start 0)
    where
      run command
        | command <= 0 = pure (if command < -1 then -1 else if command == 0 && acceptZero then 0 else 1)
        | step < 1 || step > maximumStep = pure (-2)
        | otherwise = do
            reply <- action (fromIntegral step)
            if reply /= 0 && reply /= 1 then pure (-1)
            else if testBit command 8 then pure (1-fromIntegral reply)
            else run (transition (fromIntegral step) (fromIntegral reply))
        where step = clearBit command 8

countMatches :: Word64 -> (Word64 -> IO Int32) -> IO Int64
countMatches size action
  | size > fromIntegral (maxBound :: Int64) = pure (-1)
  | otherwise = scan 0 0
  where
    scan !index !count
      | index == size = pure count
      | otherwise = action index >>= \matched -> case matched of
          0 -> scan (index+1) count
          1 -> scan (index+1) (count+1)
          _ -> pure (-1)

orderedFacts :: (Eq status, Num status) => (step -> IO status) -> [(step,Int32)] -> Int32 -> IO Int32
orderedFacts readFact checks success = foldr (\(step,code) next -> readFact step >>= \reply -> case reply of
  0 -> pure code
  1 -> next
  _ -> pure (-1)) (pure success) checks

runRequiredEffects :: (Eq status, Num status) => (step -> IO status) -> [step] -> IO Int32
runRequiredEffects action steps = orderedFacts action [(step,-1) | step <- steps] 0

-- A rejection report is an effect, never permission to continue.
runReportedEffects :: (Eq status, Num status)
  => (step -> IO status) -> (step -> Maybe step) -> [step] -> IO Int32
runReportedEffects action rejection = runRequiredEffects $ \step -> action step >>= \result ->
  if result /= 0 then pure result else case rejection step of
    Nothing -> pure 0
    Just report -> action report >> pure 0

-- Completion may publish effects; callers must finish prerequisite work first.
class Finalize op where
  type FinalInput op
  type FinalResult op
  finalize :: op -> FinalInput op -> IO (FinalResult op)
