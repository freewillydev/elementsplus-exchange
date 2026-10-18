{-# LANGUAGE ConstraintKinds, DataKinds, FlexibleContexts, FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses, UndecidableInstances, UndecidableSuperClasses #-}
{-# LANGUAGE PolyKinds #-}
-- Copyright (c) 2026 The Elements Core developers
-- Distributed under the MIT software license.
module CapabilityContext (CapabilityContext) where

import Control.Operation (Capabilities)

-- A nominal constraint preserves Context's injectivity; a reducing family cannot.
class Capabilities caps op => CapabilityContext caps op
instance Capabilities caps op => CapabilityContext caps op
