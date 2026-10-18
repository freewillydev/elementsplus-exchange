{-# LANGUAGE TypeFamilies, BangPatterns #-}
-- Copyright (c) 2026 The Elements Core developers
-- Distributed under the MIT software license.
module Usdd where

import Control.Operation.Validation
import Control.Monad (foldM)
import Data.Bits (testBit, (.&.), (.|.), shiftL, xor)
import Data.Word (Word8, Word32)
import Data.Word (Word64)
import Data.Int (Int32, Int64)
import Data.IORef (newIORef, modifyIORef', readIORef, writeIORef)
import qualified Data.ByteString as B
import Withdrawal (wordBE, readBE, readLE, WithdrawalRequest(..), WithdrawalRule(..), WithdrawalAction(..))
import Exchange (ConsensusFlow(ActivationPolicyFlow))
import Workflow (CommandFlow(..))
import ParentReplay (exceedsLane, transition)

data RpcProofFlow = RpcProofFlow Word32 Word32
instance Validation RpcProofFlow where
  type ValidationResult RpcProofFlow = Int32
  validate (RpcProofFlow phase reply) = transition phase reply
    [(1,(2,3)),(2,(-1,-1)),(3,(5,4)),(4,(5,-11)),
     (5,(7,6)),(6,(-1,-1)),(7,(-1,-1))]

data FrontierWire = FrontierWire Word64 Bool (Word32 -> IO Int32)
instance Validation FrontierWire where
  type ValidationResult FrontierWire = IO Int32
  validate (FrontierWire count reading action) = go [0..63]
    where
      go [] = pure 1
      go (level:rest)
        | not occupied && not reading = go rest
        | otherwise = do
            code <- action (fromIntegral level + if occupied then 0 else 64)
            if code==1 then go rest else pure (-1)
        where occupied=testBit count level

data AccumulatorVersion = AccumulatorVersion Word32
instance Validation AccumulatorVersion where
  type ValidationResult AccumulatorVersion = Int32
  validate (AccumulatorVersion version)
    | version>255 = -1
    | version==1 = 1
    | otherwise = 0

data AccumulatorConnection = AccumulatorConnection Word32 Word32
instance Validation AccumulatorConnection where
  type ValidationResult AccumulatorConnection = Int32
  validate (AccumulatorConnection phase result) = transition phase result
    [(1,(65539,2)),(2,(65539,4)),(4,(65541,6)),(6,(-11,7)),(7,(65544,-11))]

data CheckpointConnection = CheckpointConnection Word32 Word32
instance Validation CheckpointConnection where
  type ValidationResult CheckpointConnection = Int32
  validate (CheckpointConnection phase result) = transition phase result
    [(1,(-1,2)),(2,(65539,4)),(4,(65542,5)),(5,(65542,7)),(7,(-10,-11))]

data ApplyBlock = ApplyBlock Word64 Word8 B.ByteString B.ByteString ExtractBlock
data DeriveBlock = DeriveBlock ApplyBlock
instance Validation DeriveBlock where
  type ValidationResult DeriveBlock = IO Int
  validate (DeriveBlock (ApplyBlock count prefix before emptyRoots (ExtractBlock zero profile effect hash))) = do
    final <- newIORef (count,before)
    let capture action tx out cursor bytes = do
          result@(code,_) <- effect action tx out cursor bytes
          if action==5 && code>=0 then modifyIORef' final (const (cursor,bytes)) else pure ()
          pure result
        call action bytes = do
          result@(code,_) <- effect action 0 0 0 bytes
          if code<0 then error "checkpoint callback failed" else pure result
    applied <- validate (ApplyBlock count prefix before emptyRoots (ExtractBlock zero profile capture hash))
    if applied/=0 then call 7 (B.replicate 32 0) >> pure applied else do
      (_,metadata) <- call 6 B.empty
      if B.length metadata < 70 then error "invalid checkpoint metadata" else do
        (afterCount,after) <- readIORef final
        let (priorCount,prior) = if B.head metadata==0 then (count,before) else (afterCount,after)
        checkpoint <- validate (Checkpoint priorCount afterCount prefix prior after emptyRoots (B.tail metadata) hash)
        case checkpoint of
          Left code -> pure (code+5)
          Right digest -> call 7 digest >> pure 0

instance Validation ApplyBlock where
  type ValidationResult ApplyBlock = IO Int
  validate (ApplyBlock count prefix before emptyRoots (ExtractBlock zero profile effect hash)) = do
    sane <- validate (Accumulator 1 count prefix before emptyRoots (B.replicate 32 0) hash)
    case sane of
      Nothing -> pure 4
      Just _ -> do
        leaves <- newIORef []
        let collect action tx out cursor bytes = do
              result@(code,_) <- effect action tx out cursor bytes
              if action==3 && code>=0 then modifyIORef' leaves (B.drop 92 bytes:) else pure ()
              pure result
            publish cursor bytes = do
              (code,_) <- effect 5 0 0 cursor bytes
              if code<0 then error "accumulator publication failed" else pure ()
        extracted <- validate (ExtractBlock zero profile collect hash)
        if extracted/=0 then pure extracted else do
          publish count before
          batch <- B.concat . reverse <$> readIORef leaves
          (complete,nextCount,after) <- validate (AccumulatorBatch count prefix before emptyRoots batch hash)
          publish nextCount after
          pure (if complete then 0 else 5)

data ExtractBlock = ExtractBlock Bool B.ByteString
  (Word32 -> Word64 -> Word64 -> Word64 -> B.ByteString -> IO (Int64,B.ByteString))
  (B.ByteString -> IO B.ByteString)
instance Validation ExtractBlock where
  type ValidationResult ExtractBlock = IO Int
  validate (ExtractBlock zero profile effect hash)
    | zero = pure 1
    | otherwise = do
        (total,_) <- call 0 0 0 0 B.empty
        transactions (fromIntegral total) 0 0
    where
      call action tx out count bytes = do
        result@(code,_) <- effect action tx out count bytes
        if code < 0 then error "claim block callback failed" else pure result
      transactions total tx count
        | tx == total = pure 0
        | otherwise = do
            (outputs,_) <- call 1 tx 0 count B.empty
            if outputs == 0 then pure 2 else outputsLoop total tx (fromIntegral outputs-1) 0 count
      outputsLoop total tx outputs out count
        | out == outputs = transactions total (tx+1) count
        | otherwise = do
            (size,facts) <- call 2 tx out count B.empty
            if size /= 67 || B.take 2 facts /= B.pack [15,106] then next count else do
              (_,input) <- call 4 tx out count B.empty
              result <- validate (ExtractClaim profile input hash)
              case result of
                Left 1 -> next count
                Left _ -> pure 3
                Right claim -> do
                  _ <- call 3 tx out count claim
                  next (count+1)
        where next = outputsLoop total tx outputs (out+1)

data ExtractClaim = ExtractClaim B.ByteString B.ByteString (B.ByteString -> IO B.ByteString)
instance Validation ExtractClaim where
  type ValidationResult ExtractClaim = IO (Either Int B.ByteString)
  validate (ExtractClaim profile input hash)
    | B.length profile /= 69 || B.length input /= 216 = error "invalid claim extraction buffers"
    | otherwise = case withdrawalBody ExtractEthereumClaim (WithdrawalRequest 0 (B.take 116 input)) of
        Left _ -> pure (Left 2)
        Right parsed | B.null parsed -> pure (Left 1)
                     | otherwise -> do
            let word offset = readLE (B.take 8 (B.drop offset input))
                packed = B.take 64 (B.drop 116 input) <> B.take 32 (B.drop 8 parsed) <>
                  B.drop 180 input <> wordBE 8 (word 0 + word 8) <>
                  B.reverse (B.take 8 parsed) <> B.drop 40 parsed
            hashes <- validate (ClaimHashes 2 profile packed hash)
            pure (Right (parsed <> hashes))

data ClaimPrefix = ClaimPrefix Word64 B.ByteString B.ByteString (B.ByteString -> IO B.ByteString)
instance Validation ClaimPrefix where
  type ValidationResult ClaimPrefix = IO (Either Int B.ByteString)
  validate (ClaimPrefix first profile input hash)
    | B.length profile /= 69 || B.length input `mod` 200 /= 0 = error "invalid claim prefix buffers"
    | toInteger first + toInteger (B.length input `div` 200) > 18446744073709551616 = pure (Left 2)
    | otherwise = walk first input []
    where
      walk expected pending leaves
        | B.null pending = pure (Right (B.concat (reverse leaves)))
        | readBE (B.take 8 (B.drop 132 pending)) /= expected = pure (Left 2)
        | otherwise = do
            digest <- validate (ClaimHashes 1 profile (B.take 168 pending) hash)
            if digest /= B.take 32 (B.drop 168 pending) then pure (Left 2)
            else walk (expected+1) (B.drop 200 pending) (digest:leaves)

data ClaimHashes = ClaimHashes Word32 B.ByteString B.ByteString (B.ByteString -> IO B.ByteString)
instance Validation ClaimHashes where
  type ValidationResult ClaimHashes = IO B.ByteString
  validate (ClaimHashes mode profile input hash)
    | mode > 2 || B.length profile /= 69 || B.length input /= 168 = error "invalid claim hash buffers"
    | mode == 0 = burn
    | mode == 1 = leaf (part 96 32)
    | otherwise = do
        identifier <- burn
        digest <- leaf identifier
        pure (identifier <> digest)
    where
      part offset size = B.take size (B.drop offset input)
      burn = checked (B.take 32 (B.drop 5 profile) <> part 0 32 <> part 96 36)
      leaf identifier = checked (B.take 1 profile <> B.drop 37 profile <> B.take 4 (B.drop 1 profile) <>
                                part 0 96 <> identifier <> B.drop 132 input)
      checked bytes = do
        digest <- hash bytes
        if B.length digest == 32 then pure digest else error "invalid claim digest"

data Checkpoint = Checkpoint Word64 Word64 Word8 B.ByteString B.ByteString B.ByteString B.ByteString
  (B.ByteString -> IO B.ByteString)
instance Validation Checkpoint where
  type ValidationResult Checkpoint = IO (Either Int B.ByteString)
  validate (Checkpoint beforeCount afterCount prefix before after emptyRoots profile hash)
    | any ((/=2080) . B.length) [before,after,emptyRoots] || B.length profile < 69 = error "invalid checkpoint buffers"
    | B.all (==0) genesis || B.all (==0) block = pure (Left 1)
    | otherwise = do
        prior <- sane beforeCount before
        if not prior then pure (Left 2) else do
          following <- sane afterCount after
          if not following || afterCount < beforeCount ||
            (beforeCount == afterCount) /= (B.take 32 before == B.take 32 after)
            then pure (Left 2) else do
              result <- checkedDigest hash (B.drop 69 profile <> B.take 4 profile <> genesis <>
                B.take 1 (B.drop 68 profile) <> block <> wordBE 8 beforeCount <> B.take 32 before <>
                wordBE 8 afterCount <> B.take 32 after)
              pure $ if B.all (==0) result then Left 3 else Right result
    where
      genesis = B.take 32 (B.drop 4 profile)
      block = B.take 32 (B.drop 36 profile)
      sane count state = maybe False (const True) <$> validate
        (Accumulator 1 count prefix state emptyRoots (B.replicate 32 0) hash)

data EmptyRoots = EmptyRoots Word8 Word8 (B.ByteString -> IO B.ByteString)
instance Validation EmptyRoots where
  type ValidationResult EmptyRoots = IO B.ByteString
  validate (EmptyRoots leafPrefix nodePrefix hash) = do
    leaf <- checkedDigest hash (B.singleton leafPrefix)
    B.concat <$> levels (64 :: Int) leaf
    where
      levels 0 node = pure [node]
      levels remaining node = do
        parent <- checkedDigest hash (B.singleton nodePrefix <> node <> node)
        (node:) <$> levels (remaining-1) parent

data InclusionProof = InclusionProof Word64 Word8 B.ByteString B.ByteString (B.ByteString -> IO B.ByteString)
instance Validation InclusionProof where
  type ValidationResult InclusionProof = IO (Maybe B.ByteString)
  validate (InclusionProof index prefix emptyRoots leaves hash)
    | B.length emptyRoots /= 2080 || B.length leaves `mod` 32 /= 0 = error "invalid proof buffers"
    | index >= fromIntegral (B.length leaves `div` 32) = pure Nothing
    | otherwise = do
        (root,siblings) <- build 0 (fromIntegral index) nodes
        verified <- foldM (\node (level,sibling) -> if testBit index level
          then branch sibling node else branch node sibling) (nodes !! fromIntegral index) (zip [0..] siblings)
        pure $ if verified == root then Just (root <> B.concat siblings) else Nothing
    where
      nodes = chunks leaves
      chunks bytes | B.null bytes = []
                   | otherwise = B.take 32 bytes : chunks (B.drop 32 bytes)
      empty level = B.take 32 (B.drop (32*level) emptyRoots)
      branch left right = checkedDigest hash (B.singleton prefix <> left <> right)
      build 64 _ layer = pure (head layer,[])
      build level position layer = do
        let siblingIndex = position `xor` 1
            sibling = if siblingIndex < length layer then layer !! siblingIndex else empty level
            pairs [] = pure []
            pairs [left] = (:[]) <$> branch left (empty level)
            pairs (left:right:rest) = (:) <$> branch left right <*> pairs rest
        next <- pairs layer
        (root,siblings) <- build (level+1) (position `div` 2) next
        pure (root,sibling:siblings)

checkedDigest :: (B.ByteString -> IO B.ByteString) -> B.ByteString -> IO B.ByteString
checkedDigest hash input = do
  result <- hash input
  if B.length result /= 32 then error "invalid withdrawal tree digest" else pure result

-- State wire: root followed by 64 frontier hashes. Empty roots include depth 64.
data Accumulator = Accumulator Word32 Word64 Word8 B.ByteString B.ByteString B.ByteString
  (B.ByteString -> IO B.ByteString)
instance Validation Accumulator where
  type ValidationResult Accumulator = IO (Maybe (Word64,B.ByteString))
  validate (Accumulator mode count prefix state emptyRoots leaf hash)
    | mode > 2 || B.length state /= 2080 || B.length emptyRoots /= 2080 || B.length leaf /= 32 =
        error "invalid accumulator inputs"
    | mode == 2 && count == maxBound = pure Nothing
    | mode == 1 && any (\level -> not (testBit count level) && B.any (/=0) (frontier !! level)) [0..63] = pure Nothing
    | otherwise = do
        next <- if mode == 2 then append 0 leaf frontier else pure frontier
        root <- foldM (\node level -> if testBit nextCount level
          then branch (next !! level) node else branch node (at emptyRoots level)) (at emptyRoots 0) [0..63]
        pure $ if mode == 1 && root /= B.take 32 state then Nothing
          else Just (nextCount,root <> B.concat next)
    where
      at bytes n = B.take 32 (B.drop (32*n) bytes)
      frontier = [at state (n+1) | n <- [0..63]]
      nextCount = if mode == 2 then count + 1 else count
      branch left right = checkedDigest hash (B.singleton prefix <> left <> right)
      append level node nodes
        | testBit count level = do
            parent <- branch (nodes !! level) node
            append (level+1) parent (replace level (B.replicate 32 0) nodes)
        | otherwise = pure (replace level node nodes)
      replace n value values = take n values ++ value : drop (n+1) values

-- Keep successful prefixes on overflow, just like sequential native Append calls.
data AccumulatorBatch = AccumulatorBatch Word64 Word8 B.ByteString B.ByteString B.ByteString
  (B.ByteString -> IO B.ByteString)
instance Validation AccumulatorBatch where
  type ValidationResult AccumulatorBatch = IO (Bool, Word64, B.ByteString)
  validate (AccumulatorBatch count prefix state emptyRoots leaves hash)
    | B.length state /= 2080 || B.length emptyRoots /= 2080 || B.length leaves `mod` 32 /= 0 =
        error "invalid accumulator batch inputs"
    | otherwise = append count state leaves
    where
      append cursor current pending
        | B.null pending = pure (True,cursor,current)
        | otherwise = do
            result <- validate (Accumulator 2 cursor prefix current emptyRoots (B.take 32 pending) hash)
            case result of
              Nothing -> pure (False,cursor,current)
              Just (nextCount,next) -> append nextCount next (B.drop 32 pending)

-- Identity errors precede context and activation. Ready only admits the jet.
data ProofGate = ProofGate Word32 Bool Bool
instance Validation ProofGate where
  type ValidationResult ProofGate = Int
  validate (ProofGate identity bmm active)
    | identity > 5 = -1
    | identity /= 0 = fromIntegral identity + 1
    | not bmm = 7
    | not active = 8
    | otherwise = 9

data Annex = Annex Word64 Word64 [Word32] B.ByteString

-- Hashing stays an explicit native effect, reached only after header validation.
data Journal = Journal Word8 Word8 B.ByteString B.ByteString (B.ByteString -> IO B.ByteString)
instance Validation Journal where
  type ValidationResult Journal = IO (Either Int B.ByteString)
  validate (Journal digestMode statementKind bytes guest hashPayload)
    | B.length bytes < 124 = reject 1
    | slice 0 8 /= B.pack [85,83,68,68,74,78,76,49] = reject 2
    | slice 8 2 /= B.pack [0,2] = reject 3
    | byte 10 /= digestMode = reject 4
    | slice 11 8 /= B.pack [83,85,67,67,69,83,83,33] = reject 5
    | byte 19 /= statementKind = reject 6
    | B.length guest /= 32 || slice 20 32 /= guest = reject 7
    | 88 + payloadSize /= fromIntegral (B.length bytes) = reject 8
    | otherwise = do
        digest <- hashPayload payload
        if B.length digest /= 32 then error "invalid USDD journal hash adapter result"
        else if digest /= slice 52 32 then reject 9
        else if B.take 2 payload /= B.pack [0,2] then reject 3
        else case B.unpack (B.take 2 (B.drop 2 payload)) of
          [82,4] -> finish (payloadSize == 790)
          [82,1] -> finish (payloadSize >= 892 && payloadSize <= 13115)
          _ -> reject 10
    where
      reject = pure . Left
      slice offset count = B.take count (B.drop offset bytes)
      byte = B.index bytes
      payload = B.drop 88 bytes
      payloadSize = B.foldl' (\n b -> n * 256 + fromIntegral b) 0 (slice 84 4) :: Word64
      finish valid = if valid then pure (Right (B.take 32 (B.drop 4 payload))) else reject 11

domainIdentity :: Word32 -> Bool -> Bool -> Bool -> Bool -> Int
domainIdentity version badWidth zeroDomain zeroJournal equal
  | badWidth = 4
  | version == 1 = if zeroDomain then 4 else if equal then 0 else 5
  | version == 2 = if not zeroDomain then 4 else if zeroJournal then 5 else 0
  | otherwise = 4

data LegacyRequest = LegacyRequest Word32 Word8 Word8
  B.ByteString B.ByteString B.ByteString B.ByteString B.ByteString B.ByteString
  (B.ByteString -> IO B.ByteString)
instance Validation LegacyRequest where
  type ValidationResult LegacyRequest = IO Int
  validate (LegacyRequest version digestMode statementKind controller expectedController guest expectedGuest journal domain hashPayload)
    | controller /= expectedController = pure 1
    | guest /= expectedGuest = pure 2
    | otherwise = do
        result <- validate (Journal digestMode statementKind journal guest hashPayload)
        pure $ case result of
          Left _ -> 3
          Right journalDomain -> domainIdentity version (B.length domain /= 32)
            (B.all (==0) domain) (B.all (==0) journalDomain) (domain == journalDomain)

-- Resource bits: namespace, oversize, envelope, shape, controller, guest,
-- public values, deployment, domain. Identity is evaluated only after shape.
-- Block reads classify/count, flags, then (only when needed) transaction weight.
-- Codes 1..10 retain the native block rejection order; zero admits the block.
-- Flags: permit peg-ins, candidate-parent context, resource rules enabled.
-- Reads 0..2 are predicates; 3 classifies/counts, 4 projects flags, 5 advances.
data PackageResources = PackageResources Word32 Word64 Word64 Word64 (Word32 -> Word64 -> IO Word64)
instance Validation PackageResources where
  type ValidationResult PackageResources = IO (Int32,Word64)
  validate (PackageResources flags count initial lane action)
    | flags>7 = pure (-1,0)
    | otherwise = scan 0 initial
    where
      scan index current
        | index==count = pure (0,current)
        | otherwise = checks index current ([(0,0) | not (testBit flags 0)] ++ [(1,1)] ++ [(2,1) | testBit flags 1])
      checks index current []
        | not (testBit flags 2) = advance index current
        | otherwise = do
            additional <- action 3 index
            resource <- action 4 index
            if resource>511 then pure (-1,0)
            else if resource .&. 510 /= 0 || exceedsLane lane current additional then pure (1,0)
            else advance index (current+additional)
      checks index current ((step,expected):rest) = action step index >>= \reply ->
        if reply>1 then pure (-1,0) else if reply/=expected then pure (1,0) else checks index current rest
      advance index current = action 5 index >>= \reply ->
        if reply==1 then scan (index+1) current else pure (-1,0)

-- Resolve activation in this workflow, without returning to a native dispatcher.
-- Native steps 17..30 supply the standalone activation runner's fourteen facts.
data PolicyResources = PolicyResources Word64 (IO (Int32,Word64)) (Word32 -> Word64 -> IO Word64)
instance Validation PolicyResources where
  type ValidationResult PolicyResources = IO (Int32,Word64)
  validate (PolicyResources count classify action) = do
    (flags,_) <- classify
    code <- if flags<0 || flags>511 then pure (-1)
      else validate (PolicyWithActivation (fromIntegral flags) count action)
    pure (code,0)

data PolicyWithActivation = PolicyWithActivation Word32 Word64 (Word32 -> Word64 -> IO Word64)
instance Validation PolicyWithActivation where
  type ValidationResult PolicyWithActivation = IO Int32
  validate (PolicyWithActivation flags count action) = validate (PolicyWeight flags count readPolicy)
    where
      readPolicy step index
        | step/=1 = action step index
        | otherwise = do
            verdict <- validate (CommandFlow 14 (\phase reply -> validate (ActivationPolicyFlow phase reply))
              (\phase -> action (phase+16) index >>= \reply -> pure (if reply<=1 then fromIntegral reply else -1)))
            pure $ case verdict of 0 -> 1; 1 -> 0; _ -> 2

data PolicyWeight = PolicyWeight Word32 Word64 (Word32 -> Word64 -> IO Word64)
instance Validation PolicyWeight where
  type ValidationResult PolicyWeight = IO Int32
  validate (PolicyWeight flags count action)
    | flags>511 = pure (-1)
    | otherwise = case [code | (bit,code) <- zip [1..8] [1,1,2,3,4,5,6,7], testBit flags bit] of
        code:_ -> pure code
        [] -> scan 0 False
    where
      scan index found
        | index==count = pure 0
        | otherwise = branch 0
            (branch 1 next (branch 2 (branch 3 publish (pure 1)) (pure 1))) next
        where
          next = scan (index+1) found
          branch step yes no = action step index >>= \reply -> case reply of
            0 -> no
            1 -> yes
            _ -> pure (-1)
          publish = if found then pure 8 else action 4 index >>= \reply ->
            if reply==1 then scan (index+1) True else pure (-1)

data BlockResources = BlockResources Word64 Word64 Word64 (Word32 -> Word64 -> IO Word64)
instance Validation BlockResources where
  type ValidationResult BlockResources = IO (Int32,Word64)
  validate (BlockResources count lane weightLimit readField) = scan 0 0
    where
      scan index total
        | index == count = pure (0,total)
        | otherwise = do
            additional <- readField 0 index
            flags <- readField 1 index
            if flags > 511 then pure (-1,0) else
              case [code | (bit,code) <- [(1,1),(2,2),(3,3)], testBit flags bit] of
                code:_ -> pure (code,0)
                [] -> do
                  overweight <- if additional==0 then pure False else (>weightLimit) <$> readField 2 index
                  if overweight then pure (4,0)
                  else if exceedsLane lane total additional then pure (5,0)
                  else case [code | (bit,code) <- zip [4..8] [6..10], testBit flags bit] of
                    code:_ -> pure (code,0)
                    [] -> scan (index+1) (total+additional)

-- Classification supplies both results directly; no native flag projection or
-- recursive foreign entry is needed by either enclosing admission workflow.
data ResourceAdmission = ResourceAdmission Bool Word32 Word64 Word64 Word64 Word64
  (Word64 -> IO (Int32,Word64)) (Word32 -> Word64 -> IO Word64)
instance Validation ResourceAdmission where
  type ValidationResult ResourceAdmission = IO (Int32,Word64)
  validate (ResourceAdmission package flags count initial lane weight classify action) = do
    current <- newIORef (maxBound :: Word64)
    let stepClassify = if package then 3 else 0
        readField step index
          | step==stepClassify = do
              (resource,used) <- classify index
              writeIORef current (fromIntegral resource)
              pure used
          | step==stepClassify+1 = readIORef current
          | otherwise = action step index
    if package then validate (PackageResources flags count initial lane readField)
    else validate (BlockResources count lane weight readField)

data ResourceScan = ResourceScan Word64 (Word64 -> IO Int)
instance Validation ResourceScan where
  type ValidationResult ResourceScan = IO (Int32,Word64)
  validate (ResourceScan count classify) = go 0 0 0
    where
      go index !flags !total
        | index==count = pure (fromIntegral flags,total)
        | otherwise = classify index >>= \result ->
            if result<0 || result>511 then pure (-1,0)
            else go (index+1) (flags .|. result) (total+fromIntegral (result .&. 1))

data Resource = Resource Annex Word64 Word64 Word64 Word64 Bool (IO Int)
instance Validation Resource where
  type ValidationResult Resource = IO Int
  validate (Resource annex@(Annex size limit _ bytes) count cmrSize controlSize leaf parameterized identity)
    | count < 2 || B.take 5 bytes /= B.pack [80,85,83,68,68] = pure 0
    | parsed < 0 = pure (-1)
    | parsed == 11 = pure (base .|. 64)
    | parsed /= 0 = pure (base .|. 4)
    | parameterized && B.index bytes 11 /= 3 = pure (base .|. 4)
    | count /= 5 || cmrSize /= 32 || controlSize < 33 || controlSize > 4129 ||
      (controlSize - 33) `mod` 32 /= 0 || leaf .&. 254 /= 190 = pure (base .|. 8)
    | parameterized = pure base
    | otherwise = do
        result <- identity
        pure $ if result < 0 || result > 5 then -1
          else base .|. if result == 0 then 0 else 1 `shiftL` (result + 3)
    where
      parsed = validate annex
      base = 1 .|. if size > limit then 2 else 0

data Admission = Admission Word32 Annex Bool Bool (IO Int)
instance Validation Admission where
  type ValidationResult Admission = IO Int
  validate (Admission lane annex bmm active identity)
    | lane /= 1 && lane /= 2 = pure (-1)
    | otherwise = admitResult lane annex bmm active $ if lane == 2 then pure 0 else do
        facts <- identity
        pure $ if facts < 0 || facts > 15 then -1
          else if testBit facts 0 then 4 else if testBit facts 1 then 1
          else if testBit facts 2 then 2 else if testBit facts 3 then 3 else 0

admitResult :: Word32 -> Annex -> Bool -> Bool -> IO Int -> IO Int
admitResult lane annex@(Annex _ _ _ bytes) bmm active identity
    | lane > 2 = pure (-1)
    | parsed < 0 = pure (-1)
    | parsed == 1 = pure 0
    | parsed /= 0 = pure 1
    | B.index bytes 11 /= (if lane == 0 then 1 else 3) = pure 5
    | otherwise = do
        result <- identity
        pure $ if result < 0 || result > 5 then -1
          else validate (ProofGate (fromIntegral result) bmm active)
    where parsed = validate annex

instance Validation Annex where
  type ValidationResult Annex = Int
  validate (Annex size limit profile bytes)
    | B.length bytes /= fromIntegral (min size 87) || length profile /= 3 = -1
    | B.take 5 bytes /= B.pack [80,85,83,68,68] = 1
    | size > limit = 2
    | size < 55 = 3
    | slice 1 8 /= B.pack [85,83,68,68,83,80,49,0] = 4
    | byte 9 /= profile !! 0 = 5
    | byte 10 /= profile !! 1 = 6
    | kind /= 1 && kind /= 3 = 7
    | byte 12 /= profile !! 2 = 8
    | byte 13 /= 0 || byte 14 /= 0 = 9
    | public == 0 = 10
    | public > 16384 = 11
    | kind == 3 && public /= 32 = 12
    | proof == 0 = 13
    | B.all (==0) (slice 23 32) = 14
    | 55 + public + proof /= size = 15
    | kind == 3 && B.all (==0) (slice 55 32) = 12
    | otherwise = 0
    where
      slice offset count = B.take count (B.drop offset bytes)
      byte offset = fromIntegral (B.index bytes offset) :: Word32
      word offset = B.foldl' (\n b -> n * 256 + fromIntegral b) 0 (slice offset 4) :: Word64
      kind = byte 11
      public = word 15
      proof = word 19
