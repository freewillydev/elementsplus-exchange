{-# LANGUAGE ForeignFunctionInterface #-}
module ExchangeTests (exchangeArithmetic, exchangeAbi, cursorAbi, authorityOrder, forcedAbi, profileOrder, trancheParity, trackerOrder, configurationOrder, headerOrder, parentTarget, connectionOrder, disconnectOrder, availabilityOrder, sourceMarkerAbi, m6Abi, invalidPhaseLazy, envelopeRequirementAbi, checkpointOrder, capitalIdentityAbi, genesisInitializationOrder, deploymentOrder, frozenBoundsAbi, distinctAbi, registryAbi, requiredIdentityOrder, physicalOrder, spendSelection, transactionShapeOrder, genesisFundingAbi, genesisStateAbi, genesisCovenantAbi, tapPreimageAbi, inboxEntryAbi, transactionAdmissionAbi, publicTransactionAdmissionAbi) where

import Control.Operation.Validation
import qualified Control.Operation as Operation
import Data.Word (Word32, Word64)
import Data.Int (Int32)
import Exchange
import Test.QuickCheck hiding (total, output)
import Drivechain (elements_hs_exchange_inbox, elements_hs_exchange_cursors, elements_hs_exchange_authority, elements_hs_exchange_forced_body, elements_hs_exchange_profile, elements_hs_exchange_tranche, elements_hs_exchange_tracker, elements_hs_exchange_configuration)
import qualified Data.ByteString as B
import Data.Bits (testBit)
import Data.IORef (newIORef, modifyIORef', readIORef)
import Control.Exception (try, throwIO, IOException, bracket)
import Foreign.Marshal.Array (withArray, peekArray, pokeArray)
import Foreign.Ptr (Ptr, nullPtr, nullFunPtr, castPtr, plusPtr, FunPtr, freeHaskellFunPtr)
import Withdrawal (wordLE, wordBE)
import Drivechain (elements_hs_exchange_header)
import Drivechain (elements_hs_exchange_parent_target)
import Drivechain (elements_hs_exchange_connection)
import Drivechain (elements_hs_exchange_disconnect)
import Drivechain (elements_hs_exchange_availability)
import Drivechain (elements_hs_exchange_source_marker)
import Drivechain (elements_hs_exchange_m6)
import Drivechain (elements_hs_exchange_envelope_requirement, elements_hs_exchange_envelope_header)
import Drivechain (elements_hs_exchange_checkpoint)
import Drivechain (elements_hs_exchange_capital_identity, elements_hs_exchange_capital)
import Drivechain (elements_hs_exchange_genesis_initialization)
import Drivechain (elements_hs_exchange_deployment)
import Drivechain (elements_hs_exchange_frozen_bounds, elements_hs_exchange_frozen_configuration)
import Drivechain (elements_hs_exchange_distinct, elements_hs_exchange_identity_relation)
import Drivechain (elements_hs_exchange_registry)
import Drivechain (elements_hs_exchange_required_identities)
import Drivechain (elements_hs_exchange_physical_inputs)
import Drivechain (elements_hs_exchange_spend_scan)
import Drivechain (elements_hs_exchange_transaction_shape)
import Drivechain (elements_hs_exchange_genesis_funding)
import Drivechain (elements_hs_exchange_genesis_state)
import Drivechain (elements_hs_exchange_inbox_entry)
import Drivechain (elements_hs_exchange_bond_marker)
import Drivechain (elements_hs_exchange_receipts)
import Drivechain (elements_hs_exchange_annex_header)
import Drivechain (CustodyHash, elements_hs_exchange_custody_root, elements_hs_exchange_genesis_roots)
import Drivechain (elements_hs_exchange_append_marker)
import Drivechain (elements_hs_exchange_sources)
import Drivechain (elements_hs_exchange_source_admission)
import Drivechain (elements_hs_exchange_registry_decode)
import Drivechain (DeriveTransactionAssets, elements_hs_exchange_transaction_admission)
import BmmConstants (bondFixedSupply)

foreign import ccall "wrapper" makeCustodyHash :: CustodyHash -> IO (FunPtr CustodyHash)
foreign import ccall "wrapper" makeShapeRead :: (Ptr () -> Word32 -> IO Int32) -> IO (FunPtr (Ptr () -> Word32 -> IO Int32))
foreign import ccall "wrapper" makeTransactionAssets :: DeriveTransactionAssets -> IO (FunPtr DeriveTransactionAssets)

transactionAdmissionAbi :: Property
transactionAdmissionAbi = forAll ((,,,) <$> flags 127 <*> flags 31 <*> flags 3 <*> flags 3) $
  \(inputs,outputs,outputWitnesses,inputWitnesses) -> ioProperty $ do
    let parts = map B.pack [inputs,outputs,outputWitnesses,inputWitnesses]
        bytes = B.concat (map (wordLE 8 . fromIntegral . B.length) parts ++ parts)
        expected = [all (\n -> not (testBit n 0) && testBit n 1) inputs,
          all (\n -> all (testBit n) [0,1,2]) outputs &&
          all (\n -> (testBit n 2 || testBit n 3) && (testBit n 4 || testBit n 5)) inputs &&
          all (==3) outputWitnesses && all (==3) inputWitnesses]
        call mode dataBytes = B.useAsCStringLen dataBytes $ \(ptr,size) ->
          elements_hs_exchange_transaction_admission mode (fromIntegral size) (castPtr ptr) 0 0 0 0 nullFunPtr nullPtr
    results <- mapM (`call` bytes) [0,1]
    bad <- sequence [call 4 bytes, call 0 (bytes <> B.singleton 0),
      call 0 (B.replicate 8 255 <> B.drop 8 bytes), call 1 (B.take 31 bytes),
      elements_hs_exchange_transaction_admission 0 maxBound nullPtr 0 0 0 0 nullFunPtr nullPtr]
    pure $ conjoin [results === map (\ok -> if ok then 1 else 0) expected, bad === replicate 5 (-1)]
  where flags limit = resize 40 (listOf (choose (0,limit)))

publicTransactionAdmissionAbi :: Property
publicTransactionAdmissionAbi = forAll (choose (0,18 :: Int)) $ \mutation -> ioProperty $ do
  calls <- newIORef (0 :: Int)
  let asset = B.replicate 32 1; token = B.replicate 32 2
      issuance = B.singleton (if mutation == 1 then 105 else 104) <>
        wordLE 8 (if mutation == 2 then bondFixedSupply-1 else bondFixedSupply) <> wordLE 8 1
      output identity amount flags = B.singleton flags <> identity <> wordLE 8 amount
      inventory = output asset (if mutation == 3 then bondFixedSupply-1 else bondFixedSupply) (if mutation == 4 then 15 else 7)
      burn = output token 1 (if mutation == 5 then 7 else 23)
      extra = if mutation == 6 then output asset 0 7 else B.empty
      bytes = wordLE 8 1 <> wordLE 8 (if mutation == 6 then 3 else 2) <> wordLE 8 1 <> wordLE 8 1 <>
        issuance <> inventory <> burn <> extra <> B.pack [if mutation == 7 then 1 else 3,3]
      derive _ ptr = do
        before <- peekArray 64 ptr
        if before /= replicate 64 0 then error "uninitialized transaction asset buffer" else pure ()
        modifyIORef' calls (+1)
        pokeArray ptr (B.unpack (asset <> if mutation == 8 then asset else token))
        pure (if mutation == 9 then -1 else 1)
      call reader encoded i o b = B.useAsCStringLen encoded $ \(ptr,size) ->
        elements_hs_exchange_transaction_admission 2 (fromIntegral size) (castPtr ptr) i o b 0 reader nullPtr
      indices = case mutation of 10 -> (1,0,1); 11 -> (0,0,0); 12 -> (0,0,2); 13 -> (maxBound,0,1); _ -> (0,0,1)
      body = case mutation of 14 -> B.init bytes; 15 -> bytes <> B.singleton 0; 16 -> B.replicate 8 255 <> B.drop 8 bytes; _ -> bytes
      early = mutation `elem` [1,2,7,10,11,12,13,14,15,16]
      expected = if mutation `elem` [9,14,15,16,17] then -1 else if mutation `elem` [0,18] then 1 else 0
  result <- bracket (makeTransactionAssets derive) freeHaskellFunPtr $ \reader ->
    let (i,o,b) = indices in call (if mutation == 17 then nullFunPtr else reader) body i o b
  observed <- readIORef calls
  pure $ conjoin [result === expected, observed === if early || mutation == 17 then 0 else 1]

inboxEntryAbi :: Property
inboxEntryAbi = conjoin [inboxEventAbi, inboxStepAbi, bondEntryAbi, markerContextAbi, markerFrameAbi, legacyMarkerFrameAbi, cursorPayloadAbi, custodyReceiptsAbi, annexHeaderAbi, custodyRootOrder, custodyRootAbi, sourceAdmissionOrder, sourceAuthorizationAbi, registryCodecAbi, registryEncodingAbi, appendMarkerAbi, sourceTrackingAbi, sourcePredecessorAbi, stagingEncodingAbi, deploymentEncodingAbi]

cursorPayloadAbi :: Property
cursorPayloadAbi = forAll (choose (0,22)) $ \size ->
  forAll (vectorOf 17 arbitrary) $ \body -> forAll arbitrary $ \matching -> ioProperty $ do
    let input = take size ((if matching then [69,67,88,67,1] else [0,67,88,67,1]) ++ body)
        recognized = length input >= 4 && take 4 input == [69,67,88,67]
        status = if not recognized then 0 else if size == 21 then 1 else 2
        expected = status : if status == 1 then drop 5 input else replicate 16 0
    withArray (replicate 7 0) $ \fields -> withArray (input ++ [0]) $ \source ->
      withArray (replicate 19 0xa5) $ \output -> do
        code <- elements_hs_exchange_inbox_entry 18 fields (fromIntegral size) source 17 (output `plusPtr` 1)
        bytes <- peekArray 19 output
        invalid <- sequence [elements_hs_exchange_inbox_entry 18 fields n source cap output |
          (n,cap) <- [(23,17),(maxBound,17),(fromIntegral size,16),(fromIntegral size,18)]]
        absent <- elements_hs_exchange_inbox_entry 18 fields (fromIntegral size) nullPtr 17 output
        noOutput <- elements_hs_exchange_inbox_entry 18 fields (fromIntegral size) source 17 nullPtr
        preserved <- peekArray 19 output
        pure $ conjoin [code === 0, bytes === (0xa5 : expected ++ [0xa5]),
          validate (CursorPayload (B.pack input)) === Just (B.pack expected),
          invalid === replicate 4 (-1), absent === (-1), noOutput === (-1), preserved === bytes]

deploymentEncodingAbi :: Property
deploymentEncodingAbi = forAll ((,,,) <$> elements [0,1,2,3,4,maxBound :: Word64] <*> index <*> index <*> index) $ \(version,previous,inventory,burn) ->
  forAll (vectorOf 192 arbitrary) $ \input -> ioProperty $ do
    let deploymentFits = version `elem` [2,3] && all (<=4294967295) [previous,inventory,burn]
        be n = B.unpack . wordBE n
        expected = [if version==3 then 3 else 1] ++ take 64 input ++ be 4 previous ++ take 64 (drop 64 input) ++
          be 8 2100000000000000 ++ be 4 inventory ++ be 4 burn ++ drop 128 input
    withArray [version,previous,inventory,burn,0,0,0] $ \fields -> withArray input $ \source ->
      withArray (replicate 215 0xa5) $ \output -> do
        code <- elements_hs_exchange_inbox_entry 15 fields 192 source 213 (output `plusPtr` 1)
        result <- peekArray 215 output
        bad <- sequence [elements_hs_exchange_inbox_entry 15 f n s cap o |
          (f,n,s,cap,o) <- [(nullPtr,192,source,213,output),(fields,192,nullPtr,213,output),
            (fields,192,source,213,nullPtr),(fields,191,source,213,output),(fields,193,source,213,output),
            (fields,192,source,212,output),(fields,192,source,214,output)]]
        preserved <- peekArray 215 output
        pure $ conjoin [code === (if deploymentFits then 0 else -1),bad === replicate 7 (-1),preserved === result,
          result === (if deploymentFits then [0xa5] ++ expected ++ [0xa5] else replicate 215 0xa5)]
  where index = elements [0,1,4294967295,4294967296,maxBound :: Word64]

stagingEncodingAbi :: Property
stagingEncodingAbi = forAll arbitrary $ \hidden ->
  forAll (elements [0,1,190,255,256,4294967295,4294967296,maxBound :: Word64]) $ \first ->
  forAll arbitrary $ \second -> forAll (vectorOf (if hidden then 192 else 128) arbitrary) $ \input -> ioProperty $ do
    let width = if hidden then 204 else 130
        mode = if hidden then 14 else 13
        stagingFits = first <= (if hidden then 4294967295 else 255)
        be n = B.unpack . wordBE n
        expected = if hidden then take 160 input ++ be 4 first ++ drop 160 input ++ be 8 second
                   else [1] ++ take 32 input ++ [fromIntegral first] ++ drop 32 input
    withArray [first,second,0,0,0,0,0] $ \fields -> withArray input $ \source ->
      withArray (replicate (width+2) 0xa5) $ \output -> do
        code <- elements_hs_exchange_inbox_entry mode fields (fromIntegral (length input)) source (fromIntegral width) (output `plusPtr` 1)
        result <- peekArray (width+2) output
        bad <- elements_hs_exchange_inbox_entry mode fields (fromIntegral (length input)) source (fromIntegral (width-1)) output
        preserved <- peekArray (width+2) output
        pure $ conjoin [code === (if stagingFits then 0 else -1), bad === (-1), preserved === result,
          result === (if stagingFits then [0xa5] ++ expected ++ [0xa5] else replicate (width+2) 0xa5)]

sourcePredecessorAbi :: Property
sourcePredecessorAbi = forAll ((,,,,,,) <$> elements [0,1,2] <*> elements [0,1,2] <*>
    elements [0,1,maxBound :: Word64] <*> elements [0,1,maxBound :: Word64] <*>
    arbitrary <*> counter <*> counter) $ \(profile,proof,height,parent,zeroHead,count,processed) -> ioProperty $ do
  let encode n = B.unpack (wordBE 8 (fromInteger (n `div` 18446744073709551616)) <> wordBE 8 (fromInteger n))
      input = replicate 32 (if zeroHead then 0 else 1) ++ encode count ++ encode processed
      expected | profile>1 = -1
               | (profile==1 && proof `notElem` [1,2]) || height==0 || parent==0 || zeroHead || count<processed = 1
               | profile==0 && count>18446744073709551615 = 2
               | otherwise = 0
  withArray [profile,proof,height,parent,0,0,0] $ \fields -> withArray input $ \source ->
    withArray (replicate 50 0xa5) $ \output -> do
      code <- elements_hs_exchange_inbox_entry 12 fields 64 source 48 (output `plusPtr` 1)
      result <- peekArray 50 output
      bad <- sequence [elements_hs_exchange_inbox_entry 12 f n s cap o |
        (f,n,s,cap,o) <- [(nullPtr,64,source,48,output),(fields,64,nullPtr,48,output),
          (fields,64,source,48,nullPtr),(fields,63,source,48,output),(fields,64,source,47,output)]]
      preserved <- peekArray 50 output
      pure $ conjoin [code === expected, bad === replicate 5 (-1), preserved === result,
        result === (if expected==0 then [0xa5] ++ take 48 input ++ [0xa5] else replicate 50 0xa5)]
  where counter = frequency [(3,elements [0,1,18446744073709551615,18446744073709551616,340282366920938463463374607431768211455]),
                             (1,choose (0,340282366920938463463374607431768211455 :: Integer))]

sourceTrackingAbi :: Property
sourceTrackingAbi = forAll (choose (0,3 :: Int)) $ \mode -> forAll (choose (0,8 :: Int)) $ \prefixCount ->
  forAll ((,,,,,) <$> width <*> width <*> width <*> width <*> width <*> width) $
    \(witnessTotal,transaction,addedWitness,addedTransaction,capWitness,capTransaction) -> ioProperty $ do
  let values = [witnessTotal,transaction,addedWitness,addedTransaction,capWitness,capTransaction]
      encode = B.unpack . wordBE 4
      identities = replicate 32 0x11 ++ replicate 64 0x22
      incoming = if mode==0 then replicate 32 0x33 ++ drop 32 identities
                 else if mode==2 then take 95 identities ++ [0x44] else identities
      record = identities ++ encode addedWitness ++ encode addedTransaction
      history = concat [replicate 32 (fromIntegral n) ++ drop 32 record | n <- [1..prefixCount]] ++ record
      initial = if mode==3 then replicate 7 0 else encode witnessTotal ++ encode transaction ++ history
      nextWitness = witnessTotal+addedWitness
      nextTransaction = transaction+addedTransaction
      expectedCode | mode==3 = -1
                   | mode==2 = 3
                   | mode==1 = 0
                   | nextWitness>4294967295 || nextTransaction>4294967295 = 1
                   | nextWitness>capWitness || nextTransaction>capTransaction = 2
                   | otherwise = 0
      expectedState = if mode==1 then initial else encode nextWitness ++ encode nextTransaction ++ history ++
                          incoming ++ encode addedWitness ++ encode addedTransaction
      capacity = length initial+104
  withArray (drop 2 values) $ \fields -> withArray incoming $ \hashes -> withArray initial $ \source ->
    withArray (replicate (capacity+2) 0xa5) $ \output -> withArray [999] $ \written -> do
      code <- elements_hs_exchange_sources fields hashes (fromIntegral (length initial)) source (output `plusPtr` 1) written
      result <- peekArray (capacity+2) output
      size <- peekArray 1 written
      invalid <- sequence [elements_hs_exchange_sources f h n s o w |
        (f,h,n,s,o,w) <- [(nullPtr,hashes,112,source,output,written),(fields,nullPtr,112,source,output,written),
          (fields,hashes,112,nullPtr,output,written),(fields,hashes,112,source,nullPtr,written),
          (fields,hashes,112,source,output,nullPtr),(fields,hashes,maxBound,source,output,written)]]
      preserved <- peekArray (capacity+2) output
      preservedSize <- peekArray 1 written
      pure $ conjoin [code === expectedCode, invalid === replicate 6 (-1), preserved === result,
        preservedSize === size,
        size === [if expectedCode==0 then fromIntegral (length expectedState) else 999],
        result === (if expectedCode/=0 then replicate (capacity+2) 0xa5 else
          [0xa5] ++ expectedState ++ replicate (capacity+1-length expectedState) 0xa5)]
  where width = frequency [(2,elements [0,1,4294967294,4294967295]),(3,choose (0,4294967295 :: Word64))]

appendMarkerAbi :: Property
appendMarkerAbi = forAll arbitrary $ \wide -> forAll (choose (0,6 :: Int)) $ \failure ->
  forAll (choose (0, maxBound-1 :: Word64)) $ \upper ->
  forAll (frequency [(1,elements [0,255,65535,maxBound-1,if wide then maxBound else 1]),
                     (3,choose (0,maxBound-1 :: Word64))]) $ \index -> ioProperty $ do
    let count = if failure == 3 then maxBound else index
        high = if wide then upper else 0
        counter = if failure == 3 then replicate 16 255 else B.unpack (wordBE 8 high <> wordBE 8 index)
        next = B.unpack (wordBE 8 (high + if index==maxBound then 1 else 0) <> wordBE 8 (index+1))
        fields = [if wide then 1 else 0,100,6,0,0,0,if failure==1 then 8 else 0,8,if wide then 0 else count,0,0,10,2000,1500]
        script = [if failure==2 then 0 else 106,77,247,1,69,67,88,66,if wide then 3 else 1,0] ++ replicate 497 0
        input = replicate 160 0x11 ++ counter ++ script
        expectedCode | failure==1 || (failure==3 && not wide) = 3
                     | failure==2 = 4
                     | failure==3 = 5
                     | failure>=4 = -1
                     | otherwise = 0
        expectedCalls | failure==1 || failure==2 || (failure==3 && not wide) = []
                      | failure>=4 = take (failure-3) [0,1,2]
                      | otherwise = [0,1,2]
    withArray fields $ \raw -> withArray input $ \source -> withArray (replicate 50 0xa5) $ \output -> do
      calls <- newIORef []
      callback <- makeCustodyHash $ \_ kind size bytes digest -> do
        payload <- peekArray (fromIntegral size) bytes
        modifyIORef' calls (++ [(kind,payload)])
        if failure==fromIntegral kind+4 then pure (-1)
        else pokeArray digest (replicate 32 (fromIntegral kind)) >> pure 0
      code <- elements_hs_exchange_append_marker raw source callback nullPtr (output `plusPtr` 1)
      actual <- peekArray 50 output
      invalid <- sequence [elements_hs_exchange_append_marker f b c nullPtr o |
        (f,b,c,o) <- [(nullPtr,source,callback,output),(raw,nullPtr,callback,output),
                      (raw,source,nullFunPtr,output),(raw,source,callback,nullPtr)]]
      preserved <- peekArray 50 output
      seen <- readIORef calls
      freeHaskellFunPtr callback
      pure $ conjoin [code === expectedCode, invalid === replicate 4 (-1), preserved === actual,
        map fst seen === expectedCalls,
        property (all (\(kind,payload) -> length payload == (if kind==0 then if wide then 716 else 708
          else if kind==1 then if wide then 708 else 700 else if wide then 80 else 72)) seen),
        actual === (if expectedCode/=0 then replicate 50 0xa5 else
          [0xa5] ++ replicate 32 2 ++ next ++ [0xa5])]

registryEncodingAbi :: Property
registryEncodingAbi = forAll (vectorOf 320 arbitrary) $ \input -> ioProperty $
  withArray input $ \source -> withArray (replicate 7 0) $ \fields -> withArray (replicate 327 0xa5) $ \output -> do
    let expected = concat [[fromIntegral (i+1)] ++ take 32 (drop (32*i) input) ++ take 32 (drop (160+32*i) input) | i <- [0..4]]
    code <- elements_hs_exchange_inbox_entry 11 fields 320 source 325 (output `plusPtr` 1)
    bytes <- peekArray 327 output
    invalid <- sequence [elements_hs_exchange_inbox_entry mode fields size source capacity output |
      (mode,size,capacity) <- [(12,320,325),(11,319,325),(11,321,325),(11,320,324),(11,320,326),(11,maxBound,325)]]
    noInput <- elements_hs_exchange_inbox_entry 11 fields 320 nullPtr 325 output
    noOutput <- elements_hs_exchange_inbox_entry 11 fields 320 source 325 nullPtr
    preserved <- peekArray 327 output
    pure $ conjoin [code === 0, bytes === ([0xa5] ++ expected ++ [0xa5]), invalid === replicate 6 (-1),
      noInput === (-1), noOutput === (-1), preserved === bytes]

registryCodecAbi :: Property
registryCodecAbi = forAll (choose (0,4)) $ \failed -> forAll arbitrary $ \duplicate -> ioProperty $ do
  let key i = replicate 32 (fromIntegral (i+10 :: Int))
      records = [[fromIntegral (i+1)] ++ key i ++ key (i+5) | i <- [0..4]]
      changed = if duplicate && failed>0 then [fromIntegral (failed+1)] ++ key 0 ++ key (failed+5) else 0:tail (records !! failed)
      input = concat (take failed records ++ [changed] ++ drop (failed+1) records)
      count = if duplicate && failed>0 then failed+1 else failed
      expected = concatMap tail (take count (take failed records ++ [changed]))
  withArray input $ \source -> withArray (replicate 322 0xa5) $ \output -> withArray (replicate 3 0xa5) $ \counts -> do
    code <- elements_hs_exchange_registry_decode 325 source (output `plusPtr` 1) (counts `plusPtr` 8)
    bytes <- peekArray 322 output
    values <- peekArray 3 counts
    invalid <- sequence [elements_hs_exchange_registry_decode n ptr out cnt |
      (n,ptr,out,cnt) <- [(324,source,output,counts),(326,source,output,counts),(maxBound,source,output,counts),
        (325,nullPtr,output,counts),(325,source,nullPtr,counts),(325,source,output,nullPtr)]]
    preserved <- peekArray 322 output
    preservedCounts <- peekArray 3 counts
    let raw = concatMap key [0..4] ++ concatMap key [5..9]
    pure $ conjoin [code === (if duplicate && failed>0 then 2 else 1), values === [0xa5,fromIntegral count,0xa5],
      bytes === ([0xa5] ++ expected ++ replicate (321-length expected) 0xa5), invalid === replicate 6 (-1),
      preserved === bytes, preservedCounts === values,
      validate (RegistryEncoding (B.pack raw)) === Just (B.pack (concat records))]

sourceAuthorizationAbi :: Property
sourceAuthorizationAbi = forAll arbitrary $ \staged -> forAll arbitrary $ \value ->
  forAll (choose (1,256)) $ \bodyLength -> forAll (vectorOf 128 arbitrary) $ \hashes ->
  forAll (vectorOf bodyLength arbitrary) $ \body -> ioProperty $ do
    let input = if staged then take 64 hashes ++ body else hashes
        be n v = B.unpack (B.reverse (wordLE n v))
        expected = if staged then be 4 (fromIntegral bodyLength) ++ body ++ take 64 hashes ++ be 8 value
                   else hashes ++ be 4 value
        mode = if staged then 10 else 9
        size = fromIntegral (length input)
        capacity = fromIntegral (length expected)
    withArray (value:replicate 6 0) $ \fields -> withArray input $ \source -> withArray (replicate (length expected+2) 0xa5) $ \output -> do
      code <- elements_hs_exchange_inbox_entry mode fields size source capacity (output `plusPtr` 1)
      bytes <- peekArray (length expected+2) output
      invalid <- sequence [elements_hs_exchange_inbox_entry m fields n source cap output |
        (m,n,cap) <- [(11,size,capacity),(mode,size,capacity-1),(mode,size,capacity+1),(mode,maxBound,capacity),(10,64,76),(9,127,132)]]
      noInput <- elements_hs_exchange_inbox_entry mode fields size nullPtr capacity output
      noFields <- elements_hs_exchange_inbox_entry mode nullPtr size source capacity output
      noOutput <- elements_hs_exchange_inbox_entry mode fields size source capacity nullPtr
      preserved <- peekArray (length expected+2) output
      pure $ conjoin [code === 0, bytes === ([0xa5] ++ expected ++ [0xa5]), invalid === replicate 6 (-1),
        noInput === (-1), noFields === (-1), noOutput === (-1), preserved === bytes]

sourceAdmissionOrder :: Property
sourceAdmissionOrder = forAll (vectorOf 16 arbitrary) $ \factMask ->
  forAll (choose (0,16)) $ \throws -> ioProperty $ do
    let fields = zipWith (\ok value -> if ok then value else 0) factMask ([1,1,1,1,1,65536,8,589824,786432,1,1,1,1,1,786432,589824] :: [Word64])
        failed = length (takeWhile (/=0) fields)
        stop = min throws failed
        expected = if failed==16 then 0 else if failed<9 then 1 else if failed<14 then 2 else failed-11
    seen <- newIORef []
    result <- try (validate (SourceAdmission (\index -> do
      modifyIORef' seen (++ [index])
      if index==fromIntegral throws then throwIO (userError "source read") else pure (fields !! fromIntegral index)))) :: IO (Either IOException Int)
    observed <- readIORef seen
    absent <- elements_hs_exchange_source_admission nullFunPtr nullPtr
    pure $ conjoin [observed === map fromIntegral [0..min stop 15], absent === (-1), case result of
      Left _ -> property (throws<=failed && throws<16)
      Right code -> conjoin [property (throws>failed || throws==16), code === expected]]

custodyRootAbi :: Property
custodyRootAbi = forAll arbitrary $ \fails -> ioProperty $
  withArray (replicate 192 0) $ \identities -> withArray [0] $ \receipts -> withArray (replicate 34 0xa5) $ \output -> do
    calls <- newIORef []
    callback <- makeCustodyHash $ \_ kind size _ digest -> do
      modifyIORef' calls (++ [(kind,size)])
      if fails then pure (-1) else pokeArray digest (replicate 32 0x42) >> pure 0
    code <- elements_hs_exchange_custody_root 1 identities 0 receipts callback nullPtr (output `plusPtr` 1)
    bytes <- peekArray 34 output
    bad <- sequence [elements_hs_exchange_custody_root amount ids size input cb nullPtr out |
      (amount,ids,size,input,cb,out) <- [(maxBound,identities,0,receipts,callback,output),
        (1,identities,691,receipts,callback,output),(1,identities,1,receipts,callback,output),
        (1,nullPtr,0,receipts,callback,output),(1,identities,0,nullPtr,callback,output),
        (1,identities,0,receipts,nullFunPtr,output),(1,identities,0,receipts,callback,nullPtr)]]
    preserved <- peekArray 34 output
    seen <- readIORef calls
    freeHaskellFunPtr callback
    pure $ conjoin [code === (if fails then -1 else 0), bytes === (if fails then replicate 34 0xa5 else [0xa5] ++ replicate 32 0x42 ++ [0xa5]),
      bad === replicate 7 (-1), seen === [(2,0)], preserved === bytes]

custodyRootOrder :: Property
custodyRootOrder = forAll (choose (0,5)) $ \count -> forAll (choose (0,30)) $ \failed ->
  forAll (vectorOf (count*138) arbitrary) $ \receipts -> ioProperty $ do
    observed <- newIORef []
    let width = until (>= max 1 count) (*2) 1
        steps = if count==0 then [2] else concat (replicate count [0,1]) ++ replicate count 3 ++ [4] ++ replicate (width-1) 5
        callback kind bytes = do
          seen <- readIORef observed
          modifyIORef' observed (++ [kind])
          if length seen==failed then throwIO (userError "custody hash")
            else pure (B.replicate 32 (fromIntegral (B.length bytes)))
    result <- try (validate (CustodyRoot 1 (B.replicate 192 0) (B.pack receipts) callback)) :: IO (Either IOException (Maybe B.ByteString))
    seen <- readIORef observed
    invalid <- validate (CustodyRoot 1 B.empty B.empty (\_ _ -> error "invalid custody rule performed hashing"))
    pure $ conjoin [seen === take (failed+1) steps, invalid === Nothing, case result of
      Left _ -> property (failed < length steps)
      Right value -> conjoin [property (failed >= length steps), fmap B.length value === Just 32]]

annexHeaderAbi :: Property
annexHeaderAbi = forAll (choose (0,4294967295 :: Word64)) $ \bundle ->
  forAll (elements [0,bundle,maxBound]) $ \expected ->
  forAll (elements [0,bundle,maxBound]) $ \limit ->
  forAll (elements [0,14,15,bundle+14,bundle+15,maxBound]) $ \size ->
  forAll (elements [0,2,3,4,5,6,255]) $ \count -> ioProperty $ do
    let input = [80,69,67,88,66,73,78,50,0,1] ++ B.unpack (B.reverse (wordLE 4 bundle)) ++ [count]
        accepted = size >= 15 && bundle > 0 && bundle == expected && bundle <= limit && count >= 3 && count <= 5 && toInteger bundle+15 <= toInteger size
        reference = if size < 15 then 1 else if accepted then 0 else 2
    withArray input $ \source -> withArray (replicate 4 0xa5) $ \output -> do
      code <- elements_hs_exchange_annex_header expected limit size source (output `plusPtr` 8)
      bytes <- peekArray 4 output
      absent <- elements_hs_exchange_annex_header expected limit size nullPtr output
      noOutput <- elements_hs_exchange_annex_header expected limit size source nullPtr
      preserved <- peekArray 4 output
      pure $ conjoin [code === reference, absent === (-1), noOutput === (-1), preserved === bytes,
        bytes === (if accepted then [0xa5,bundle,fromIntegral count,0xa5] else replicate 4 0xa5)]

custodyReceiptsAbi :: Property
custodyReceiptsAbi = forAll (choose (3,5)) $ \count ->
  forAll (vectorOf (count*138) arbitrary) $ \body ->
  forAll (choose (0,count*140-1)) $ \cut -> ioProperty $ do
    let receipt i = [1] ++ take 72 (drop (i*138+1) body) ++ [fromIntegral (i+1)] ++ take 64 (drop (i*138+74) body)
        expected = concatMap receipt [0..count-1] ++ [fromIntegral (2^count-1 :: Int)]
        input = concatMap (\i -> [0,138] ++ receipt i) [0..count-1]
        size = fromIntegral (length input)
        capacity = fromIntegral (length expected)
    withArray input $ \source -> withArray (replicate (length expected+2) 0xa5) $ \output -> do
      code <- elements_hs_exchange_receipts (fromIntegral count) size source capacity (output `plusPtr` 1)
      bytes <- peekArray (length expected+2) output
      invalid <- sequence [elements_hs_exchange_receipts n size source cap output |
        (n,cap) <- [(0,capacity),(2,capacity),(6,capacity),(maxBound,capacity),(fromIntegral count,capacity-1),(fromIntegral count,capacity+1)]]
      absent <- elements_hs_exchange_receipts (fromIntegral count) size nullPtr capacity output
      noOutput <- elements_hs_exchange_receipts (fromIntegral count) size source capacity nullPtr
      tooLarge <- elements_hs_exchange_receipts (fromIntegral count) maxBound source capacity output
      truncated <- elements_hs_exchange_receipts (fromIntegral count) (fromIntegral cut) source capacity output
      preserved <- peekArray (length expected+2) output
      pure $ conjoin [code === 0, bytes === ([0xa5] ++ expected ++ [0xa5]), invalid === replicate 6 (-1),
        absent === (-1), noOutput === (-1), tooLarge === (-1), preserved === bytes,
        truncated === (if cut `mod` 140 < 2 then 1 else 2),
        validate (CustodyReceipts count (B.pack input)) === Right (B.pack expected)]

legacyMarkerFrameAbi :: Property
legacyMarkerFrameAbi = forAll arbitrary $ \forced -> forAll (choose (8,255)) $ \count ->
  forAll (vectorOf (if forced then count-4 else 69) arbitrary) $ \body ->
  forAll (choose (0,5)) $ \offset -> forAll arbitrary $ \byte -> ioProperty $ do
    let header = if forced then [106,76,fromIntegral count,69,67,88,70] else [106,73,69,67,88,68]
        canonical = header ++ body
        input = take offset canonical ++ [byte] ++ drop (offset+1) canonical
        accepted = take (length header) input == header
        prefix = if forced then 3 else 2
        expected = drop prefix input
        mode = if forced then 16 else 17
        size = fromIntegral (length input)
        capacity = fromIntegral (length expected)
    withArray (replicate 7 0) $ \fields -> withArray input $ \source ->
      withArray (replicate (length expected+2) 0xa5) $ \output -> do
        code <- elements_hs_exchange_inbox_entry mode fields size source capacity (output `plusPtr` 1)
        bytes <- peekArray (length expected+2) output
        invalid <- sequence [elements_hs_exchange_inbox_entry mode fields n source cap output |
          (n,cap) <- [(size-1,capacity),(size+1,capacity),(size,capacity-1),(size,capacity+1),(maxBound,capacity)]]
        absent <- elements_hs_exchange_inbox_entry mode fields size nullPtr capacity output
        noOutput <- elements_hs_exchange_inbox_entry mode fields size source capacity nullPtr
        preserved <- peekArray (length expected+2) output
        pure $ conjoin [code === (if accepted then 0 else -1),
          validate (LegacyMarkerFrame forced (B.pack input)) === (if accepted then Just (B.pack expected) else Nothing),
          bytes === (if accepted then [0xa5] ++ expected ++ [0xa5] else replicate (length expected+2) 0xa5),
          invalid === replicate 5 (-1), absent === (-1), noOutput === (-1), preserved === bytes]

markerFrameAbi :: Property
markerFrameAbi = forAll arbitrary $ \successor -> forAll (vectorOf 497 arbitrary) $ \body ->
  forAll (choose (0,506)) $ \offset -> forAll arbitrary $ \byte -> ioProperty $ do
    let canonical = [106,77,247,1,69,67,88,66,if successor then 3 else 1,0] ++ body
        input = take offset canonical ++ [byte] ++ drop (offset+1) canonical
        accepted = take 8 input == [106,77,247,1,69,67,88,66] && input !! 8 == (if successor then 3 else 1) && input !! 9 <= 3
        mode = if successor then 8 else 7
    withArray (replicate 7 0) $ \fields -> withArray input $ \source -> withArray (replicate 505 0xa5) $ \output -> do
      code <- elements_hs_exchange_inbox_entry mode fields 507 source 503 (output `plusPtr` 1)
      bytes <- peekArray 505 output
      invalid <- sequence [elements_hs_exchange_inbox_entry mode fields size source capacity output | (size,capacity) <- [(506,503),(508,503),(507,502),(507,504)]]
      noInput <- elements_hs_exchange_inbox_entry mode fields 507 nullPtr 503 output
      noOutput <- elements_hs_exchange_inbox_entry mode fields 507 source 503 nullPtr
      preserved <- peekArray 505 output
      pure $ conjoin [code === (if accepted then 0 else -1),
        bytes === (if accepted then [0xa5] ++ drop 4 input ++ [0xa5] else replicate 505 0xa5),
        invalid === replicate 4 (-1), noInput === (-1), noOutput === (-1), preserved === bytes]

markerContextAbi :: Property
markerContextAbi = forAll (vectorOf 503 arbitrary) $ \input -> ioProperty $
  withArray (replicate 7 0) $ \fields -> withArray input $ \source -> withArray (replicate 238 0xa5) $ \output -> do
    let expected = concat [take size (drop offset input) |
          (offset,size) <- [(6,32),(38,32),(102,32),(134,32),(166,4),(170,32),(202,8),(210,32),(407,32)]]
    code <- elements_hs_exchange_inbox_entry 6 fields 503 source 236 (output `plusPtr` 1)
    bytes <- peekArray 238 output
    invalid <- sequence [elements_hs_exchange_inbox_entry mode fields size source capacity output |
      (mode,size,capacity) <- [(7,503,236),(6,502,236),(6,504,236),(6,503,235),(6,503,237),(6,maxBound,236)]]
    absent <- elements_hs_exchange_inbox_entry 6 fields 503 nullPtr 236 output
    noOutput <- elements_hs_exchange_inbox_entry 6 fields 503 source 236 nullPtr
    preserved <- peekArray 238 output
    pure $ conjoin [code === 0, bytes === ([0xa5] ++ expected ++ [0xa5]), invalid === replicate 6 (-1),
      absent === (-1), noOutput === (-1), preserved === bytes,
      validate (MarkerContext (B.pack input)) === Just (B.pack expected)]

bondEntryAbi :: Property
bondEntryAbi = forAll arbitrary $ \wide ->
  forAll ((++) <$> vectorOf 3 arbitrary <*> vectorOf 4 (choose (0,4294967295))) $ \values ->
  forAll (vectorOf (if wide then 675 else 659) arbitrary) $ \input -> ioProperty $
  withArray values $ \fields -> withArray input $ \source -> case values of
    [count,height,parent,txLength,witnessLength,txIndex,vout] -> do
      let mode = if wide then 5 else 4
          size = if wide then 708 else 700
          be n value = B.unpack (B.reverse (wordLE n value))
          hash n = take 32 (drop (n*32) input)
          expected = [if wide then 2 else 1] ++ (if wide then take 16 (drop 160 input) else be 8 count) ++
            hash 0 ++ be 8 height ++ be 8 parent ++ concatMap hash [1,2,3] ++ be 4 txLength ++ hash 4 ++
            concatMap (be 4) [witnessLength,txIndex,vout] ++ drop (if wide then 176 else 160) input
      withArray (replicate (size+2) 0xa5) $ \output -> do
        code <- elements_hs_exchange_inbox_entry mode fields (fromIntegral (length input)) source (fromIntegral size) (output `plusPtr` 1)
        bytes <- peekArray (size+2) output
        invalid <- sequence [elements_hs_exchange_inbox_entry m fields n source cap output |
          (m,n,cap) <- [(6,659,700),(mode,0,fromIntegral size),(mode,maxBound,fromIntegral size),(mode,fromIntegral (length input),0)]]
        badField <- withArray [count,height,parent,4294967296,witnessLength,txIndex,vout] $ \bad ->
          elements_hs_exchange_inbox_entry mode bad (fromIntegral (length input)) source (fromIntegral size) output
        preserved <- peekArray (size+2) output
        pure $ conjoin [code === 0, bytes === ([0xa5] ++ expected ++ [0xa5]), preserved === bytes,
          invalid === replicate 4 (-1), badField === (-1), validate (BondEntry wide values (B.pack input)) === Just (B.pack expected)]
    _ -> pure (property False)

inboxStepAbi :: Property
inboxStepAbi = forAll arbitrary $ \wide -> forAll arbitrary $ \count ->
  forAll (vectorOf (if wide then 80 else 64) arbitrary) $ \input -> ioProperty $ do
    let mode = if wide then 3 else 2
        size = if wide then 80 else 72
        expected = take 32 input ++ (if wide then drop 64 input else B.unpack (B.reverse (wordLE 8 count))) ++ take 32 (drop 32 input)
    withArray [count,0,0,0,0] $ \fields -> withArray input $ \source ->
      withArray (replicate (size+2) 0xa5) $ \output -> do
        code <- elements_hs_exchange_inbox_entry mode fields (fromIntegral (length input)) source (fromIntegral size) (output `plusPtr` 1)
        bytes <- peekArray (size+2) output
        bad <- sequence [elements_hs_exchange_inbox_entry mode fields n source (fromIntegral cap) output |
          (n,cap) <- [(0,size),(maxBound,size),(fromIntegral (length input),size-1)]]
        preserved <- peekArray (size+2) output
        pure $ conjoin [code === 0, bytes === ([0xa5] ++ expected ++ [0xa5]),
          bad === replicate 3 (-1), preserved === bytes,
          validate (InboxStep wide count (B.pack input)) === Just (B.pack expected)]

inboxEventAbi :: Property
inboxEventAbi = forAll arbitrary $ \deposit ->
  forAll (vectorOf 3 arbitrary) $ \prefix ->
  forAll (choose (0,4294967295)) $ \vout ->
  forAll (choose (0,if deposit then 4294967295 else 255)) $ \extra ->
  forAll (choose (0,256)) $ \bodySize ->
  forAll (vectorOf (if deposit then 160 else 96+bodySize) arbitrary) $ \input -> ioProperty $ do
    let values = prefix ++ [vout,extra]
        be n value = B.unpack (B.reverse (wordLE n value))
        hash n = take 32 (drop (n*32) input)
        expected = [1] ++ hash 0 ++ be 8 (prefix !! 0) ++ hash 1 ++
          be 8 (prefix !! 1) ++ be 8 (prefix !! 2) ++ hash 2 ++ be 4 vout ++
          be (if deposit then 4 else 1) extra ++ drop 96 input
        size = length expected
        mode = if deposit then 1 else 0
    withArray values $ \fields -> withArray input $ \source ->
      withArray (replicate (size+2) 0xa5) $ \output -> do
        code <- elements_hs_exchange_inbox_entry mode fields (fromIntegral (length input)) source (fromIntegral size) (output `plusPtr` 1)
        bytes <- peekArray (size+2) output
        invalid <- sequence [elements_hs_exchange_inbox_entry m fields n source cap output |
          (m,n,cap) <- [(2,96,126),(mode,95,125),(mode,maxBound,0),(mode,fromIntegral (length input),0)]]
        badValue <- withArray (prefix ++ [4294967296,extra]) $ \bad ->
          elements_hs_exchange_inbox_entry mode bad (fromIntegral (length input)) source (fromIntegral size) output
        absent <- elements_hs_exchange_inbox_entry mode nullPtr (fromIntegral (length input)) source (fromIntegral size) output
        noInput <- elements_hs_exchange_inbox_entry mode fields (fromIntegral (length input)) nullPtr (fromIntegral size) output
        noOutput <- elements_hs_exchange_inbox_entry mode fields (fromIntegral (length input)) source (fromIntegral size) nullPtr
        badExtra <- withArray (prefix ++ [vout,if deposit then 4294967296 else 256]) $ \bad ->
          elements_hs_exchange_inbox_entry mode bad (fromIntegral (length input)) source (fromIntegral size) output
        preserved <- peekArray (size+2) output
        pure $ conjoin [code === 0, bytes === ([0xa5] ++ expected ++ [0xa5]),
          invalid === replicate 4 (-1), badValue === (-1), absent === (-1),
          noInput === (-1), noOutput === (-1), badExtra === (-1), preserved === bytes,
          validate (InboxEntry deposit values (B.pack input)) === Just (B.pack expected)]

tapPreimageAbi :: Property
tapPreimageAbi = forAll ((,) <$> arbitrary <*> frequency [(4,choose (0,255)),(1,elements [256,maxBound])]) $ \(leaf,version) ->
  forAll (vectorOf (if leaf then 32 else 64) arbitrary) $ \input -> ioProperty $ do
    let (left,right) = splitAt 32 input
        encodingValid = not leaf || version <= 255
        expected = if leaf then [fromIntegral version,32] ++ input else if left < right then input else right ++ left
        size = if leaf then 34 else 64
        mode = if leaf then 3 else 4
    withArray input $ \source -> withArray (replicate (size+2) 0xa5) $ \output -> do
      code <- elements_hs_exchange_genesis_state mode version 0 (fromIntegral (length input)) source (fromIntegral size) (output `plusPtr` 1)
      bytes <- peekArray (size+2) output
      invalid <- elements_hs_exchange_genesis_state mode version 0 0 source (fromIntegral size) output
      noOutput <- elements_hs_exchange_genesis_state mode version 0 (fromIntegral (length input)) source (fromIntegral size) nullPtr
      noInput <- elements_hs_exchange_genesis_state mode version 0 (fromIntegral (length input)) nullPtr (fromIntegral size) output
      preserved <- peekArray (size+2) output
      pure $ conjoin [code === (if encodingValid then 0 else -1),
        bytes === (if encodingValid then [0xa5] ++ expected ++ [0xa5] else replicate (size+2) 0xa5),
        invalid === (-1), noOutput === (-1), noInput === (-1), preserved === bytes,
        validate (TapPreimage leaf version (B.pack input)) === (if encodingValid then Just (B.pack expected) else Nothing)]

genesisCovenantAbi :: Property
genesisCovenantAbi = forAll ((,) <$> arbitrary <*> vectorOf 352 arbitrary) $ \(height,input) -> ioProperty $ do
  let be value = B.unpack (B.reverse (wordLE 8 value))
      hash i = take 32 (drop (i*32) input)
      expected = hash 0 ++ [0,0,0,4] ++ be 0 ++ concatMap hash [1..7] ++
        hash 8 ++ hash 8 ++ hash 9 ++ be 0 ++ hash 9 ++ be 0 ++ hash 10 ++ be 0 ++ be 0 ++ be height
  withArray input $ \source -> withArray (replicate 470 0xa5) $ \output -> do
    code <- elements_hs_exchange_genesis_state 2 height 0 352 source 468 (output `plusPtr` 1)
    bytes <- peekArray 470 output
    invalid <- sequence [elements_hs_exchange_genesis_state mode height 0 size source capacity output |
      (mode,size,capacity) <- [(5,352,468),(2,351,468),(2,353,468),(2,352,467),(2,352,469),(2,maxBound,468)]]
    absent <- elements_hs_exchange_genesis_state 2 height 0 352 nullPtr 468 output
    noOutput <- elements_hs_exchange_genesis_state 2 height 0 352 source 468 nullPtr
    preserved <- peekArray 470 output
    pure $ conjoin [code === 0, bytes === ([0xa5] ++ expected ++ [0xa5]), preserved === bytes,
      invalid === replicate 6 (-1), absent === (-1), noOutput === (-1),
      validate (GenesisCovenant height (B.pack input)) === Just (B.pack expected),
      validate (GenesisCovenant height B.empty) === Nothing]

genesisStateAbi :: Property
genesisStateAbi = conjoin [genesisRootsWorkflow, capitalSnapshotAbi, forAll ((,,) <$> arbitrary <*> arbitrary <*> arbitrary) $ \(private,height,price) ->
  forAll (vectorOf (if private then 1223 else 128) arbitrary) $ \input -> ioProperty $ do
    let be value = B.unpack (B.reverse (wordLE 8 value))
        hash i = take 32 (drop (i*32) input)
        zeros n = replicate n 0
        size = if private then 1713 else 242
        mode = if private then 1 else 0
        expected = if private then [2,4] ++ hash 0 ++ [69,67,88,45,85,83,68,68,45,80,69,82,80,0,0,0] ++
          be 0 ++ be height ++ be price ++ zeros 80 ++ be 0 ++ hash 1 ++
          concat [hash i ++ be 0 ++ hash i ++ be 0 | i <- [2,3]] ++
          concat (replicate 5 (hash 4)) ++ hash 5 ++ drop 256 input ++ be 0 ++ be height ++
          hash 6 ++ be 0 ++ hash 6 ++ be 0 ++ hash 7 ++ be 0 ++ hash 4 ++ hash 4
          else [2] ++ take 96 input ++ zeros 16 ++ be 2100000000000000 ++ be 0 ++ be 2100000000000000 ++
            zeros 48 ++ hash 3 ++ be 0 ++ be 0 ++ be 0 ++ [0]
    withArray input $ \source -> withArray (replicate (size+2) 0xa5) $ \output -> do
      let run kind lengthIn capacity = elements_hs_exchange_genesis_state kind height price lengthIn source capacity output
      code <- elements_hs_exchange_genesis_state mode height price (fromIntegral (length input)) source (fromIntegral size) (output `plusPtr` 1)
      bytes <- peekArray (size+2) output
      invalid <- sequence [run 5 (fromIntegral (length input)) (fromIntegral size),
        run mode 0 (fromIntegral size), run mode maxBound (fromIntegral size), run mode (fromIntegral (length input)) 0]
      absent <- elements_hs_exchange_genesis_state mode height price (fromIntegral (length input)) nullPtr (fromIntegral size) output
      noOutput <- elements_hs_exchange_genesis_state mode height price (fromIntegral (length input)) source (fromIntegral size) nullPtr
      preserved <- peekArray (size+2) output
      pure $ conjoin [code === 0, bytes === ([0xa5] ++ expected ++ [0xa5]), preserved === bytes,
        invalid === replicate 4 (-1), absent === (-1), noOutput === (-1),
        validate (GenesisState private height price (B.pack input)) === Just (B.pack expected),
        validate (GenesisState private height price (B.pack (drop 1 input))) === Nothing]]

genesisRootsWorkflow :: Property
genesisRootsWorkflow = forAll ((,,,,) <$> arbitrary <*> arbitrary <*> arbitrary <*> vectorOf 384 arbitrary <*> choose (-1,9 :: Int)) $
  \(height,mtp,price,input,zeroKind) -> ioProperty $ do
    trace <- newIORef []
    let digest :: Word32 -> B.ByteString
        digest kind = B.replicate 32 (if fromIntegral kind==zeroKind then 0 else fromIntegral kind+1)
        expectedCalls = if zeroKind==1 || zeroKind==2 then [0,1,2] else if zeroKind==8 then [0..8] else [0..9]
        failed = zeroKind `elem` [1,2,8]
        expected = B.concat [if failed then B.replicate 32 0 else digest 8,digest 1,digest 2,
          if failed then B.replicate 32 0 else digest 9]
        hash kind _ = modifyIORef' trace (++[kind]) >> pure (digest kind)
        request = GenesisRequest height mtp price (B.pack input) hash
    result <- Operation.execute request buildGenesisRoots
    seen <- readIORef trace
    invalid <- Operation.execute (GenesisRequest height mtp price B.empty (\_ _ -> error "invalid genesis request hashed")) buildGenesisRoots
    badDigest <- try (Operation.execute (GenesisRequest height mtp price (B.pack input) (\_ _ -> pure B.empty)) buildGenesisRoots)
      :: IO (Either IOException (Maybe B.ByteString))
    let mismatch = case Operation.interpret (Operation.SomeOperation (Check (error "mismatched genesis payload forced" :: GenesisState))) buildGenesisRoots of
          Nothing -> True
          Just _ -> False
    withArray input $ \source -> withArray (replicate 130 0xa5) $ \output -> do
      callback <- makeCustodyHash $ \_ kind _ _ target -> pokeArray target (B.unpack (digest kind)) >> pure 0
      code <- elements_hs_exchange_genesis_roots height mtp price source callback nullPtr (output `plusPtr` 1)
      actual <- peekArray 130 output
      bad <- sequence [elements_hs_exchange_genesis_roots height mtp price ptr cb nullPtr out |
        (ptr,cb,out) <- [(nullPtr,callback,output),(source,nullFunPtr,output),(source,callback,nullPtr)]]
      freeHaskellFunPtr callback
      failing <- makeCustodyHash $ \_ _ _ _ _ -> pure (-1)
      rejected <- elements_hs_exchange_genesis_roots height mtp price source failing nullPtr (output `plusPtr` 1)
      freeHaskellFunPtr failing
      preserved <- peekArray 130 output
      pure (conjoin [result === Just expected, seen === expectedCalls, invalid === Nothing, property mismatch,
        property (case badDigest of Left _ -> True; Right _ -> False),
        code === 0, actual === (0xa5 : B.unpack expected ++ [0xa5]), bad === replicate 3 (-1),
        rejected === (-1), preserved === actual])

capitalSnapshotAbi :: Property
capitalSnapshotAbi = forAll (choose (0,3)) $ \profile ->
  forAll ((,,) <$> arbitrary <*> arbitrary <*> vectorOf (320 + case profile of 0 -> 850; 1 -> 1627; 2 -> 364; _ -> 168) arbitrary) $
    \(height,mtp,input) -> ioProperty $ withArray input $ \source -> withArray (replicate 916 0xa5) $ \output -> do
      let mode=profile+8
          size=fromIntegral (length input)
          call kind count capacity ptr=elements_hs_exchange_genesis_state kind height mtp count ptr capacity (output `plusPtr` 1)
      code <- call mode size 914 source
      encoded <- peekArray 916 output
      invalid <- sequence [call kind count capacity source |
        (kind,count,capacity) <- [(12,size,914),(mode,size-1,914),(mode,size+1,914),(mode,maxBound,914),(mode,size,913),(mode,size,915)]]
      absent <- call mode size 914 nullPtr
      noOutput <- elements_hs_exchange_genesis_state mode height mtp size source 914 nullPtr
      preserved <- peekArray 916 output
      pure $ conjoin [code === 0, head encoded === 0xa5, last encoded === 0xa5,
        validate (CapitalSnapshot profile height mtp (B.pack input)) === Just (B.pack (take 914 (drop 1 encoded))),
        preserved === encoded, invalid === replicate 6 (-1), absent === (-1), noOutput === (-1),
        validate (CapitalSnapshot profile height mtp (B.pack (drop 1 input))) === Nothing,
        validate (CapitalSnapshot 4 height mtp (B.pack input)) === Nothing]

genesisFundingAbi :: Property
genesisFundingAbi = forAll ((,) <$> arbitrary <*> arbitrary) $ \(mtp,price) -> ioProperty $ do
  let be value = B.unpack (B.reverse (wordLE 8 value))
      expected = [2] ++ concatMap be [mtp,price,price,price,mtp,maxBound] ++ replicate 20 0 ++
        concat [[255,255,255,255,255,255,255,255,index] ++ replicate 73 0 | index <- [0..7]]
  withArray (replicate 727 0xa5) $ \output -> do
    code <- elements_hs_exchange_genesis_funding mtp price 725 (output `plusPtr` 1)
    bytes <- peekArray 727 output
    invalid <- mapM (\capacity -> elements_hs_exchange_genesis_funding mtp price capacity output) [0,724,726,maxBound]
    preserved <- peekArray 727 output
    absent <- elements_hs_exchange_genesis_funding mtp price 725 nullPtr
    pure $ conjoin [code === 0, bytes === ([0xa5] ++ expected ++ [0xa5]),
      validate (GenesisFunding mtp price) === B.pack expected,
      invalid === replicate 4 (-1), preserved === bytes, absent === (-1)]

transactionShapeOrder :: Property
transactionShapeOrder = forAll ((,,) <$> elements ([0..14] ++ [18..25] ++ [maxBound]) <*> choose (0,16) <*> arbitrary) $ \(phase,failed,throws) -> ioProperty $ do
  seen <- newIORef []
  result <- try (validate (TransactionShape phase (\step -> do
    modifyIORef' seen (++ [step])
    if step == failed && throws then throwIO (userError "transaction shape read") else pure (step /= failed))))
      :: IO (Either IOException Int)
  observed <- readIORef seen
  absent <- elements_hs_exchange_transaction_shape phase nullFunPtr nullPtr
  abiSeen <- newIORef []
  abiResult <- bracket (makeShapeRead (\_ step -> do
      modifyIORef' abiSeen (++ [fromIntegral step])
      pure (if fromIntegral step == failed then 0 else 1))) freeHaskellFunPtr $ \reader ->
        elements_hs_exchange_transaction_shape phase reader nullPtr
  abiObserved <- readIORef abiSeen
  let count = case phase of 0 -> 3; 1 -> 9; 2 -> 8; 3 -> 16; 4 -> 16; 5 -> 11; 6 -> 8; 7 -> 9; 8 -> 2; 9 -> 2; 10 -> 8; 11 -> 2; 12 -> 1; 13 -> 1; 14 -> 16; 18 -> 11; 19 -> 3; 20 -> 3; 21 -> 3; 22 -> 10; 23 -> 2; 24 -> 3; _ -> 0
      first = if phase == 4 then 1 else 0
      rejected = failed >= first && failed < count
      expected = if phase==24 then (if rejected then [33,25,34] !! failed else 0)
                 else if phase==23 then (if rejected then failed+31 else 0)
                 else if phase==22 then (if rejected then (if failed<3 then 29 else 30) else 0)
                 else if phase==20 || phase==21 then (if rejected then fromIntegral phase+7 else 0)
                 else if phase==19 then (if rejected then failed+24 else 0)
                 else if phase==18 then (if rejected then 23 else 0) else if phase > 14 then -1 else if not rejected then 0
                 else if phase >= 8 then fromIntegral phase+3
                 else if phase == 7 then (if failed < 3 then 8 else if failed < 8 then 9 else 10)
                 else if phase == 0 then (if failed < 2 then 1 else 2)
                 else if phase < 3 then fromIntegral phase+2 else if phase < 5 then 5 else fromIntegral phase+1
  pure $ conjoin [absent === (-1), abiResult === fromIntegral expected,
    abiObserved === [first .. (if rejected then failed else count-1)],
    observed === [first .. (if rejected then failed else count-1)], case result of
    Left _ -> property (throws && rejected)
    Right code -> conjoin [property (not throws || not rejected), code === expected]]

spendSelection :: Property
spendSelection = forAll ((,,) <$> arbitrary <*> listOf (choose (0,3 :: Word64)) <*> choose (0,10 :: Word64)) $ \(unique,counts,start) -> ioProperty $ do
  seen <- newIORef []
  result <- validate (SpendScan unique start (start + fromIntegral (length counts)) (\index -> do
    modifyIORef' seen (++ [index])
    pure (counts !! fromIntegral (index-start))))
  observed <- readIORef seen
  let threshold = if unique then 1 else 0
      totals = tail (scanl (+) 0 (map toInteger counts))
      accepted = sum (map toInteger counts) <= threshold
      matches = [start+fromIntegral i | (i,n) <- zip [0 :: Int ..] counts, n /= 0]
      expected = if accepted then Right (case matches of [] -> Nothing; i:_ -> Just i) else Left 2
      readLength = min (length counts) (length (takeWhile (<= threshold) totals) + 1)
  invalid <- validate (SpendScan unique 2 1 (\_ -> error "invalid range read"))
  edge <- validate (SpendScan unique maxBound maxBound (\_ -> error "empty range read"))
  badAbi <- elements_hs_exchange_spend_scan 2 0 0 nullFunPtr nullPtr nullPtr
  pure $ conjoin [result === expected, observed === take readLength [start..],
    invalid === Left (-1), edge === Right Nothing, badAbi === (-1)]

physicalOrder :: Property
physicalOrder = forAll ((,,) <$> arbitrary <*> choose (0,13) <*> arbitrary) $ \(public,failed,throws) -> ioProperty $ do
  seen <- newIORef []
  result <- try (validate (PhysicalInputs public (\step -> do
    modifyIORef' seen (++ [step])
    if step == failed && throws then throwIO (userError "physical read") else pure (step /= failed))))
      :: IO (Either IOException Int)
  observed <- readIORef seen
  absent <- elements_hs_exchange_physical_inputs (if public then 1 else 0) nullFunPtr nullPtr
  invalid <- elements_hs_exchange_physical_inputs 2 nullFunPtr nullPtr
  let steps = filter (\step -> not public || step < 4 || step > 8) [0..12]
      rejected = failed `elem` steps
  pure $ conjoin [observed === (if rejected then takeWhile (<=failed) steps else steps), absent === (-1), invalid === (-1),
    case result of
      Left _ -> property (throws && rejected)
      Right code -> conjoin [property (not throws || not rejected), code === (if rejected then 1 else 0)]]

requiredIdentityOrder :: Property
requiredIdentityOrder = forAll ((,,) <$> choose (0,5) <*> choose (0,45) <*> arbitrary) $ \(flags,failed,throws) -> ioProperty $ do
  seen <- newIORef []
  result <- try (validate (RequiredIdentities flags (\step -> do
    modifyIORef' seen (++ [step])
    if step == failed && throws then throwIO (userError "identity read") else pure (step /= failed))))
      :: IO (Either IOException Int)
  observed <- readIORef seen
  absent <- elements_hs_exchange_required_identities flags nullFunPtr nullPtr
  let excluded = (if flags == 1 || flags == 3 then [44] else []) ++ (if flags == 2 || flags == 3 then [33..38] else [])
      steps = if flags > 3 then [] else filter (`notElem` excluded) [0..44]
      rejected = failed `elem` steps
      expectedReads = if rejected then takeWhile (<= failed) steps else steps
  pure $ conjoin [observed === expectedReads, absent === (-1), case result of
    Left _ -> property (throws && rejected)
    Right code -> conjoin [property (not throws || not rejected),
      code === (if flags > 3 then -1 else if rejected then failed+1 else 0)]]

registryAbi :: Property
registryAbi = forAll (vectorOf 5 ((,) <$> choose (0,6) <*> choose (0,6))) $ \keys -> ioProperty $ do
  let fields = [(B.replicate 32 a,B.replicate 32 b) | (a,b) <- keys]
      failures = [if a == 0 || b == 0 then 1 else
          if any (\(x,y) -> x == a || y == b) (take index keys) then 2 else 0 |
          (index,(a,b)) <- zip [0..] keys]
      expected = case filter (/=0) failures of [] -> 0; code:_ -> code
  withArray (concatMap (replicate 32 . fst) keys) $ \a -> withArray (concatMap (replicate 32 . snd) keys) $ \b -> do
    code <- elements_hs_exchange_registry a b
    missingA <- elements_hs_exchange_registry nullPtr b
    missingB <- elements_hs_exchange_registry a nullPtr
    pure $ conjoin [code === expected, validate (CustodianRegistry fields) === fromIntegral expected,
      validate (CustodianRegistry (tail fields)) === (-1),
      validate (CustodianRegistry ((B.empty,B.empty):tail fields)) === (-1),
      missingA === (-1), missingB === (-1)]

distinctAbi :: Property
distinctAbi = forAll (choose (0,45)) $ \count ->
  forAll ((,) <$> vectorOf count (vectorOf 32 arbitrary) <*> arbitrary) $ \(original,duplicate) -> ioProperty $ do
    let values = if duplicate && count > 1 then head original : head original : drop 2 original else original
        expected = and [a /= b | (i,a) <- zip [0 :: Int ..] values, b <- drop (i+1) values]
    withArray (concat values) $ \input -> do
      code <- elements_hs_exchange_distinct (fromIntegral count) input
      absent <- elements_hs_exchange_distinct (fromIntegral count) nullPtr
      oversized <- elements_hs_exchange_distinct 46 nullPtr
      zeroOnly <- elements_hs_exchange_identity_relation 1 (fromIntegral count) input
      isolated <- elements_hs_exchange_identity_relation 2 (fromIntegral count) input
      invalidMode <- elements_hs_exchange_identity_relation 7 0 nullPtr
      zeros <- withArray (replicate (count*32) 0) (elements_hs_exchange_identity_relation 1 (fromIntegral count))
      let expectedZero = all (all (==0)) values
          expectedIsolated = case values of [] -> False; first:rest -> first `notElem` rest
      pure $ conjoin [code === (if expected then 0 else 1),
        validate (IdentitySet (map B.pack values)) === expected,
        validate (IdentitySet [B.empty]) === False,
        absent === (if count == 0 then 0 else -1), oversized === (-1),
        zeroOnly === (if expectedZero then 0 else 1), isolated === (if expectedIsolated then 0 else 1),
        zeros === 0, invalidMode === (-1),
        validate (AbsentIdentities (map B.pack values)) === expectedZero,
        validate (IsolatedIdentity (map B.pack values)) === expectedIsolated]

frozenBoundsAbi :: Property
frozenBoundsAbi = conjoin [frozenWorkflowAbi, hybridOracleBoundsAbi, forAll (choose (0,15)) $ \index ->
  let baseline = [190,12,6,65536,8,589824,786432,64,64,4096,6,3600,16777216,32,2100000000000000,1008]
  in forAll (frequency [(1,arbitrary),(2,elements [0,1,maxBound,baseline !! index,baseline !! index+1])]) $ \value ->
    ioProperty $ do
      let fields = take index baseline ++ [value] ++ drop (index+1) baseline
          expected = if index == 11 then value > 0 else if index == 12 then value > 0 && value <= 16777216
                     else value == baseline !! index
      withArray fields $ \input -> do
        code <- elements_hs_exchange_frozen_bounds 16 input
        short <- elements_hs_exchange_frozen_bounds 15 input
        long <- elements_hs_exchange_frozen_bounds 18 input
        absent <- elements_hs_exchange_frozen_bounds 16 nullPtr
        inboxCode <- elements_hs_exchange_frozen_bounds 9 (input `plusPtr` 16)
        proofCode <- elements_hs_exchange_frozen_bounds 5 (input `plusPtr` 88)
        pure $ conjoin [code === (if expected then 0 else 1),
          inboxCode === (if index < 2 || index > 10 || expected then 0 else 1),
          proofCode === (if index < 11 || expected then 0 else 1),
          validate (FrozenBounds fields) === expected, short === (-1), long === (-1), absent === (-1),
          validate (FrozenBounds (tail fields)) === False, validate (FrozenBounds (0:fields)) === False]]

frozenWorkflowAbi :: Property
frozenWorkflowAbi = forAll (vectorOf 16 arbitrary) $ \market ->
  forAll (choose (0,2 :: Int)) $ \mode -> ioProperty $ do
    let base = B.concat [B.pack [5,3], B.replicate 32 1, B.pack market,
          B.concat [B.replicate 32 x | x <- [2..5]]]
        input = case mode of
          0 -> B.replicate 1976 0
          1 -> B.replicate 1977 0
          _ -> base <> B.replicate (1977-B.length base) 0
        expected = mode+1
        publications = if mode==2 then [(4,B.take 32 (B.drop 2 base) <> B.drop 50 base)] else []
    trace <- newIORef []
    let effect kind payload = modifyIORef' trace (++[(kind,payload)]) >> pure B.empty
    result <- Operation.execute (FrozenRequest (B.pack market) input effect) decodeFrozenRequest
    seen <- readIORef trace
    invalidMarket <- Operation.execute (FrozenRequest B.empty (B.replicate 1977 0) effect) decodeFrozenRequest
    let mismatch = case Operation.interpret (Operation.SomeOperation (Check (error "mismatched frozen payload forced" :: GenesisState))) decodeFrozenRequest of
          Nothing -> True
          Just _ -> False
    withArray (B.unpack input) $ \source -> withArray market $ \identity -> do
      calls <- newIORef []
      callback <- makeCustodyHash $ \_ kind size payload _ -> do
        contents <- B.pack <$> peekArray (fromIntegral size) payload
        modifyIORef' calls (++[(kind,contents)])
        pure 0
      code <- elements_hs_exchange_frozen_configuration (fromIntegral (B.length input)) source identity callback nullPtr
      actual <- readIORef calls
      invalid <- sequence [elements_hs_exchange_frozen_configuration 1977 ptr key cb nullPtr |
        (ptr,key,cb) <- [(nullPtr,identity,callback),(source,nullPtr,callback),(source,identity,nullFunPtr)]]
      short <- elements_hs_exchange_frozen_configuration 0 nullPtr nullPtr nullFunPtr nullPtr
      freeHaskellFunPtr callback
      failing <- makeCustodyHash $ \_ _ _ _ _ -> pure (-1)
      rejected <- elements_hs_exchange_frozen_configuration (fromIntegral (B.length input)) source identity failing nullPtr
      freeHaskellFunPtr failing
      pure $ conjoin [result === expected, seen === publications, invalidMarket === (-1), property mismatch,
        code === fromIntegral expected, actual === publications, invalid === replicate 3 (-1), short === 1,
        rejected === (if mode==2 then -1 else fromIntegral expected)]

hybridOracleBoundsAbi :: Property
hybridOracleBoundsAbi = forAll (choose (0,16)) $ \index ->
  forAll (frequency [(1,arbitrary),(3,elements [0,1,6,7,9999,10000,10001,1000000,1000001,499999999,500000000,maxBound])]) $ \value -> ioProperty $ do
    let baseline = [0,144,6,6,12,24,100,4,100,1000,10,100,100,1000,100,100000000,100000000]
        fields = take index baseline ++ [value] ++ drop (index+1) baseline
        positive = all ((>0) . (fields !!)) [1,2,4,5,6,7,14,15,16]
        expected = positive && fields !! 2 <= fields !! 3 && fields !! 8 <= fields !! 9 &&
          fields !! 9 <= 1000000 && fields !! 10 <= fields !! 11 && fields !! 11 < 10000 &&
          fields !! 12 < 10000 && 2 * toInteger (fields !! 13) < 1000000000 && fields !! 14 <= 10000
    withArray fields $ \input -> do
      code <- elements_hs_exchange_frozen_bounds 17 input
      absent <- elements_hs_exchange_frozen_bounds 17 nullPtr
      pure $ conjoin [code === (if expected then 0 else 1), absent === (-1),
        validate (HybridOracleBounds fields) === expected,
        validate (HybridOracleBounds (tail fields)) === False]

deploymentOrder :: Property
deploymentOrder = forAll ((,,) <$> frequency [(1,arbitrary),(2,elements [2,3])] <*> vectorOf 5 arbitrary <*> arbitrary) $
  \(version,facts,throws) -> ioProperty $ do
    seen <- newIORef []
    result <- try (validate (Deployment version (\step -> do
      modifyIORef' seen (++ [step])
      if throws && not (facts !! step) then throwIO (userError "deployment read") else pure (facts !! step))))
        :: IO (Either IOException Int)
    observed <- readIORef seen
    absent <- elements_hs_exchange_deployment version nullFunPtr nullPtr
    let steps = if version == 2 then [3,4] else if version == 3 then [0..4] else []
        passed = takeWhile (facts !!) steps
        remaining = drop (length passed) steps
        expectedCode = case remaining of
          step:_ -> if step < 3 then 2 else step
          [] -> if null steps then 1 else 0
    pure $ conjoin [observed === take (length passed + 1) steps, absent === (-1), case result of
      Left _ -> property (throws && not (null remaining))
      Right code -> conjoin [property (not throws || null remaining), code === expectedCode]]

genesisInitializationOrder :: Property
genesisInitializationOrder = forAll ((,,) <$> elements [0,1,2,3,maxBound] <*> factsGenerator <*> arbitrary) $
  \(version,facts,throws) -> ioProperty $ do
    seen <- newIORef []
    result <- try (validate (GenesisInitialization version (\step -> do
      modifyIORef' seen (++ [step])
      if throws && not (facts !! step) then throwIO (userError "genesis read") else pure (facts !! step))))
        :: IO (Either IOException Int)
    observed <- readIORef seen
    absent <- elements_hs_exchange_genesis_initialization version nullFunPtr nullPtr
    let steps = [0,1] ++ (if version == 0 then [2..4] ++ [19] else if version == 2 then [5..18] ++ [20] else [])
        passed = takeWhile (facts !!) steps
        visited = take (length passed + 1) steps
        failure = drop (length passed) steps
        expectedCode = case failure of
          step:_ -> if step >= 19 then -1 else if step < 2 then 1 else if step < 5 then 2 else if step < 14 then 3 else 4
          [] -> if version == 0 || version == 2 then 0 else 3
    pure $ conjoin [observed === visited, absent === (-1), case result of
      Left _ -> property (throws && not (null failure))
      Right code -> conjoin [property (not throws || null failure), code === expectedCode]]
  where factsGenerator = frequency [(1,vectorOf 21 arbitrary),(1,pure (replicate 21 True)),
          (2,do failed <- choose (0,20); pure [i /= failed | i <- [0..20 :: Int]])]

capitalIdentityAbi :: Property
capitalIdentityAbi = conjoin [capitalWorkflowAbi, forAll (choose (0,2)) $ \profile ->
  let size = case profile of 0 -> 850; 1 -> 1627; _ -> 364
      offsets = case profile of 0 -> [0,36,276,308]; 1 -> [4,388,420,452,484,516]; _ -> [4,36,100,164,196,228]
      fields = [(offset,32) | offset <- offsets] ++ [(offset,8) | profile==2, offset <- [324,332]]
  in forAll ((,,) <$> vectorOf 32 arbitrary <*> vectorOf size arbitrary <*> choose (-1,size-1)) $
    \(program,values,changed) -> ioProperty $ do
      let expected = program ++ concat [take width (drop offset values) | (offset,width) <- fields]
          modified = [if index == changed then byte + 1 else byte | (index,byte) <- zip [0..] values]
          mismatch = any (\(offset,width) -> changed >= offset && changed < offset + width) fields
      withArray program $ \p -> withArray modified $ \v -> withArray expected $ \e -> do
        let call kind n ptr expectedSize = elements_hs_exchange_capital_identity kind p n ptr expectedSize e
            count = fromIntegral (length expected)
        actual <- call profile (fromIntegral size) v count
        badProfile <- call 3 (fromIntegral size) v count
        truncated <- call profile (fromIntegral size-1) v count
        badExpected <- call profile (fromIntegral size) v (count-1)
        absent <- call profile (fromIntegral size) nullPtr count
        missingProgram <- elements_hs_exchange_capital_identity profile nullPtr (fromIntegral size) v count e
        missingExpected <- elements_hs_exchange_capital_identity profile p (fromIntegral size) v count nullPtr
        oversized <- call profile (fromIntegral size+1) v count
        extraExpected <- call profile (fromIntegral size) v (count+1)
        pure $ conjoin [actual === (if mismatch then 1 else 0),
          validate (CapitalIdentity profile (B.pack program) (B.pack modified) (B.pack expected)) === fromIntegral actual,
          badProfile === (-1), truncated === (-1), badExpected === (-1), absent === (-1),
          missingProgram === (-1), missingExpected === (-1), oversized === (-1), extraExpected === (-1)]]

capitalWorkflowAbi :: Property
capitalWorkflowAbi = forAll (choose (0,1)) $ \profile ->
  forAll ((,,) <$> vectorOf 32 arbitrary <*> vectorOf (if profile==0 then 850 else 1627) arbitrary <*> vectorOf 96 arbitrary) $
    \(program,values,context) -> ioProperty $ do
      let offsets=if profile==0 then [0,36,276,308] else [4,388,420,452,484,516]
          expected=program ++ concat [take 32 (drop offset values) | offset <- offsets]
          identity=CapitalIdentity profile (B.pack program) (B.pack values) (B.pack expected)
          request=CapitalRequest identity (Just (B.pack context))
          wanted=validate (CapitalSnapshot profile 0 0 (B.pack
            (take 32 context ++ replicate 96 0 ++ program ++ drop 32 context ++ replicate 96 0 ++ values)))
          badIdentity=CapitalIdentity profile (B.pack program) (B.pack values) B.empty
          mismatch=case Operation.interpret (Operation.SomeOperation (Check (error "mismatched payload forced" :: GenesisState))) bindAndProject of
            Nothing -> True
            Just _ -> False
      withArray program $ \p -> withArray values $ \v -> withArray (expected++context) $ \e ->
        withArray (replicate 916 0xa5) $ \output -> do
          let size=fromIntegral (length values)
              count=fromIntegral (length expected+96)
              call capacity=elements_hs_exchange_capital profile p size v count e capacity (output `plusPtr` 1)
          code <- call 914
          encoded <- peekArray 916 output
          invalid <- mapM call [1,913,915,maxBound]
          noOutput <- elements_hs_exchange_capital profile p size v count e 914 nullPtr
          malformed <- elements_hs_exchange_capital profile p size v (count-1) e 914 (output `plusPtr` 1)
          preserved <- peekArray 916 output
          pure $ conjoin [code===0, fmap B.unpack wanted===Just (take 914 (drop 1 encoded)),
            head encoded===0xa5,last encoded===0xa5,preserved===encoded,invalid===replicate 4 (-1),
            noOutput===(-1),malformed===(-1),property mismatch,
            Operation.execute request bindAndProject===maybe (Left (-1)) Right wanted,
            Operation.execute (CapitalRequest badIdentity (error "rejected projection forced")) bindAndProject===Left (-1)]

checkpointOrder :: Property
checkpointOrder = forAll ((,) <$> vectorOf 8 arbitrary <*> arbitrary) $ \(facts,throws) -> ioProperty $ do
  seen <- newIORef []
  result <- try (validate (Checkpoint (\step -> do
    modifyIORef' seen (++ [step])
    if not (facts !! step) && throws then throwIO (userError "checkpoint read") else pure (facts !! step))))
      :: IO (Either IOException Int)
  observed <- readIORef seen
  absent <- elements_hs_exchange_checkpoint nullFunPtr nullPtr
  let passed = length (takeWhile id facts)
      expectedCode = if passed == 8 then 0 else if passed == 0 then 1 else if passed < 3 then 2 else 3
  pure $ conjoin [observed === [0 .. min 8 (passed+1)-1], absent === (-1),
    case result of
      Left _ -> property (throws && passed < 8)
      Right code -> conjoin [property (not throws || passed == 8), code === expectedCode]]

envelopeRequirementAbi :: Property
envelopeRequirementAbi = forAll arbitrary $ \flags -> ioProperty $ do
  actual <- elements_hs_exchange_envelope_requirement flags
  let table = [0,3,0,3,0,0,0,3,1,4,2,4,1,1,2,4]
      expected = if flags > 15 then -1 else table !! fromIntegral flags
  allCases <- mapM elements_hs_exchange_envelope_requirement [0..15]
  headers <- mapM (\(size,version,body) -> do
      result <- elements_hs_exchange_envelope_header size version body
      let expectedHeader | version /= 1 || size < 45 = 1
                 | body == 0 || body > 100000 || toInteger size /= 45 + toInteger body = 2
                 | otherwise = 0
      pure (result === expectedHeader))
    [(size,version,body) | size <- [0,44,45,46,100045,100046,maxBound],
       version <- [0,1,255], body <- [0,1,100000,100001,maxBound]]
  pure $ conjoin ([actual === expected, allCases === table] ++ headers)

invalidPhaseLazy :: Property
invalidPhaseLazy = forAll (frequency [(1,pure maxBound),(3,choose (4,maxBound))]) $ \phase -> ioProperty $ do
  results <- mapM (validate . (\constructor -> constructor phase (\_ -> error "invalid phase read")))
    [TrackerPhase,HeaderPhase,DisconnectPhase,Availability]
  pure $ results === replicate 4 (-1)

m6Abi :: Property
m6Abi = forAll ((,,,) <$> vectorOf 64 arbitrary <*> choose (0,300) <*> arbitrary <*> choose (0,6)) $
  \(commitments,size,amount,mode) -> ioProperty $ do
    let fields = B.pack commitments
        commitment = B.pack [if mode == (5 :: Int) then 0 else 106,32] <> B.take 32 fields
        anchor = B.pack [106,37,80,88,83,84,1] <> B.drop 32 fields
        scripts = [B.replicate size 81,commitment,B.empty,anchor]
        compact n = if n < 253 then B.singleton (fromIntegral n) else B.singleton 253 <> wordLE 2 (fromIntegral n)
        frame = wordLE 4 (if mode == 1 then 3 else 2) <> B.pack [0,4]
        body = B.concat [wordLE 8 value <> compact (B.length script) <> script |
          (value,script) <- zip [if mode == 3 then 1 else 0,0,amount,0] scripts]
        raw | mode == 2 = frame <> wordLE 8 0 <> B.pack [253,17,39]
            | otherwise = frame <> body <> wordLE 4 (if mode == 4 then 1 else 0) <> (if mode == 6 then B.singleton 0 else B.empty)
        expected = [0,1,2,3,4,5,4] !! mode
    B.useAsCStringLen raw $ \(input,count) -> withArray (replicate 66 165) $ \output -> do
      code <- elements_hs_exchange_m6 (fromIntegral count) (castPtr input) (output `plusPtr` 1)
      values <- peekArray 66 output
      noInput <- elements_hs_exchange_m6 (fromIntegral count) nullPtr output
      noOutput <- elements_hs_exchange_m6 (fromIntegral count) (castPtr input) nullPtr
      tooLarge <- elements_hs_exchange_m6 100001 (castPtr input) output
      unchanged <- peekArray 66 output
      pure $ conjoin [code === expected,
        validate (M6Preimage raw) === (if expected == 0 then Right fields else Left (fromIntegral expected)),
        values === (if expected == 0 then [165] ++ commitments ++ [165] else replicate 66 165),
        unchanged === values, conjoin (map (=== (-1)) [noInput,noOutput,tooLarge])]

sourceMarkerAbi :: Property
sourceMarkerAbi = forAll ((,,) <$> choose (0,5) <*> choose (0,4) <*> arbitrary) $ \(seen,kind,present) -> ioProperty $
  withArray [99,12345] $ \output -> do
    let expected
          | seen > 3 || kind > 2 = Left (-1)
          | kind == 2 = if seen == 0 || present then Right seen else Left 3
          | not present = Right seen
          | (if kind == 0 then odd seen else seen >= 2) = Left (fromIntegral kind + 1)
          | otherwise = Right (seen + if kind == 0 then 1 else 2)
    code <- elements_hs_exchange_source_marker seen kind (if present then 1 else 0) output
    values <- peekArray 2 output
    badFlag <- elements_hs_exchange_source_marker seen kind 2 output
    noOutput <- elements_hs_exchange_source_marker seen kind 0 nullPtr
    unchanged <- peekArray 2 output
    pure $ conjoin [validate (SourceMarker seen kind present) === expected,
      code === either fromIntegral (const 0) expected,
      values === [either (const 99) id expected,12345], unchanged === values,
      badFlag === (-1), noOutput === (-1)]

availabilityOrder :: Property
availabilityOrder = forAll ((,,) <$> choose (0,4) <*> choose (0,4) <*> arbitrary) $ \(kind,failed,throws) -> ioProperty $ do
  seen <- newIORef []
  result <- try (validate (Availability kind (\step -> do
    modifyIORef' seen (++ [step])
    if step == failed && throws then throwIO (userError "availability read") else pure (step /= failed)))) :: IO (Either IOException Int)
  observed <- readIORef seen
  absent <- elements_hs_exchange_availability kind nullFunPtr nullPtr
  ffiSeen <- newIORef []
  ffi <- bracket (makeShapeRead (\_ step -> do
    modifyIORef' ffiSeen (++ [fromIntegral step])
    pure (if fromIntegral step /= failed then 1 else if throws then -1 else 0))) freeHaskellFunPtr $
    \callback -> elements_hs_exchange_availability kind callback nullPtr
  ffiObserved <- readIORef ffiSeen
  malformed <- bracket (makeShapeRead (\_ _ -> pure 2)) freeHaskellFunPtr $
    \callback -> elements_hs_exchange_availability kind callback nullPtr
  let count = if kind == 4 then 0 else [3,2,4,1] !! fromIntegral kind
  pure $ conjoin [observed === [0 .. min count (failed+1)-1], absent === (-1),
    ffiObserved === observed, ffi === (if kind == 4 then -1 else if failed < count then 1 else 0),
    malformed === (if kind == 4 then -1 else 1),
    case result of
      Left _ -> property (throws && failed < count)
      Right code -> conjoin [property (not throws || failed >= count),
        code === (if kind == 4 then -1 else if failed >= count then 0 else 1)]]

disconnectOrder :: Property
disconnectOrder = forAll ((,,) <$> choose (0,4) <*> choose (0,7) <*> arbitrary) $ \(phase,failed,throws) -> ioProperty $ do
  seen <- newIORef []
  effects <- newIORef []
  result <- try (validate (DisconnectPhase phase (\step -> do
    modifyIORef' seen (++ [step])
    if step == failed then
      if throws then throwIO (userError "disconnect step") else pure False
    else modifyIORef' effects (++ [step]) >> pure True))) :: IO (Either IOException Int)
  observed <- readIORef seen
  applied <- readIORef effects
  let codes = case phase of
        0 -> [1,1,1,2,2,2,2]
        1 -> [3,3,3,3]
        2 -> [4,5,5]
        3 -> [6,6]
        _ -> []
      count = length codes
  absent <- elements_hs_exchange_disconnect phase nullFunPtr nullPtr
  pure $ conjoin [observed === [0 .. min count (failed+1)-1],
    applied === [0 .. min count failed-1], absent === (-1),
    case result of
      Left _ -> property (throws && failed < count)
      Right code -> conjoin [property (not throws || failed >= count),
        code === (if phase == 4 then -1 else if failed >= count then 0 else codes !! failed)]]

connectionOrder :: Property
connectionOrder = forAll ((,) <$> arbitrary <*> vectorOf 9 arbitrary) $ \(activation,facts) -> ioProperty $ do
  seen <- newIORef []
  result <- validate (Connection activation (\step -> modifyIORef' seen (++ [step]) >> pure (facts !! step)))
  observed <- readIORef seen
  let count = if activation then 9 else 6
      first = length (takeWhile id (take count facts))
  missing <- elements_hs_exchange_connection (if activation then 1 else 0) nullFunPtr nullPtr
  invalid <- elements_hs_exchange_connection 2 nullFunPtr nullPtr
  pure $ conjoin [result === (if first == count then 0 else if first < 6 then 1 else 2),
    observed === [0 .. min count (first+1)-1], missing === (-1), invalid === (-1)]

parentTarget :: Property
parentTarget = forAll ((,,) <$> arbitrary <*> arbitrary <*> frequency
  [(1,arbitrary),(3,elements [0,1,4294967294,4294967295,4294967296,maxBound])]) $ \(present,testNetwork,height) -> ioProperty $ do
  seen <- newIORef []
  result <- validate (ParentTarget (if present then Just height else Nothing) (\step -> do
    modifyIORef' seen (++ [step])
    pure (if step == 0 then if testNetwork then 1 else 0 else height)))
  observed <- readIORef seen
  let candidate = if present then toInteger height else toInteger height + 1
      expected | not present && not testNetwork = Left 1
               | candidate < 1 || candidate > 4294967295 = Left 2
               | otherwise = Right (fromInteger candidate)
  withArray [999,12345] $ \output -> do
    code <- elements_hs_exchange_parent_target 1 height nullFunPtr nullPtr output
    values <- peekArray 2 output
    missing <- elements_hs_exchange_parent_target 0 height nullFunPtr nullPtr output
    invalid <- elements_hs_exchange_parent_target 2 height nullFunPtr nullPtr output
    noOutput <- elements_hs_exchange_parent_target 1 height nullFunPtr nullPtr nullPtr
    preserved <- peekArray 2 output
    let validHeight = height > 0 && height <= 4294967295
    pure $ conjoin [result === expected, observed === (if present then [] else if testNetwork then [0,1] else [0]),
      code === (if validHeight then 0 else 2), values === [if validHeight then height else 999,12345], preserved === values,
      conjoin (map (=== (-1)) [missing,invalid,noOutput])]

headerOrder :: Property
headerOrder = forAll ((,,) <$> choose (0,3) <*> choose (0,11) <*> arbitrary) $ \(phase,failed,throws) -> ioProperty $ do
  seen <- newIORef []
  result <- try (validate (HeaderPhase phase (\step -> do
    modifyIORef' seen (++ [step])
    if step == failed && throws then throwIO (userError "header read") else pure (step /= failed)))) :: IO (Either IOException Int)
  observed <- readIORef seen
  absent <- elements_hs_exchange_header phase nullFunPtr nullPtr
  invalid <- elements_hs_exchange_header maxBound nullFunPtr nullPtr
  let count = if phase == 3 then 0 else [11,8,6] !! fromIntegral phase
  pure $ conjoin [absent === (-1), invalid === (-1), observed === [0 .. min count (failed+1)-1],
    case result of
      Left _ -> property (throws && failed < count)
      Right code -> conjoin [code === (if phase == 3 then -1 else if failed < count then 1 else 0),
                            property (not throws || failed >= count)]]

configurationOrder :: Property
configurationOrder = forAll (vectorOf 14 arbitrary) $ \facts -> ioProperty $ do
  seen <- newIORef []
  result <- validate (Configuration (\step -> modifyIORef' seen (++ [step]) >> pure (facts !! step)))
  observed <- readIORef seen
  missing <- elements_hs_exchange_configuration nullFunPtr nullPtr
  let first = length (takeWhile id facts)
      expected = if first == 14 then 0 else if first == 0 then 1 else if first < 4 then 2 else if first < 13 then 3 else 4
  pure $ conjoin [result === expected, observed === [0 .. min 14 (first+1)-1], missing === (-1)]

trackerOrder :: Property
trackerOrder = forAll ((,) <$> choose (0,3) <*> choose (0,7)) $ \(phase,failed) -> ioProperty $ do
  seen <- newIORef []
  result <- validate (TrackerPhase phase (\step -> modifyIORef' seen (++ [step]) >> pure (step /= failed)))
  observed <- readIORef seen
  absent <- elements_hs_exchange_tracker phase nullFunPtr nullPtr
  let count = if phase == 3 then 0 else [5,7,3] !! fromIntegral phase
  pure $ conjoin [result === (if phase == 3 then -1 else if phase == 0 && failed == 0 then 2 else if failed < count then 1 else 0),
    observed === [0 .. min count (failed+1)-1], absent === (-1)]

trancheParity :: Property
trancheParity = forAll (choose (0,140) >>= \n -> vectorOf n (frequency [(8,elements [0,1,2]),(1,arbitrary)])) $ \kinds -> ioProperty $
  withArray kinds $ \input -> withArray [999,12345] $ \output -> do
    let reference accumulated visited [] = (0,accumulated,visited)
        reference accumulated visited (kind:rest)
          | kind > 2 = (1,accumulated,visited+1)
          | accumulated + cost > 64 = (2,accumulated,visited+1)
          | otherwise = reference (accumulated+cost) (visited+1) rest
          where cost = if kind == 0 then 1 else if kind == 1 then 64 else 0
        (expected,work,visits) = reference (0 :: Integer) (0 :: Int) kinds
    code <- elements_hs_exchange_tranche (fromIntegral (length kinds)) input output
    actual <- peekArray 2 output
    invalid <- elements_hs_exchange_tranche 1 nullPtr output
    canary <- peekArray 2 output
    seen <- newIORef (0 :: Int)
    result <- validate (Tranche (fromIntegral (length kinds)) (\index -> do
      modifyIORef' seen (+1)
      pure (kinds !! fromIntegral index)))
    observedReads <- readIORef seen
    pure $ conjoin [code === expected, actual === [fromInteger work,12345], invalid === (-1),
      canary === actual, result === (fromIntegral expected,fromInteger work), observedReads === visits]

forcedAbi :: Property
forcedAbi = forAll generator $ \(kind,body,chain,market) -> ioProperty $
  withArray body $ \b -> withArray chain $ \c -> withArray market $ \m -> do
    result <- elements_hs_exchange_forced_body kind (fromIntegral (length body)) b c m
    let expected = validate (ForcedBody (fromIntegral kind) (B.pack body) (B.pack chain) (B.pack market))
    invalid <- elements_hs_exchange_forced_body 3 maxBound nullPtr nullPtr nullPtr
    missing <- elements_hs_exchange_forced_body 0 201 nullPtr c m
    preserved <- peekArray (length body) b
    pure $ conjoin [result === fromIntegral expected, invalid === 1, missing === (-1), preserved === body]
  where
    generator = do
      kind <- choose (0,4)
      size <- elements [0,1,192,193,194,200,201,202,207,208,209]
      body <- vectorOf size arbitrary
      chain <- vectorOf 32 arbitrary
      market <- vectorOf 16 arbitrary
      pure (kind,body,chain,market)

authorityOrder :: Property
authorityOrder = forAll ((,,) <$> arbitrary <*> choose (0,8) <*> arbitrary) $ \(successor,failed,throws) -> ioProperty $ do
  trace <- newIORef []
  let steps = if successor then [0..7] else [0,1,2,5,6,7]
      (prefix,suffix) = break (== failed) steps
      visited = prefix ++ take 1 suffix
      expected = if null suffix then 0 else [1,1,1,2,3,4,4,4] !! failed
      reader step = do
        modifyIORef' trace (++ [step])
        if step == failed && throws then throwIO (userError "reader failure")
          else pure (step /= failed)
  result <- try (validate (Authority successor reader)) :: IO (Either IOException Int)
  seen <- readIORef trace
  absent <- elements_hs_exchange_authority 0 nullFunPtr nullPtr
  invalid <- elements_hs_exchange_authority 2 nullFunPtr nullPtr
  pure $ conjoin [absent === (-1), invalid === (-1), seen === visited,
    case result of
      Left _ -> property (throws && not (null suffix))
      Right code -> conjoin [code === expected, property (not throws || null suffix)]]

profileOrder :: Property
profileOrder = forAll ((,,) <$> arbitrary <*> choose (0,7) <*> arbitrary) $ \(collateral,failed,throws) -> ioProperty $ do
  trace <- newIORef []
  let count = if collateral then 7 else 6
      reader step = do
        modifyIORef' trace (++ [step])
        if step == failed && throws then throwIO (userError "profile read") else pure (step /= failed)
  result <- try (validate (OutputProfile collateral reader)) :: IO (Either IOException Int)
  seen <- readIORef trace
  absent <- elements_hs_exchange_profile 0 nullFunPtr nullPtr
  invalid <- elements_hs_exchange_profile 2 nullFunPtr nullPtr
  pure $ conjoin [seen === [0 .. min count (failed+1)-1], absent === (-1), invalid === (-1),
    case result of
      Left _ -> property (throws && failed < count)
      Right code -> conjoin [code === (if failed < count then 1 else 0), property (not throws || failed >= count)]]

exchangeArithmetic :: Property
exchangeArithmetic = forAll generator $ \rule -> validate rule === oracle rule
  where
    word = frequency [(3,elements [0,1,5,6,63,64,65,447,448,449,maxBound-6,maxBound]),(1,arbitrary)]
    backlog = frequency
      [(1,Backlog <$> word <*> word <*> word <*> word),
       (3,do f <- word; d <- word; fc <- choose (0,f); dc <- choose (0,d); pure (Backlog f fc d dc))]
    generator = oneof [AppendBudget <$> backlog,
      Liveness <$> backlog <*> backlog <*> word <*> word <*> word <*> word]

-- Integer oracle uses total sums, independent of bounded subtractive admission.
oracle :: InboxRule -> (Maybe InboxError, Maybe Word64)
oracle (ActivationCounts active forced deposits)
  | not active || (forced==0 && deposits==0) = (Nothing,Nothing)
  | otherwise = (Just ActivationAppends,Nothing)
oracle (AppendBudget b)
  | not (valid b) = (Just InvalidCursor,Just 0)
  | total b > 64 = (Just BacklogLimit,Just 0)
  | otherwise = (Nothing,Just (fromInteger (64-total b)))
oracle (Liveness p n f d old height)
  | not (valid p && valid n) = failure InvalidCursor
  | appends > 64 = failure AppendLimit
  | total p + appends > 448 = failure WitnessLimit
  | total n > 64 = failure BacklogLimit
  | total n == 0 = (Nothing,Just 0)
  | height == 0 = failure MissingHeight
  | total p /= 0 && (old == 0 || old > height) = failure InvalidAge
  | otherwise = (if age + 6 > toInteger (maxBound :: Word64) || toInteger height >= age + 6
                  then Just Deadline else Nothing, Just (fromInteger age))
  where
    appends = toInteger f + toInteger d
    age = toInteger (if total p == 0 then height else old)
    failure err = (Just err,Nothing)

valid :: Backlog -> Bool
valid (Backlog f fc d dc) = fc <= f && dc <= d

cursorAbi :: Property
cursorAbi = forAll generator $ \(flags,pf,pd,mf,md) -> ioProperty $
  withArray [pf,pd,mf,md] $ \input -> withArray [101,102,12345] $ \output -> do
    let transitioned = testBit flags 0; found = testBit flags 1
        activation = testBit flags 2 && pf == 0 && pd == 0
        same = testBit flags 3
        (expected,values) = case (transitioned,found) of
          (False,False) -> (0,[pf,pd,12345])
          (False,True) -> (2,[101,102,12345])
          (True,False) | activation -> (0,[0,0,12345])
                       | otherwise -> (1,[101,102,12345])
          (True,True) | same && mf >= pf && md >= pd -> (0,[mf,md,12345])
                      | otherwise -> (3,[101,102,12345])
    code <- elements_hs_exchange_cursors flags input output
    result <- peekArray 3 output
    badFlags <- elements_hs_exchange_cursors 16 input output
    noInput <- elements_hs_exchange_cursors flags nullPtr output
    noOutput <- elements_hs_exchange_cursors flags input nullPtr
    unchanged <- peekArray 3 output
    pure $ conjoin [code === expected, result === values, unchanged === result,
      conjoin (map (=== (-1)) [badFlags,noInput,noOutput])]
  where
    word = frequency [(1,arbitrary),(2,elements [0,1,2,64,maxBound])]
    generator = (,,,,) <$> choose (0,15) <*> word <*> word <*> word <*> word

total :: Backlog -> Integer
total (Backlog f fc d dc) = toInteger f - toInteger fc + toInteger d - toInteger dc

exchangeAbi :: Property
exchangeAbi = conjoin [sourceBytesAbi, markerBoundsAbi, bondMarkerAbi, livenessAbi, activationCountsAbi, pendingAbi]

pendingAbi :: Property
pendingAbi = forAll ((,,,) <$> count <*> count <*> count <*> count) $ \(f,fc,d,dc) -> ioProperty $
  withArray [f,fc,d,dc] $ \input -> withArray ([91,92,93,94] :: [Word64]) $ \output -> do
    let accepted = fc <= f && dc <= d
        difference x y = fromInteger (toInteger x-toInteger y)
        expected = if accepted then [91,difference f fc,difference d dc,94] else [91,92,93,94]
    code <- elements_hs_exchange_inbox 5 4 input (output `plusPtr` 8)
    result <- peekArray 4 output
    malformed <- sequence [elements_hs_exchange_inbox 5 n input (output `plusPtr` 8) | n <- [0,3,5,maxBound]]
    noInput <- elements_hs_exchange_inbox 5 4 nullPtr (output `plusPtr` 8)
    noOutput <- elements_hs_exchange_inbox 5 4 input nullPtr
    preserved <- peekArray 4 output
    pure $ conjoin [code === (if accepted then 0 else 1), result === expected,
      malformed === replicate 4 (-1), noInput === (-1), noOutput === (-1), preserved === result]
  where count = frequency [(2,arbitrary),(1,elements [0,1,4294967295,4294967296,maxBound-1,maxBound])]

activationCountsAbi :: Property
activationCountsAbi = forAll ((,,) <$> elements [0,1,2,maxBound] <*> amount <*> amount) $ \(active,forced,deposits) ->
  ioProperty $ withArray [active,forced,deposits] $ \input -> withArray [99,99,12345] $ \output -> do
    code <- elements_hs_exchange_inbox 4 3 input output
    result <- peekArray 3 output
    invalid <- sequence [elements_hs_exchange_inbox mode count input output |
      (mode,count) <- [(4,2),(4,4),(5,3),(0,3)]]
    noInput <- elements_hs_exchange_inbox 4 3 nullPtr output
    noOutput <- elements_hs_exchange_inbox 4 3 input nullPtr
    unchanged <- peekArray 3 output
    let expected = if active>1 then -1 else if active==1 && (forced/=0 || deposits/=0) then 8 else 0
        rule = ActivationCounts (active==1) forced deposits
    pure $ conjoin [code===expected,result===(if active>1 then [99,99,12345] else [0,0,12345]),
      unchanged===result,invalid===replicate 4 (-1),noInput===(-1),noOutput===(-1),validate rule===oracle rule]
  where amount = frequency [(1,pure 0),(1,elements [1,maxBound]),(1,arbitrary)]

bondMarkerAbi :: Property
bondMarkerAbi = forAll (choose (0,4)) $ \kind -> forAll (choose (0,502)) $ \offset ->
  forAll (elements [0,1,7,31,255]) $ \byte -> forAll (elements [0,1,65536]) $ \limit -> ioProperty $ do
    let replace n xs ys = take n ys ++ xs ++ drop (n+length xs) ys
        required = [70,102,210,306,370,407]
        base = foldr (\n -> replace n [1]) (replicate 503 0) required
        staged = if kind == 1 then foldr (\n -> replace n [1]) base [134,170,209]
                 else replace 166 (replicate 4 255) base
        payload = replace offset [byte] . replace 406 [7] . replace 405 [1] . replace 5 [kind] $ staged
        part n i = take n (drop i payload)
        zero i = all (==0) (part 32 i)
        bundle = foldl (\a b -> a*256+toInteger b) 0 (part 4 402)
        bitmap = payload !! 406
        enqueue = payload !! 5 == 1
        sentinel = part 4 166 == replicate 4 255
        refundZero = all (==0) (part 8 202)
        identitiesBad = any (not . zero) [6,38,242,274] || payload !! 5 > 3 || any zero required ||
          bundle == 0 || bundle > toInteger limit || bitmap > 31 || length (filter (testBit bitmap) [0..7]) < 3
        stagingGood = if enqueue then not sentinel && not (zero 134) && not (zero 170) && not refundZero
                      else sentinel && zero 134 && zero 170 && refundZero
        expected = if identitiesBad then 1 else if stagingGood then 0 else 2
    withArray payload $ \input -> withArray (replicate 128 0) $ \identities -> do
      code <- elements_hs_exchange_bond_marker limit 503 input identities
      badSize <- elements_hs_exchange_bond_marker limit 502 input identities
      noInput <- elements_hs_exchange_bond_marker limit 503 nullPtr identities
      noIdentities <- elements_hs_exchange_bond_marker limit 503 input nullPtr
      pure $ conjoin [code === fromIntegral expected, badSize === (-1), noInput === (-1), noIdentities === (-1),
        validate (BondMarker limit (B.pack payload) (B.replicate 128 0)) === expected]

markerBoundsAbi :: Property
markerBoundsAbi = forAll ((:) <$> elements [0,1,2] <*> vectorOf 10 word) $ \fields -> ioProperty $
  withArray fields $ \input -> withArray [99,99,12345] $ \output -> case fields of
    [successor,height,delay,kind,refundDelay,refundHeight,markers,limit,count,tx,vout] -> do
      let deadline = toInteger height + toInteger delay
          refund = toInteger height + toInteger refundDelay
          max64 = toInteger (maxBound :: Word64)
          expectedCode | successor > 1 = -1
                       | deadline > max64 = 1
                       | kind == 1 && (refund > max64 || toInteger refundHeight < refund) = 2
                       | markers == limit || (successor == 0 && count == maxBound) || tx > 4294967295 || vout > 4294967295 = 3
                       | otherwise = 0
          expected = if successor > 1 then [99,99] else if deadline > max64 then [0,0] else [1,fromInteger deadline]
      code <- elements_hs_exchange_inbox 3 11 input output
      result <- peekArray 3 output
      invalid <- sequence [elements_hs_exchange_inbox m n input output | (m,n) <- [(3,10),(3,12),(4,11)]]
      noInput <- elements_hs_exchange_inbox 3 11 nullPtr output
      noOutput <- elements_hs_exchange_inbox 3 11 input nullPtr
      preserved <- peekArray 3 output
      pure $ conjoin [code === expectedCode, result === (expected ++ [12345]),
        invalid === replicate 3 (-1), noInput === (-1), noOutput === (-1), preserved === result]
    _ -> pure (property False)
  where word = frequency [(3,elements [0,1,6,4294967295,4294967296,maxBound-1,maxBound]),(2,choose (0,100))]

sourceBytesAbi :: Property
sourceBytesAbi = forAll ((,,,,,) <$> word <*> word <*> word <*> word <*> word <*> word) $ \(w,t,aw,at,mw,mt) -> ioProperty $
  withArray [w,t,aw,at,mw,mt] $ \input -> withArray [99,99,12345] $ \output -> do
    let sw = toInteger w + toInteger aw
        st = toInteger t + toInteger at
        overflow = sw > 4294967295 || st > 4294967295
        expectedCode = if overflow then 1 else if sw > toInteger mw || st > toInteger mt then 2 else 0
        expected = if overflow then [w,t] else map fromInteger [sw,st]
    code <- elements_hs_exchange_inbox 2 6 input output
    result <- peekArray 3 output
    invalid <- sequence [elements_hs_exchange_inbox m n input output | (m,n) <- [(2,5),(2,7),(3,6)]]
    noInput <- elements_hs_exchange_inbox 2 6 nullPtr output
    noOutput <- elements_hs_exchange_inbox 2 6 input nullPtr
    preserved <- peekArray 3 output
    pure $ conjoin [code === fromIntegral expectedCode, result === (expected ++ [12345]),
      invalid === replicate 3 (-1), noInput === (-1), noOutput === (-1), preserved === result,
      validate (SourceBytes w t aw at mw mt) === (expectedCode,expected)]
  where word = frequency [(3,elements [0,1,4294967294,4294967295,4294967296,maxBound]),(2,choose (0,4294967295))]

livenessAbi :: Property
livenessAbi = forAll (vectorOf 12 arbitrary) $ \fields -> ioProperty $
  withArray fields $ \input -> withArray [99,99,12345] $ \output -> do
    let (err,value) = case fields of
          [f,fc,d,dc,nf,nfc,nd,ndc,fa,da,old,height] ->
            oracle (Liveness (Backlog f fc d dc) (Backlog nf nfc nd ndc) fa da old height)
          _ -> error "generator returned wrong field count"
    code <- elements_hs_exchange_inbox 1 12 input output
    result <- peekArray 3 output
    badCount <- elements_hs_exchange_inbox 1 11 input output
    badMode <- elements_hs_exchange_inbox 2 12 input output
    noInput <- elements_hs_exchange_inbox 1 12 nullPtr output
    noOutput <- elements_hs_exchange_inbox 1 12 input nullPtr
    unchanged <- peekArray 3 output
    pure $ conjoin [code === maybe 0 ((+1) . fromIntegral . fromEnum) err,
      result === (maybe [0,0] (\n -> [1,n]) value ++ [12345]),
      unchanged === result, conjoin (map (=== (-1)) [badCount,badMode,noInput,noOutput])]
