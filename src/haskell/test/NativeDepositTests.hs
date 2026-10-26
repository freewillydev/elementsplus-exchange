{-# LANGUAGE TypeFamilies #-}
module NativeDepositTests (properties) where

import Control.Exception (SomeException, try)
import Control.Monad (when)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Except (runExceptT)
import Control.Operation
import Control.Operation.Validation (validate)
import Data.Bits ((.&.), (.|.), shiftL, shiftR)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.Int (Int32, Int64)
import Data.IORef
import Data.Maybe (isNothing)
import Data.Word (Word32, Word64)
import Foreign.Marshal.Array (withArray)
import Foreign.Marshal.Utils (withMany)
import Foreign.Ptr (castPtr, nullPtr, nullFunPtr)
import qualified Deposit as D
import qualified Drivechain as FFI
import qualified NativeDeposit as N
import Test.QuickCheck hiding (witness, witnesses, (.&.))
import Withdrawal (wordLE)
import Workflow (NativeBytes)

type Event = (Word32,Word64,B.ByteString)
bound :: Int64
bound = 2100000000000000

capture :: Int -> [(Word32,B.ByteString)] -> (NativeBytes -> IO Int32) -> IO (Int32,[Event])
capture failure overrides action = do
  events <- newIORef []
  let native step index input = do
        prior <- readIORef events
        modifyIORef' events (++ [(step,index,input)])
        when (length prior == failure) (ioError (userError "native deposit test fault"))
        pure $ case lookup step overrides of
          Just bytes -> bytes
          Nothing | step == 2 -> wordLE 8 1
                  | otherwise -> B.empty
  result <- try (action native) :: IO (Either SomeException Int32)
  (,) (either (const (-1)) id result) <$> readIORef events

recipient :: Word32 -> Int64 -> B.ByteString -> NativeBytes -> IO Int32
recipient mode amount bytes native = execute
  (N.Recipient bound amount (fromIntegral (B.length bytes)) (pure bytes) native) $ case mode of
    0 -> N.DecodeRecipient
    1 -> N.EncodeRecipient
    2 -> N.ConstructNative
    _ -> error "unknown test recipient"

codec :: Property
codec = forAll (choose (1,bound)) $ \fee ->
  forAll (chooseInt (1,90)) $ \size -> ioProperty $ do
    let address = C.replicate size 'x'
        payload = C.pack ("dcfee1:" ++ show fee ++ ":") <> address
    (encoded,events) <- capture (-1) [] (recipient 1 fee address)
    (decoded,decodeEvents) <- capture (-1) [] (recipient 0 0 payload)
    pure $ conjoin [encoded === 0, decoded === 0,
      events === [(2,1,B.empty),(4,0,payload)],
      decodeEvents === [(1,0,B.empty),(2,0,address),(3,0,wordLE 8 (fromIntegral fee))],
      N.destination bound payload === Just (address,fee)]

invalidFees :: Property
invalidFees = once $ ioProperty $ conjoin <$> mapM (\fee -> do
  let payload = C.pack ("dcfee1:" ++ fee ++ ":address")
  result <- capture (-1) [] (recipient 0 0 payload)
  pure (result === (1,[(1,0,B.empty)])))
  ["0","00","01","+1","-1"," 1","1 ","1.0","1e2","",
   "2100000000000001","9223372036854775808",replicate 200 '9',"1\NUL"]

construction :: Property
construction = forAll (elements [0,1,100,bound-1]) $ \fee -> ioProperty $ do
  let payload = if fee == 0 then C.pack "address" else C.pack ("dcfee1:" ++ show fee ++ ":address")
      expected = [(1,0,B.empty),(2,0,C.pack "address"),(3,0,wordLE 8 (fromIntegral fee)),
        (5,0,B.empty),(6,0,wordLE 8 1)] ++
        [(7,0,wordLE 8 (fromIntegral fee)) | fee > 0] ++ [(8,0,B.empty),(9,0,B.empty)]
  result <- capture (-1) [] (recipient 2 (fee+1) payload)
  tooSmall <- capture (-1) [] (recipient 2 fee payload)
  pure $ conjoin [result === (0,expected),tooSmall === (3,take 3 expected)]

faults :: Property
faults = once $ ioProperty $ do
  let run = recipient 2 100 (C.pack "dcfee1:1:address")
  (_,trace) <- capture (-1) [] run
  conjoin <$> mapM (\i -> (=== (-1,take (i+1) trace)) <$> capture i [] run) [0..length trace-1]

malformed :: Property
malformed = once $ ioProperty $ conjoin <$> mapM (\(step,bytes) -> do
  (result,events) <- capture (-1) [(step,bytes)] (recipient 2 100 (C.pack "dcfee1:1:address"))
  pure $ conjoin [result === -1, property (not (null events)), property (all (\(s,_,_) -> s /= 9) events)])
  ([(s,B.singleton 1) | s <- [1,3,5,6,7,8]] ++ [(2,B.empty),(2,wordLE 8 2)])

withOutputs :: Bool -> Int64 -> Word64 -> Word64 -> Word64 -> NativeBytes -> (N.Outputs -> IO a) -> IO a
withOutputs broken fee inputs witnesses count native action =
  let asset = B.replicate 32 3; genesis = B.replicate 32 4; txid = B.replicate 32 5
      address = C.pack (if fee == 0 then "address" else "dcfee1:" ++ show fee ++ ":address")
      stack = [wordLE 8 100,if broken then B.empty else asset,genesis,B.singleton 81,
        C.pack "drivechain-deposit-v2",txid,txid,address]
  in withMany B.useAsCString stack $ \pointers -> withArray (map castPtr pointers) $ \fields ->
    withArray (map (fromIntegral . B.length) stack) $ \sizes ->
    B.useAsCString asset $ \a -> B.useAsCString genesis $ \g -> B.useAsCString txid $ \t ->
      action (N.Outputs inputs 0 witnesses count bound
        (\_ mode amount -> pure (D.DepositWitness bound 4000000 mode 8 sizes fields
          (castPtr a) (castPtr g) (castPtr t) nullFunPtr amount))
        (\_ i -> pure (stack !! i)) native)

outputs :: Property
outputs = forAll (elements [0,1,99,100,101]) $ \fee ->
  forAll arbitrary $ \broken -> forAll (choose (0,7)) $ \input ->
  forAll (chooseInt (0,4) >>= \n -> vectorOf n ((,) <$> choose (0,31) <*> choose (-1,101))) $ \rows ->
    ioProperty $ do
      let projected (flags,value) =
            let credit = (if flags .&. 16 /= 0 then 1 else 0) .|.
                  ((flags .&. 1) `shiftL` 1) .|. ((flags .&. 2) `shiftL` 1)
            in (credit .|. (flags `shiftL` 8),value)
          packed = map projected rows :: [(Word64,Int64)]
          native step i _ = pure $ case step of
            2 -> wordLE 8 1
            10 -> wordLE 8 input
            20 -> let (flags,value) = packed !! fromIntegral i in wordLE 8 flags <> wordLE 8 (fromIntegral value)
            _ -> B.empty
          amount = if broken then 0 else 100
          actualFee = if broken then 0 else fee
          inputFacts = (if input .&. 4 == 0 then 1 else 0) .|. (if broken then 0 else 14)
          legacy = validate (D.DepositOutputs inputFacts (amount-actualFee)
            [(if broken then 0 else 1) .|. (fromIntegral (input .&. 1) `shiftL` 1)]
            [(fromIntegral f,v) | (f,v) <- packed])
          exactFlags = fromIntegral ((input .&. 1) .|. 2 .|. ((input .&. 6) `shiftL` 1) .|. 112)
          exact = validate (D.AuthenticatedDeposit 1 0 1 exactFlags amount amount (fromIntegral (length rows))
            [(fromIntegral (f `shiftR` 8),v) | (f,v) <- take 2 packed])
          expected | actualFee > 0 && actualFee >= amount = 2
                   | legacy /= 0 = 0x100+legacy
                   | actualFee /= 0 && exact /= 0 = 0x200+exact
                   | otherwise = 0
      actual <- withOutputs broken fee 1 1 (fromIntegral (length rows)) native
        (\value -> execute value N.CheckOutputs)
      pure (actual === expected)

outputFaults :: Property
outputFaults = once $ ioProperty $ do
  let run failure = capture failure [(10,wordLE 8 7),(20,wordLE 8 (7 .|. (23 `shiftL` 8)) <> wordLE 8 100)]
        (\native -> withOutputs False 0 1 1 1 native (\value -> execute value N.CanonicalFeeFree))
  (valid,trace) <- run (-1)
  checks <- mapM (\i -> (=== (-1,take (i+1) trace)) <$> run i) [0..length trace-1]
  pure (conjoin ((valid === 0):checks))

lazyDispatch :: Property
lazyDispatch = once $ ioProperty $ do
  let bottom = error "forced rejected native request"
      recipientValue = N.Recipient bound 0 0 bottom (\_ _ _ -> pure B.empty)
      outputValue = N.Outputs 0 0 0 0 bound bottom bottom bottom
  decoded <- execute recipientValue N.DecodeRecipient
  checked <- execute outputValue N.CheckOutputs
  canonical <- execute outputValue N.CanonicalFeeFree
  unknown <- FFI.elements_hs_native_recipient 99 bound 0 maxBound nullPtr nullFunPtr nullPtr
  other <- FFI.elements_hs_native_outputs 99 0 0 0 0 bound 0 nullPtr nullPtr nullPtr nullPtr nullPtr nullPtr nullFunPtr nullFunPtr nullPtr
  pure $ conjoin [decoded === 1,checked === 1,canonical === 3,unknown === -1,other === -1,
    property (isNothing (interpret (SomeOperation outputValue) (bottom :: DSL N.Recipient))),
    property (isNothing (interpret (SomeOperation recipientValue) (bottom :: DSL N.Outputs)))]

newtype ConstructionProbe = ConstructionProbe (IORef [Int64])
instance N.RecipientDecoding ConstructionProbe where
  decodeRecipient (ConstructionProbe seen) = liftIO (modifyIORef' seen (++ [1])) >> pure 7
instance N.NativeAssembly ConstructionProbe where
  assembleNative (ConstructionProbe seen) fee = liftIO (modifyIORef' seen (++ [fee]))

composition :: Property
composition = once $ ioProperty $ do
  seen <- newIORef []
  result <- runExceptT (N.constructNative (ConstructionProbe seen))
  trace <- readIORef seen
  pure $ conjoin [result === Right (),trace === [1,7]]

properties :: [(String,Property)]
properties =
  [("native deposit / canonical recipient round trip and effects",codec),
   ("native deposit / noncanonical fees",invalidFees),
   ("native deposit / ordered assembly and amount admission",construction),
   ("native deposit / assembly callback failures",faults),
   ("native deposit / malformed replies",malformed),
   ("native deposit / output projection and original rule parity",outputs),
   ("native deposit / canonical output callback failures",outputFaults),
   ("native deposit / lazy dispatch and unknown ABI modes",lazyDispatch),
   ("native deposit / generic capability composition",composition)]
