-- Copyright (c) 2026 The Elements Core developers
-- Distributed under the MIT software license.
module BmmConstants where

import Data.Word (Word8, Word32, Word64)
import Data.Int (Int64)
import Data.Char (ord, toUpper)
import Data.List (intercalate, nub)

-- Historical Alpha-only activation, outside the M1/genesis identity.
alphaPeginOneConfirmationHeight :: Int64
alphaPeginOneConfirmationHeight = 64

-- Historical eligibility pins, not aliases for mutable current-network defaults.
peginIdentityNetwork :: String
peginIdentityNetwork = "elements"

peginIdentitySlot, peginIdentityDepth :: Word32
peginIdentitySlot = 24
peginIdentityDepth = 100

peginIdentityPins :: [(String,String)]
peginIdentityPins =
  [("PEGIN_ALPHA_GENESIS","672af009bd90bfc6527a5a9dda4c83aba0048c15cff3697d07e89a7f96fa5bcd"),
   ("PEGIN_PARENT_GENESIS","000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"),
   ("PEGIN_ALPHA_MANIFEST","fbd55822590e0e7a3389c2316171068b2fe7ddbb35c52aa010159bfbd92d09e6"),
   ("PEGIN_BETA_GENESIS","a7754ce0debc40baddbd8c47e79d19209685f22c63edaaf8b69cf54116374d7f"),
   ("PEGIN_BETA_MANIFEST","5c3d0dab899b95e05a47691bed1a0bdca87938faca69ab04985a4c43a970a673")]

peginIdentityHeader :: String
peginIdentityHeader = unlines $
  ["// Generated from BmmConstants.hs; do not edit.", "#pragma once", "#include <cstdint>",
   "namespace drivechain {",
   "inline constexpr uint32_t PEGIN_IDENTITY_SLOT{" ++ show peginIdentitySlot ++ "};",
   "inline constexpr uint32_t PEGIN_IDENTITY_DEPTH{" ++ show peginIdentityDepth ++ "};"] ++
  ["inline constexpr char " ++ name ++ "[]{" ++ show value ++ "};" |
    (name,value) <- ("PEGIN_IDENTITY_NETWORK",peginIdentityNetwork) : peginIdentityPins] ++ ["}"]

compressedSp1Cost :: Word32
compressedSp1Cost = 900007720

-- Public jet identifiers are native adapters; digests and types are frozen.
publicJetPins :: [(String,String,String,String,String,Word32)]
publicJetPins =
  [("CURRENT_BMM_PARENT_MTP","current_bmm_parent_mtp","12dc3d4f22466873daaf83b10e1cfa1ea551e23ae7d0fbd6d9da64ce7e89a3e2","u","mw64",108),
   ("CURRENT_BMM_PARENT_MTP_REQUIRED","native_current_bmm_parent_mtp_required","c824e737318c66258d0b094d9ad35380ef1f58484c27ad47dea02ca345e0c061","u","w64",108),
   ("FE_IS_SQUARE_TOTAL","fe_is_square_total","ae9ed26c25af1ff1217a944bc849db9217124d63d3fa3590c030a9dafb0213e8","w256","b",108),
   ("INPUT_IS_PEGIN","input_is_pegin","e5d2571137e635b83c813800d1167215ec512d9a61a1d5b2e8b80f5030bcf612","w32","b",108),
   ("ISSUANCE_IS_NONE","issuance_is_none","25cc2f7ba2f4eb93053076d482a0439efeaba84b12fc60b188ed750df5a5a807","w32","b",108),
   ("PRIOR_ACTIVE_BMM_PARENT_CHECKPOINT_REQUIRED","prior_active_bmm_parent_checkpoint_required","9c1194d4572852baa7320808db7f4ea64c0f1785f08a08b67b51efd96597882a","u","pw256pw64pw64w256",216),
   ("VERIFY_SP1_COMPRESSED_SHA256","verify_sp1_compressed_sha256","595cfa3adbc83e616918a6a51441ba847f19faf7e77f3cb97d21314e28928399","w512","b",compressedSp1Cost)]

jetRecord :: (String,String,String,String,String,Word32) -> String -> [String]
jetRecord (name,function,digest,source,target,cost) note =
  [",[" ++ name ++ "] =", "{ .tag = JET", ", .jet = simplicity_" ++ function,
   ", .cmr = {{" ++ intercalate ", " ["0x" ++ take 8 (drop offset digest) ++ "u" | offset <- [0,8..56]] ++ "}}",
   ", .sourceIx = ty_" ++ source, ", .targetIx = ty_" ++ target,
   ", .cost = " ++ show cost ++ " /* " ++ note ++ " */", "}"]

publicJetHeader :: String
publicJetHeader = unlines $ "/* Generated from BmmConstants.publicJetHeader; do not edit. */" :
  concatMap (`jetRecord` "milli weight units") publicJetPins

-- Historical private-only specification fingerprints and costs, not the newer
-- 24-entry typed production catalogue. Preserve these identities byte-for-byte.
privateJetPins :: [(String,String,String,String,Word32)]
privateJetPins =
  [("prior_active_exchange_state_root_required","0c5ab500b3aa0c2657d88c32d52acb24bf9ff2ef2b948e551052f177c250934a","u","w256",235),
   ("prior_active_forced_inbox_root_required","6bac39b527d124fbc9ef8b29b74fcfb31593b5cc901a9e359900d89abc9ebfeb","u","w256",231),
   ("prior_active_deposit_inbox_root_required","6f27eefe75e280bcb1c5617542108453eea376a7fd7a3e3164b6a84f6ad420a9","u","w256",235),
   ("prior_active_forced_processed_cursor_required","8586ea416a440270a41cddc47d984b8e3fc263c19a653cf3da4b02db72f8ddb5","u","w64",193),
   ("prior_active_deposit_processed_cursor_required","56375fde02ea03bd14f2dd2a19a8eed5319f2c9812937ac3f8d4e9dc0ea940f9","u","w64",191),
   ("current_bmm_parent_block_hash_required","78522ee4b12802e83c6a369dc752600eef635b7cc93c877e77bf291df6d009cb","u","w256",236),
   ("current_bmm_parent_height_required","117f2e10d293772e39df4d49958742634a61f00839262a6734c9f072c3108a76","u","w64",195),
   ("current_bmm_parent_mtp_required","8e17f5d5dfbfbd1136a1a05b8a3bcccd063d2e99c3d489935b290b151d3b08d1","u","w64",202),
   ("bond_v2_configuration_hash_required","b315a9678610baabe9f73382f08b7a06145fa1243dec4d9a9477311de2acf5b8","u","w256",235),
   ("bond_v2_asset_id_required","5fa2f1ef55935afdbee1da4957b6b572373de42920917ab7fb7b7759636ac587","u","w256",234),
   ("bond_v2_deployment_commitment_required","dd7a30f8ab05ee8f6e8bebf85a34a1e408f3817d8f149663ea880f34f0ae13cb","u","w256",234),
   ("bond_v2_transition_cmr_required","1b566de0815028e32c044ee623fb273b1c889df22b062cdea0ccb6210a3f7305","u","w256",235),
   ("verify_sp1_groth16_sha256","d8878f35afadf6010d8e31026b5c9742ec938944cdd9e6c2d66fde33ca8b5434","ecx_pw256w256","b",842045435),
   ("verify_sp1_groth16_v3_public_values_v4_sha256","a52e069cf9c1f1da6f3fe0c23f893da4f59414dcec0e34933f05875df8f9b5b1","ecx_pw256w256","b",820469462),
   ("verify_sp1_groth16_v4_public_values_v5_sha256","fb2aa82d0500811fe750890f1441d8051b7d09c62365b58b7619d699c4b6b624","ecx_pw256w256","b",826626612),
   ("prior_active_bond_inbox_root_required","e0f49da0a834f48fbdee7dfd0ff96f56675a0f169ac15cf05989c3a35ff10f82","u","w256",233),
   ("prior_active_bond_inbox_count_required","72679a3ed747c29e4aa870ee5c84dfd796c3a342381d3c4b08d6ab4de57bbab9","u","w64",190),
   ("current_sidechain_height_required","242a810a64938eea9859b32e31de786d7709c0f1fc2e7c235864666376f77842","u","w64",191),
   ("bond_v2_insurance_reserve_input_required","d48d4edfcb17128c2f5da919d7dc5727108930a286a8acde763038a55e12d1ce","w32","u",200),
   ("bond_v2_collateral_vault_input_required","377f24584cc215e88771bbaeda66046cf481297037f6ab805817559261b3849c","w32","u",195),
   ("bond_v2_incremental_activation_cmr_required","547b5f517d8cdef8a52db33f35334314cfa0a5e3f8c1d2478dcb93ac96b2544d","u","w256",232),
   ("incremental_successor_transition_cmr_required","42003f28531aeff33225abff84d2ea93393d43a7ae9bd9b9f12cac7989c23e5e","u","w256",231),
   ("verify_sp1_groth16_v5_incremental_activation_sha256","b9de62090d0b268734a7a7b3b361f70d14aabb040885713262b6c3a4a2190832","ecx_pw256w256","b",825247407)]

privateJetHeader :: String
privateJetHeader = unlines $ "/* Test-only operator-risk ECX catalogue; specification fingerprints only. */" :
  concat [jetRecord ("ECX_" ++ map toUpper name,name,digest,source,target,cost)
    "milli weight units; nonactivating operator catalogue" |
    (name,digest,source,target,cost) <- privateJetPins]

depositAddressLimit :: Word32
depositAddressLimit = 128

ownedAnnexLimit :: Word32
ownedAnnexLimit = 1310720

groth16ProofLength, publicValuesV4Length, publicValuesV5Length, activationValuesLength, successorValuesLength, swapSuccessorValuesLength, custodySuccessorValuesLength :: Int
groth16ProofLength = 356
publicValuesV4Length = 609
publicValuesV5Length = 850
activationValuesLength = 364
successorValuesLength = 1627
swapSuccessorValuesLength = 1693
custodySuccessorValuesLength = 791

simplicityLengths :: [(String, Int)]
simplicityLengths =
  [("ECX_SP1_GROTH16_PROOF_LEN",groth16ProofLength),
   ("ECX_SP1_PUBLIC_VALUES_V4_LEN",publicValuesV4Length),
   ("ECX_SP1_PUBLIC_VALUES_V5_LEN",publicValuesV5Length),
   ("ECX_SP1_INCREMENTAL_ACTIVATION_PUBLIC_VALUES_LEN",activationValuesLength),
   ("ECX_SP1_INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_LEN",successorValuesLength),
   ("ECX_SP1_SWAP_SUCCESSOR_PUBLIC_VALUES_LEN",swapSuccessorValuesLength),
   ("ECX_SP1_CUSTODY_SUCCESSOR_PUBLIC_VALUES_LEN",custodySuccessorValuesLength)]

simplicityHeader :: String
simplicityHeader = unlines $
  ["/* Generated from BmmConstants.simplicityHeader; do not edit. */",
   "#ifndef SIMPLICITY_ELEMENTS_POLICY_CONSTANTS_H", "#define SIMPLICITY_ELEMENTS_POLICY_CONSTANTS_H",
   "#include <stddef.h>",
   "/* V4 is historical/test-only; V5 is frozen bond-V2; activation and successor are incremental. */"] ++
  ["#define " ++ name ++ " ((size_t)" ++ show size ++ ")" | (name,size) <- simplicityLengths] ++
  ["#define SIMPLICITY_ELEMENTS_MAX_OWNED_ANNEX_SIZE (" ++ show ownedAnnexLimit ++ "U)","#endif"]

depositMarker, legacyDepositMarker :: String
depositMarker = "drivechain-deposit-v2"
legacyDepositMarker = "drivechain-deposit-v1"

depositLayouts :: [(String,[Word8])]
depositLayouts =
  [("LEGACY_DEPOSIT_LAYOUT",[0,1,2,3,255,4]),
   ("NATIVE_DEPOSIT_LAYOUT",[0,1,2,3,254,4,5,6]),
   ("EVIDENCE_DEPOSIT_LAYOUT",[0,1,2,3,254,4,5,6,7,8,9])]

jetCostHeader :: String
jetCostHeader = unlines
  ["/* Generated from BmmConstants.jetCostHeader; do not edit. */",
   "#ifndef SIMPLICITY_ELEMENTS_PRIMITIVE_JET_COST_INC",
   "#define SIMPLICITY_ELEMENTS_PRIMITIVE_JET_COST_INC",
   "#define SIMPLICITY_VERIFY_SP1_COMPRESSED_SHA256_COST_MWU " ++ show compressedSp1Cost ++ "u",
   "#endif /* SIMPLICITY_ELEMENTS_PRIMITIVE_JET_COST_INC */"]

-- Frozen V7 resource schedule; changing these defines a different network.
resourceConstants :: [(String, Word32)]
resourceConstants =
  [("CONSENSUS_MAX_BLOCK_SERIALIZED_SIZE",6000000),("CONSENSUS_MAX_BLOCK_WEIGHT",6000000),
   ("USDD_SP1_ANNEXES_PER_BLOCK",1),("USDD_SP1_PROOF_TX_MAX_WEIGHT",1500000),
   ("USDD_SP1_ANNEX_MAX_BYTES",ownedAnnexLimit),("USDD_SP1_PUBLIC_VALUES_MAX_BYTES",16384),
   ("USDD_SP1_MEASURED_RAW_PROOF_BYTES",1272546),("USDD_SP1_MEASURED_PUBLIC_VALUES_BYTES",1001),
   ("USDD_SP1_MEASURED_ANNEX_BYTES",1273602),("USDD_SP1_MEASURED_ANNEX_WEIGHT",1273607),
   ("USDD_SP1_MAX_ANNEX_WEIGHT",1310725),("USDD_SP1_MAX_NON_ANNEX_TX_WEIGHT",189275),
   ("MAX_DRIVECHAIN_DEPOSITS_PER_BLOCK",64)]

activationBudget :: Int64
activationBudget = 1002636

standardScriptVerifyFlags :: Word32
standardScriptVerifyFlags = 134217728 -- Native SCRIPT_VERIFY_USDD_SP1_ANNEX ABI bit.

activationCmr :: [Word8]
activationCmr =
  [0xd9,0xef,0x88,0xa9,0x38,0x9f,0x87,0x11,0x4f,0x62,0x53,0x9d,0x7e,0x0e,0x2d,0x07,
   0x0f,0xed,0x1a,0x4e,0xa9,0x0f,0xda,0xa7,0xc2,0x06,0xac,0x14,0x0e,0xcf,0x2e,0x87]

-- Included within namespace ecx; frozen credit applies only to this exact CMR.
activationHeader :: String
activationHeader = unlines
  ["// Generated from BmmConstants.hs; do not edit.",
   "static constexpr int64_t ACTIVATION_EXECUTION_BUDGET_WU{" ++ show activationBudget ++ "};",
   "static constexpr std::array<unsigned char,32> ACTIVATION_BUDGET_CMR{{" ++
     intercalate "," (map show activationCmr) ++ "}};"]

resourceHeader :: String
resourceHeader = unlines $ ["// Generated from BmmConstants.resourceHeader; do not edit.",
  "#ifndef ELEMENTS_HASKELL_RESOURCE_CONSTANTS_H", "#define ELEMENTS_HASKELL_RESOURCE_CONSTANTS_H",
  "#include <cstdint>", "namespace ElementsDrivechainIdentity {"] ++
  ["inline constexpr uint32_t " ++ name ++ "{" ++ show value ++ "U};" | (name,value) <- resourceConstants] ++
  ["inline constexpr int ALPHA_PEGIN_ONE_CONFIRMATION_HEIGHT{" ++ show alphaPeginOneConfirmationHeight ++ "};",
   "inline constexpr uint32_t DEPOSIT_ADDRESS_LIMIT{" ++ show depositAddressLimit ++ "U};",
   "inline constexpr uint32_t STANDARD_SCRIPT_VERIFY_FLAGS{" ++ show standardScriptVerifyFlags ++ "U};"] ++
  ["inline constexpr unsigned char " ++ name ++ "[]{" ++ intercalate "," (map (show . ord) marker) ++ "};"
    | (name,marker) <- [("DEPOSIT_MARKER",depositMarker),("LEGACY_DEPOSIT_MARKER",legacyDepositMarker)]] ++
  ["inline constexpr unsigned char " ++ name ++ "[]{" ++ intercalate "," (map show layout) ++ "};"
    | (name,layout) <- depositLayouts] ++
  ["}","#endif"]

schemaVersion, sidechainSlot, proofEntries, proofBytes, targetTimespan, targetSpacing, requireSignet :: Word64
schemaVersion = 1
sidechainSlot = 24
proofEntries = 128
proofBytes = 1000000
targetTimespan = 1209600
targetSpacing = 600
requireSignet = 1

anchorVersion, pegEventVersion :: Word64
anchorVersion = 1
pegEventVersion = 1

checkpointHeaderLimit, checkpointEntryLimit, checkpointByteLimit, pegEventDefaultCount, pegEventCountLimit :: Word64
checkpointHeaderLimit = 10000
checkpointEntryLimit = 100000
checkpointByteLimit = 64 * 1024 * 1024
pegEventDefaultCount = 1000
pegEventCountLimit = 10000

bondExportDefaultBlocks, bondExportBlockLimit, bondExportEntryLimit :: Word64
bondExportDefaultBlocks = 1
bondExportBlockLimit = 64
bondExportEntryLimit = 8

withdrawalReadConfirmations, withdrawalSubmitConfirmations, withdrawalProofSeconds, withdrawalProofInterruptInterval :: Word64
withdrawalReadConfirmations = 1
withdrawalSubmitConfirmations = 6
withdrawalProofSeconds = 10
withdrawalProofInterruptInterval = 4096

grpcEndpoint :: String
grpcEndpoint = "127.0.0.1:55051"

productionChainName, configFilename :: String
productionChainName = "elements"
configFilename = "elements.conf"

-- Historical deposit verification pins; never alias mutable network defaults.
historicalDepositSlot :: Word32
historicalDepositSlot = 24

historicalDepositDefaults :: [(String,String)]
historicalDepositDefaults =
  [("SIDECHAIN_NETWORK","liquid-signet"),("MAINCHAIN_NETWORK","signet"),
   ("SIGNET_CHALLENGE","00148835832e28c816b7acd8fdb19772ab2199603a56"),
   ("ENFORCER_NETWORK","NETWORK_SIGNET"),("TITLE","Elements"),
   ("HASH_ID_1","5883560531f013b9b27b2f9cfbac4f64ee5062b95ad3e21593a8f6916530b74b"),
   ("HASH_ID_2","b2b7b20f3fbc4baf50e9d39f58661c6168e279d4")]

networkDefaultsHeader :: String
networkDefaultsHeader = unlines $
  ["// Generated from BmmConstants.hs; do not edit.", "#pragma once",
   "#include <util/chaintype.h>", "namespace drivechain {",
   "inline constexpr ChainType DEFAULT_CHAIN{ChainType::ELEMENTS};",
   "inline constexpr char PRODUCTION_CHAIN_NAME[]{" ++ show productionChainName ++ "};",
   "inline constexpr char CONFIG_FILENAME[]{" ++ show configFilename ++ "};",
   "inline constexpr int HISTORICAL_DEPOSIT_SLOT{" ++ show historicalDepositSlot ++ "};"] ++
  ["inline constexpr char HISTORICAL_DEPOSIT_" ++ name ++ "[]{" ++ show value ++ "};" |
    (name,value) <- historicalDepositDefaults] ++ ["}"]

journalFilename, journalMagic :: String
journalFilename = "drivechain_withdrawal.dat"
journalMagic = "ELEMENTS_DRIVECHAIN_WITHDRAWAL_JOURNAL_V1"

journalHeader :: String
journalHeader = unlines
  ["// Generated from BmmConstants.hs; do not edit.", "#pragma once",
   "namespace drivechain {",
   "inline constexpr char WITHDRAWAL_JOURNAL_FILENAME[]{" ++ show journalFilename ++ "};",
   "inline constexpr char WITHDRAWAL_JOURNAL_MAGIC[]{" ++ show journalMagic ++ "};", "}"]

grpcCredentialDefaults :: [(String, String)]
grpcCredentialDefaults =
  [("GRPC_CA_FILE","enforcer-tls/ca.pem"),
   ("GRPC_CLIENT_CERT_FILE","enforcer-tls/elements-client.pem"),
   ("GRPC_CLIENT_KEY_FILE","enforcer-tls/elements-client-key.pem")]

rpcSecurityHeader :: String
rpcSecurityHeader = unlines $ ["// Generated from BmmConstants.hs; do not edit.",
  "#pragma once", "namespace drivechain {"] ++
  ["inline constexpr char " ++ name ++ "[]{" ++ show path ++ "};" | (name,path) <- grpcCredentialDefaults] ++ ["}"]

pegoutMainFee :: Word64
pegoutMainFee = 10000

defaultBmmBid, defaultBmmWorkPrice, defaultBmmProducerReserve :: Word64
defaultBmmBid = 1000
defaultBmmWorkPrice = 1000
defaultBmmProducerReserve = 0

bmmEdgeCacheSize, bmmNegativeCacheSize, bmmNegativeCacheSeconds :: Word64
bmmEdgeCacheSize = 8
bmmNegativeCacheSize = 64
bmmNegativeCacheSeconds = 5

peerBlockTimeoutSeconds, peerRejectedBackoffSeconds, peerUnavailableBackoffSeconds, peerRejectedStrikes :: Word64
peerBlockTimeoutSeconds = 30
peerRejectedBackoffSeconds = 30
peerUnavailableBackoffSeconds = 5
peerRejectedStrikes = 2

forcedInclusionBlocks, maxCombinedUnconsumed, maxCombinedAppends, maxPendingWitnessEntries, maxTrancheWork :: Word64
forcedInclusionBlocks = 6
maxCombinedUnconsumed = 64
maxCombinedAppends = 64
maxPendingWitnessEntries = 448
maxTrancheWork = 64

withdrawalDestinationSize, withdrawalReferenceSize, withdrawalLegacySize :: Word64
withdrawalDestinationSize = 128
withdrawalReferenceSize = 74
-- Version, zero vin, three outputs (including a 128-byte payout), and locktime.
withdrawalLegacySize = 251

fingerprintTag :: String
fingerprintTag = "ECX/BMM-runtime-consensus/v4"

parentHashHexLength :: Word64
parentHashHexLength = 64

parentRecoverySeconds :: Int64
parentRecoverySeconds = 30

replayIdentityDomain :: String
replayIdentityDomain = "ELEMENTS_AUTHENTICATED_PARENT_REPLAY_STORE_V4"

replayDirectory :: String
replayDirectory = "parent-replay"

ctipHash, ctipMarker :: String
ctipHash = "2d15ce4b128995291c4e38d36b8ae411a15bf80d7acee97cf5f58d2fc4de52b1"
ctipMarker = "drivechain-ctip-v1"

withdrawalStatuses :: [String]
withdrawalStatuses = map fst withdrawalLifecycle

capitalModes, oracleModes :: [String]
capitalModes = ["Normal","ReduceOnly","Recovery"]
oracleModes = ["Normal","ReduceOnly","Disputed","Halt"]

withdrawalLifecycle :: [(String, String)]
withdrawalLifecycle = [("submitted", "pending"), ("succeeded", "accepted"), ("failed", "rejected")]

consensusDefaults :: [Word64]
consensusDefaults = [targetTimespan,targetSpacing,sidechainSlot,proofEntries,proofBytes]

replayConstants :: [(String, String, Word64)]
replayConstants =
  [("uint32_t","REPLAY_UNIQUE_SCHEMA",4),("uint32_t","REPLAY_REPROPOSAL_SCHEMA",5),
   ("size_t","DRIVECHAIN_PARENT_REPLAY_DB_CACHE_BYTES",4194304),
   ("uint8_t","REPLAY_DEFAULT_HISTORY_RULE",0),
   ("bool","REPLAY_DB_MEMORY_ONLY",0),("bool","REPLAY_DB_OBFUSCATE",0),
   ("bool","REPLAY_DB_SYNC",1),("bool","REPLAY_RESET_WIPE",1)] ++
  [("uint8_t","DB_REPLAY_" ++ name,fromIntegral (ord tag)) |
    (name,tag) <- [("IDENTITY",'I'),("TIP",'T'),("DEPOSIT",'d'),("BMM_EDGE",'e'),
      ("SUCCESSFUL_WITHDRAWAL",'w'),("WITHDRAWAL_OCCURRENCE",'W')]] ++
  [("int","REPLAY_LOAD_" ++ name,value) | (name,value) <- zip
    ["EMPTY","LOADED","CORRUPT","IDENTITY_MISMATCH"] [0..]] ++
  [("int","REPLAY_READ_" ++ name,value) | (name,value) <- zip
    ["FOUND","NOT_FOUND","CORRUPT"] [0..]] ++
  [("int64_t","LOCKED_PARENT_DEADLINE_SECONDS",2),
   ("int64_t","ANCHOR_WARM_DEADLINE_SECONDS",120),
   ("size_t","MAX_ECX_DEPLOYMENT_IDENTITY_BYTES",1024),
   ("uint32_t","LOCKED_MAX_REPLAY_STEPS",2),("int64_t","PARENT_RPC_BACKOFF_SECONDS",5),
   ("size_t","MAX_MAINCHAIN_RPC_RESPONSE_SIZE",16777216),("size_t","MAX_MAINCHAIN_RPC_HEADER_SIZE",65536),
   ("int64_t","AUTHENTICATED_GRPC_TIMEOUT_SECONDS",30),("size_t","MAX_AUTHENTICATED_GRPC_RESPONSE_SIZE",16777216)]

parentMessageTags :: [(String, [Int])]
parentMessageTags = [("PARENT_M1_TAG",[0xd5,0xe0,0xc4,0xaf]),("PARENT_M2_TAG",[0xd6,0xe1,0xc5,0xdf])]

data Lifecycle = BudgetEnter | BudgetExit | AdmissionEnter | AdmissionExit | BundleReserve | BundleAbort
  deriving (Eq, Show, Enum, Bounded)

-- Cleanup uses generated plans rather than allocating runtime FFI dispatch.
lifecyclePlan :: Lifecycle -> Bool -> Bool -> [Int]
lifecyclePlan BundleReserve acquired busy = [if acquired then 1 else if busy then 2 else 3]
lifecyclePlan _ False _ = []
lifecyclePlan BudgetEnter True boundary = if boundary then [1..8] else [1]
lifecyclePlan BudgetExit True boundary = if boundary then [1..7] else [1,2]
lifecyclePlan AdmissionEnter True _ = [1]
lifecyclePlan AdmissionExit True _ = [1,2]
lifecyclePlan BundleAbort True _ = [1]

-- Factory indices: deposits [historical,native], withdrawals [historical,PAK,native].
walletRpcRoute :: Bool -> Bool -> Bool -> Word8
walletRpcRoute withdrawal native pak
  | native = if withdrawal then 2 else 1
  | withdrawal && pak = 1
  | otherwise = 0

walletRpcHeader :: String
walletRpcHeader = unlines
  ["// Generated from BmmConstants.walletRpcHeader; do not edit.",
   "#pragma once", "#include <array>", "#include <cstdint>",
   "namespace drivechain {",
   "inline constexpr std::array<std::array<uint8_t, 4>, 2> WALLET_RPC_ROUTES{{" ++
     intercalate "," ["{{" ++ intercalate "," [show (walletRpcRoute withdrawal native pak) |
       native <- [False,True], pak <- [False,True]] ++ "}}" | withdrawal <- [False,True]] ++ "}};",
   "}"]

lifecycleHeaders :: [String]
lifecycleHeaders =
  ["static constexpr std::array<std::array<uint8_t, 8>, 4> " ++ name ++ "{{" ++
    intercalate "," ["{{" ++ intercalate "," (map show (take 8 (lifecyclePlan kind enabled boundary ++ repeat 0))) ++ "}}" |
      enabled <- [False,True], boundary <- [False,True]] ++ "}};" |
    (kind,name) <- zip [minBound..maxBound]
      ["PARENT_BUDGET_ENTER_ACTIONS","PARENT_BUDGET_EXIT_ACTIONS",
       "PARENT_ADMISSION_ENTER_ACTIONS","PARENT_ADMISSION_EXIT_ACTIONS",
       "WITHDRAWAL_BUNDLE_RESERVE_ACTIONS","WITHDRAWAL_BUNDLE_ABORT_ACTIONS"]]

-- Compile-time native declarations preserve aggregate initialization without RTS calls.
type BootstrapSlot = (Word8, String, String, Word32, Int64)

bootstrapCatalogs :: [(Word32, String, [BootstrapSlot])]
bootstrapCatalogs =
  [(4, "ALPHA_SLOTS",
    [empty 2 "44923e8adf714f49838fa096a59d3913811b8af07cca03b82843b76fe9ca6cd9",
     empty 4 "e5cfe12a22ff7245baf797dc7e966033afeaddd7dfe5a8379e37a8751fa55a2a",
     (9,"61375db9dc0fe8c2b3aabdadcd7a5ea542ca9162cc8c89992bb3e6c5869ce039",
        "57dd0496215533d258e6c08119f3952ce12c3f804523e307d4de983eccc991a0",0,302000000),
     empty 13 "76b3820beb056fe6674013ed4eddd9e074bb2621107ecab886eebd0a175c4f17",
     empty 98 "2fb3d32db5bf9f82624a07313ed09713fd271f06f3276034830dba0131280c8c",
     empty 99 "d9825e315ab563c70f38496d0867ecde37a9791b746d47fcec5290a8eda05597",
     empty 255 "3459ab323378afbc87c8719f5807448a79849c481c5a23930a9aa8c93ef5d144"]),
   (emptyBootstrapVersion, "", [])]
  where empty slot active = (slot,active,replicate 64 '0',maxBound,0)

betanetReplayVersion, emptyBootstrapVersion, emptyBootstrapHeight :: Word32
betanetReplayVersion = 5
emptyBootstrapVersion = betanetReplayVersion
emptyBootstrapHeight = 967679

bootstrapSlots :: Word32 -> Maybe [BootstrapSlot]
bootstrapSlots version = lookup version [(v,slots) | (v,_,slots) <- bootstrapCatalogs]

-- Included within the native Slot namespace, without runtime initialization.
bootstrapHeader :: String
bootstrapHeader = unlines $
  ["// Generated from BmmConstants.hs; do not edit.", "inline constexpr bool ENABLED{true};"] ++
  ["inline constexpr std::array<Slot, " ++ show (length slots) ++ "> " ++ name ++ "{{" ++
   intercalate "," ["Slot{" ++ intercalate "," [show slot,show active,show txid,show vout,show value] ++ "}" |
     (slot,active,txid,vout,value) <- slots] ++ "}};" | (_,name,slots) <- bootstrapCatalogs, not (null slots)] ++
  ["constexpr std::optional<std::span<const Slot>> SlotsForReplayVersion(uint32_t version) {",
   "switch (version) {"] ++
  ["case " ++ show version ++ ": return std::span<const Slot>{" ++ name ++ "};" |
    (version,name,_) <- bootstrapCatalogs] ++
  ["default: return std::nullopt;", "}", "}",
   "static_assert(SlotsForReplayVersion(ElementsDrivechainIdentity::PARENT_REPLAY_VERSION).has_value());",
   "static_assert(ElementsDrivechainIdentity::PARENT_REPLAY_VERSION != " ++ show emptyBootstrapVersion ++ " ||",
   "ElementsDrivechainIdentity::PARENT_CHECKPOINT_HEIGHT == " ++ show emptyBootstrapHeight ++ ",",
   "\"Empty Betanet bootstrap is valid only immediately before BIP300 activation\");",
   "inline constexpr auto SLOTS = *SlotsForReplayVersion(ElementsDrivechainIdentity::PARENT_REPLAY_VERSION);"]

-- Enum names are native type adapters; text is frozen protocol metadata.
parentRuleCatalog :: [(Word32, [String], [String])]
parentRuleCatalog =
  [(4, ["TreasuryOpcode::NOP5", "DrivechainM6ReplayRule::SINGLE_CONFIGURED_SLOT_M6", "DrivechainWithdrawalHistoryRule::UNIQUE_M6ID"],
    ["ELEMENTS_ALPHANET_PARENT_REPLAY_BOOTSTRAP_V1", "ELEMENTS_SLOT24_SINGLE_M6_PER_PARENT_BLOCK_V1",
     "Elements Drivechain v11; parameterized controller profile; replay v4; annex v2; one M6 per parent block; withdrawal accumulator v1; BIP301 checkpoint v1; Simplicity active; slot 24"]),
   (betanetReplayVersion, ["TreasuryOpcode::NOP8", "DrivechainM6ReplayRule::SEQUENTIAL_M6", "DrivechainWithdrawalHistoryRule::ALLOW_REPROPOSAL"],
    ["ELEMENTS_BETANET_PARENT_REPLAY_BOOTSTRAP_V1", "ELEMENTS_SLOT24_SEQUENTIAL_M6_REPROPOSAL_V1",
     "Elements Drivechain Betanet v1; parameterized controller profile; replay v5; annex v2; sequential M6; withdrawal accumulator v1; BIP301 checkpoint v1; Simplicity active; slot 24"])]

-- Included after ParentRules is defined, within namespace drivechain.
parentRulesHeader :: String
parentRulesHeader = unlines $
  ["// Generated from BmmConstants.hs; do not edit.",
   "static_assert(!ElementsDrivechainIdentity::BETANET_EXISTING_ELEMENTS_TEST_PROFILE ||",
   "(ElementsDrivechainIdentity::PARENT_REPLAY_VERSION == " ++ show betanetReplayVersion ++ " &&",
   "ElementsDrivechainIdentity::SIDECHAIN_SLOT == " ++ show sidechainSlot ++ "),",
   "\"Elements test profile requires Betanet replay and slot 24\");",
   "constexpr std::optional<ParentRules> ParentRulesForVersion(uint32_t version) {",
   "switch (version) {"] ++
  ["case " ++ show version ++ ": return ParentRules{" ++ intercalate "," (enums ++ map show texts) ++ "};" |
    (version,enums,texts) <- parentRuleCatalog] ++
  ["default: return std::nullopt;", "}", "}",
   "constexpr bool SupportedParentReplayRules(TreasuryOpcode treasury, DrivechainM6ReplayRule m6) {",
   "return " ++ allowed "treasury" [t | (_,t:_:_,_) <- parentRuleCatalog] ++ " && " ++
     allowed "m6" [m | (_,_:m:_,_) <- parentRuleCatalog] ++ ";", "}",
   "static_assert(ParentRulesForVersion(ElementsDrivechainIdentity::PARENT_REPLAY_VERSION).has_value(),",
   "\"Frozen identity selects unsupported parent replay rules\");",
   "inline constexpr ParentRules FROZEN_PARENT_RULES = *ParentRulesForVersion(ElementsDrivechainIdentity::PARENT_REPLAY_VERSION);",
   "static_assert(FROZEN_PARENT_RULES.local_rule_domain == ElementsDrivechainIdentity::BIP300301_LOCAL_RULE_DOMAIN,",
   "\"Frozen identity local rule domain disagrees with replay version\");",
   "static_assert(ElementsDrivechainIdentity::PARENT_REPLAY_VERSION != " ++ show betanetReplayVersion ++ " ||",
   "ElementsDrivechainIdentity::SIDECHAIN_SLOT == " ++ show sidechainSlot ++ ",",
   "\"Betanet frozen identity must select sidechain slot 24\");"]
  where allowed field choices = "(" ++ intercalate " || " [field ++ " == " ++ choice | choice <- nub choices] ++ ")"

-- BIP341 NUMS point H, followed by the frozen V18 staging-renderer domain.
-- Native comparisons remain compile-time data and cannot reenter the RTS.
exchangeIdentities :: [(String, [Word8])]
exchangeIdentities =
  [("ECX_BIP341_NUMS_XONLY",
    [0x50,0x92,0x9b,0x74,0xc1,0xa0,0x49,0x54,0xb7,0x8b,0x4b,0x60,0x35,0xe9,0x7a,0x5e,
     0x07,0x8a,0x5a,0x0f,0x28,0xec,0x96,0xd5,0x47,0xbf,0xee,0x9a,0xce,0x80,0x3a,0xc0]),
   ("ECX_BOND_STAGING_RENDERER_DOMAIN_V18",
    [0xd8,0xca,0x78,0x83,0x76,0x9d,0xd7,0x38,0x30,0x98,0x7f,0x72,0x7a,0x34,0x93,0x9d,
     0x2d,0x9b,0x69,0xa3,0xe7,0x83,0xe0,0xa2,0xe1,0xcc,0xa3,0x5f,0xa4,0x87,0x2e,0x6f])]

exchangeScriptCacheRevision :: Word64
exchangeScriptCacheRevision = 14

exchangeInterfaceConstants :: [(String,String,Word64)]
exchangeInterfaceConstants =
  [("uint8_t","EXCHANGE_STATE_INTERFACE_VERSION",1),
   ("uint16_t","EXCHANGE_SCRIPT_CACHE_REVISION",exchangeScriptCacheRevision),
   ("uint32_t","ECX_CONSENSUS_RULESET_REVISION",8),
   ("uint32_t","DEFAULT_BOND_DEPLOYMENT_VERSION",2),
   ("int","DISABLED_EXCHANGE_ACTIVATION_HEIGHT",2147483647),
   ("bool","BOND_V2_PARTITIONED_INCREMENTAL_RECOVERY_BOUND_PROVEN",1)]

bondFixedSupply :: Word64
bondFixedSupply = 2100000000000000

forcedBodySizes :: [Int]
forcedBodySizes = [201,208,193]

depositPayloadSize :: Int
depositPayloadSize = 73

bondRequiredArguments, bondGroupedArguments, bondHashArguments :: [String]
bondRequiredArguments = map ("-ecxbondv2" ++) [
  "deploymentversion", "deploymenttx", "genesistx", "issuanceinput", "inventoryoutput",
  "burnoutput", "stateauthoritysourceoutput", "inventoryassetblinder", "inventoryvalueblinder",
  "issuancevalueblinder", "transitionprogramid", "configurationhash", "configurationbytes",
  "publicstatedomain", "statenodedomain", "journaldomain", "transitioncmr",
  "incrementalactivationprogramid", "incrementalactivationconfigurationhash", "incrementalactivationcmr",
  "incrementalsuccessorprogramid", "incrementalsuccessorconfigurationhash", "incrementalsuccessortransitioncmr",
  "incrementalsuccessorstatenodedomain", "inventorycmr", "queuecmr", "ecxbtcprogramid",
  "ecxbtcredemptioncovenant", "ecxbtcsourcecheckpoint", "usddusdprogramid", "usddusdredemptioncovenant",
  "usddusdsourcecheckpoint", "matcherreceipt", "orderreceiptsroot", "availabilityroot", "custodianregistry"]
bondGroupedArguments = map ("-ecxbondv2" ++) ["usddasset", "keylessinternalkey", "genesismarkprice"]
bondHashArguments = map ("-ecxbondv2" ++) [
  "publicstatedomain", "statenodedomain", "journaldomain", "transitioncmr",
  "incrementalactivationprogramid", "incrementalactivationconfigurationhash", "incrementalactivationcmr",
  "incrementalsuccessorprogramid", "incrementalsuccessorconfigurationhash", "incrementalsuccessortransitioncmr",
  "incrementalsuccessorstatenodedomain", "inventorycmr", "queuecmr", "ecxbtcprogramid",
  "ecxbtcredemptioncovenant", "ecxbtcsourcecheckpoint", "usddusdprogramid",
  "usddusdredemptioncovenant", "usddusdsourcecheckpoint", "matcherreceipt", "orderreceiptsroot", "availabilityroot"]

bondInboxTag :: Bool -> String -> String
bondInboxTag successor name =
  (if successor then "ECX/successor-bond-inbox-" else "ECX/bond-inbox-") ++ name ++
  (if successor then "/v2-u128" else "/v2")

bondInboxDomains :: [(String,[String])]
bondInboxDomains = [("ECX_BOND_" ++ name ++ "_TAGS", map (`bondInboxTag` suffix) [False,True]) |
  (name,suffix) <- [("CONTEXT","availability-context"),("SIGNATURE","marker-signature"),
    ("BUNDLE","encrypted-availability-bundle"),("STAGING_AUTH","staging-source-authorization"),
    ("NO_STAGING_AUTH","no-staging-source-authorization"),("ENTRY","entry"),("STEP","step")]]

bondInboxCustodyDomains :: [[String]]
bondInboxCustodyDomains =
  [[bondInboxTag successor name | name <- ["custody-receipt-binding","exact-custody-receipt"]] ++
   [bondInboxTag successor "custody-receipts" ++ suffix | suffix <- ["/empty","/leaf","/pad","/node"]] |
   successor <- [False,True]]

exchangeTrackerHeader :: String
exchangeTrackerHeader = unlines $
  ["const COutPoint " ++ name ++ "{Txid::FromUint256(uint256S(" ++ show hash ++ ")),0};" |
    (name,hash) <-
      [("EXCHANGE_TRACKER_OUTPOINT","e31f7fb1e9489bfb9f6a73c10f80ecdcce1f276fbdf0cf85c02e3bcf174dc041"),
       ("FORCED_INBOX_TRACKER_OUTPOINT","c3fd019db845c81a68a561f5ab67d92c3ab2505cb2c8212f02511e07e8c2f2a1"),
       ("DEPOSIT_INBOX_TRACKER_OUTPOINT","0cc4c302121a9d75c8a0e520253c1740520a6d6f4d03db6947a99565175d6586")]] ++
  ["const std::vector<unsigned char> " ++ name ++ "{" ++ bytes value ++ "};" |
    (name,value) <- [("EXCHANGE_TRACKER_MARKER","ecx-state-v1"),
      ("FORCED_INBOX_TRACKER_MARKER","ecx-forced-v1"),("DEPOSIT_INBOX_TRACKER_MARKER","ecx-deposit-v1")]] ++
  ["constexpr std::array<unsigned char," ++ show (length value) ++ "> " ++ name ++ "{{" ++ bytes value ++ "}};" |
    (name,value) <- [("FORCED_MAGIC","ECXF"),("DEPOSIT_MAGIC","ECXD"),("ECX_USDD_MARKET","ECX-USDD-PERP\0\0\0")]]
  where bytes = intercalate "," . map (show . ord)

exchangeHeader :: String
exchangeHeader
  | any ((/=32) . length . snd) exchangeIdentities = error "invalid exchange identity width"
  | length forcedBodySizes /= 3 = error "invalid forced body size catalog"
  | otherwise = unlines $ "// Generated from BmmConstants.hs; do not edit." :
      ("namespace {\n" ++ exchangeTrackerHeader ++ "}\n") :
      ["constexpr std::array<unsigned char, 32> " ++ name ++ "{{" ++
       intercalate "," (map show bytes) ++ "}};" | (name,bytes) <- exchangeIdentities] ++
      ["constexpr size_t " ++ name ++ "{" ++ show size ++ "};" |
        (name,size) <- zip ["FORCED_CANCEL_BODY_SIZE","FORCED_LIMIT_BODY_SIZE","FORCED_WITHDRAW_BODY_SIZE"] forcedBodySizes ++
          [("DEPOSIT_PAYLOAD_SIZE",depositPayloadSize)]] ++
      ["constexpr int64_t ECX_BOND_FIXED_SUPPLY{" ++ show bondFixedSupply ++ "};",
       "constexpr const char* ECX_BOND_ARGUMENTS[]{" ++ intercalate "," (map show (bondRequiredArguments ++ bondGroupedArguments)) ++ "};",
       "constexpr std::array<const char*," ++ show (length bondHashArguments) ++ "> ECX_BOND_HASH_ARGUMENTS{{" ++
       intercalate "," (map show bondHashArguments) ++ "}};"] ++
      ["constexpr std::array<const char*,2> " ++ name ++ "{{" ++ intercalate "," (map show tags) ++ "}};" |
       (name,tags) <- bondInboxDomains] ++
      ["constexpr std::array<std::array<const char*,6>,2> ECX_BOND_CUSTODY_TAGS{{" ++
       intercalate "," ["{{" ++ intercalate "," (map show tags) ++ "}}" | tags <- bondInboxCustodyDomains] ++ "}};"]

withdrawalHeaderBit :: Int
withdrawalHeaderBit = 30

-- This bit has meaning only in the separately selected fresh swap wire mode.
swapForcedHeaderBit :: Int
swapForcedHeaderBit = 14

headerExtensionBits :: [Int]
headerExtensionBits = [20,19..16]

header :: String
header = unlines $ ["// Generated from BmmConstants.hs; do not edit.",
  "#ifndef ELEMENTS_HASKELL_BMM_CONSTANTS_H", "#define ELEMENTS_HASKELL_BMM_CONSTANTS_H",
  "#include <cstdint>", "#include <cstddef>", "#include <array>", "namespace drivechain {"] ++
  ["static constexpr " ++ ty ++ " " ++ name ++ "{" ++ show value ++ "};" |
    (ty,name,value) <- [("uint8_t","BMM_PROOF_SCHEMA_VERSION",schemaVersion),
      ("uint8_t","DRIVECHAIN_ANCHOR_VERSION",anchorVersion),
      ("int","PEG_EVENT_SCHEMA_VERSION",pegEventVersion),
      ("int","PEG_EVENT_DEFAULT_COUNT",pegEventDefaultCount),
      ("int","PEG_EVENT_COUNT_LIMIT",pegEventCountLimit),
      ("int","BOND_EXPORT_DEFAULT_BLOCKS",bondExportDefaultBlocks),
      ("int","BOND_EXPORT_BLOCK_LIMIT",bondExportBlockLimit),
      ("uint32_t","BOND_EXPORT_ENTRY_LIMIT",bondExportEntryLimit),
      ("uint32_t","CHECKPOINT_HEADER_LIMIT",checkpointHeaderLimit),
      ("uint32_t","CHECKPOINT_ENTRY_LIMIT",checkpointEntryLimit),
      ("uint32_t","CHECKPOINT_BYTE_LIMIT",checkpointByteLimit),
      ("int","WITHDRAWAL_READ_CONFIRMATIONS",withdrawalReadConfirmations),
      ("int","WITHDRAWAL_SUBMIT_CONFIRMATIONS",withdrawalSubmitConfirmations),
      ("int","WITHDRAWAL_PROOF_SECONDS",withdrawalProofSeconds),
      ("int","WITHDRAWAL_PROOF_INTERRUPT_INTERVAL",withdrawalProofInterruptInterval),
      ("int","BMM_SIDECHAIN_SLOT",sidechainSlot),
      ("int","DRIVECHAIN_SIDECHAIN_SLOT",sidechainSlot),
      ("int64_t","DRIVECHAIN_PEGOUT_MAIN_FEE_SATS",pegoutMainFee),
      ("int64_t","DEFAULT_DRIVECHAIN_BMM_BID",defaultBmmBid),
      ("int64_t","DEFAULT_BMM_WORK_SATS_PER_KWU",defaultBmmWorkPrice),
      ("int64_t","DEFAULT_BMM_PRODUCER_RESERVE",defaultBmmProducerReserve),
      ("size_t","BMM_EDGE_CACHE_MAX",bmmEdgeCacheSize),
      ("size_t","BMM_NEGATIVE_PARENT_CACHE_MAX",bmmNegativeCacheSize),
      ("int64_t","BMM_NEGATIVE_PARENT_CACHE_SECONDS",bmmNegativeCacheSeconds),
      ("int64_t","PEER_BLOCK_TIMEOUT_SECONDS",peerBlockTimeoutSeconds),
      ("int64_t","PEER_REJECTED_BACKOFF_SECONDS",peerRejectedBackoffSeconds),
      ("int64_t","PEER_UNAVAILABLE_BACKOFF_SECONDS",peerUnavailableBackoffSeconds),
      ("uint32_t","ECX_FORCED_INCLUSION_BLOCKS",forcedInclusionBlocks),
      ("uint64_t","ECX_MAX_COMBINED_UNCONSUMED",maxCombinedUnconsumed),
      ("uint64_t","ECX_MAX_COMBINED_APPENDS",maxCombinedAppends),
      ("uint64_t","ECX_MAX_PENDING_WITNESS_ENTRIES",maxPendingWitnessEntries),
      ("uint32_t","ECX_MAX_TRANCHE_WORK",maxTrancheWork),
      ("size_t","NATIVE_WITHDRAWAL_MAX_DESTINATION_SIZE",withdrawalDestinationSize),
      ("size_t","NATIVE_WITHDRAWAL_M6_REFERENCE_SIZE",withdrawalReferenceSize),
      ("size_t","NATIVE_WITHDRAWAL_MAX_M6_LEGACY_SIZE",withdrawalLegacySize),
      ("uint32_t","CTIP_STATE_INDEX",0),
      ("size_t","MAX_BMM_PROOF_ENTRIES",proofEntries),
      ("size_t","MAX_BMM_PROOF_BYTES",proofBytes),
      ("int64_t","BMM_TARGET_TIMESPAN",targetTimespan),
      ("int64_t","BMM_TARGET_SPACING",targetSpacing),
      ("bool","BMM_REQUIRE_SIGNET_SOLUTION",requireSignet)] ++ replayConstants ++ exchangeInterfaceConstants] ++
  ["static constexpr uint32_t " ++ name ++ "_HF_MASK{" ++ show (2 ^ bit :: Word64) ++ "};" |
    (name,bit) <- zip ["WITHDRAWAL_BUNDLE","BMM_PROOF","EXCHANGE_STATE","FORCED_INBOX","DEPOSIT_INBOX","INBOX_CURSOR","SWAP_FORCED_STATE"]
      (withdrawalHeaderBit : headerExtensionBits ++ [swapForcedHeaderBit])] ++
  ["static constexpr size_t PARENT_HASH_HEX_LENGTH{" ++ show parentHashHexLength ++ "};",
   "static constexpr int64_t PARENT_RECOVERY_SECONDS{" ++ show parentRecoverySeconds ++ "};"] ++
  ["inline constexpr char DRIVECHAIN_GRPC_ENDPOINT[]{" ++ show grpcEndpoint ++ "};",
   "static constexpr char BMM_FINGERPRINT_TAG[]{" ++ show fingerprintTag ++ "};",
   "static constexpr char PARENT_REPLAY_STORE_DOMAIN[]{" ++ show replayIdentityDomain ++ "};",
   "static constexpr char PARENT_REPLAY_DIRECTORY[]{" ++ show replayDirectory ++ "};",
   "static constexpr char CTIP_STATE_HASH[]{" ++ show ctipHash ++ "};",
   "static constexpr unsigned char CTIP_MARKER_BYTES[]{" ++ intercalate "," (map (show . ord) ctipMarker) ++ "};"] ++
  ["static constexpr std::array<const char*, " ++ show (length values) ++ "> " ++ name ++
    "{" ++ intercalate "," (map show values) ++ "};" |
    (name,values) <- [("WITHDRAWAL_STATUSES",withdrawalStatuses),("WITHDRAWAL_STATE_NAMES","":withdrawalStatuses),
      ("WITHDRAWAL_ACKNOWLEDGEMENTS",map snd withdrawalLifecycle),
      ("ECX_CAPITAL_MODES",capitalModes),("ECX_ORACLE_MODES",oracleModes)]] ++ [""] ++ lifecycleHeaders ++
  ["static constexpr std::array<uint8_t, 4> " ++ name ++ "{{" ++ intercalate "," (map show bytes) ++ "}};" |
    (name,bytes) <- parentMessageTags] ++ ["}", "#endif"]
