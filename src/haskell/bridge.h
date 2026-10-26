// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#ifndef ELEMENTS_HASKELL_BRIDGE_H
#define ELEMENTS_HASKELL_BRIDGE_H

#include <cstdint>
#include <cstddef>
#include <array>
#include <span>
#include <string>
#include <vector>
#include <functional>
#include <iterator>
#include <initializer_list>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <utility>

class CTransaction;
class CScript;
class uint256;
namespace Sidechain::Bitcoin { class CBlock; }

namespace drivechain::haskell {
using NativeWorkflow = std::function<std::vector<unsigned char>(uint32_t, uint64_t, std::span<const unsigned char>)>;
enum class ExchangeSession : uint32_t {
    FORCED_CANONICAL, FORCED_ADMISSION, FORCED_CURSOR, FORCED_SOURCE, CUSTODY_RESERVED, CUSTODY_BUDGET,
    CUSTODY_AVAILABLE, CUSTODY_IDENTITY, CUSTODY_GENESIS, CUSTODY_DECODE,
};
bool RunExchangeSession(ExchangeSession mode, const NativeWorkflow& native);
// Owns transient Signet objects; the supplied block, challenge and genesis must outlive it.
NativeWorkflow PrepareParentSignet(const Sidechain::Bitcoin::CBlock& block,
    const CScript& challenge, const uint256& genesis, std::string* error);
enum class AuthFileMode : uint32_t { RAW, STATIC_RECORD, ROTATING_COOKIE };
bool ReadAuthFile(AuthFileMode mode, const NativeWorkflow& native);
enum class ReplayStoreWorkflow : uint32_t { CHECK_TIP, APPEND, DEPOSIT, EDGE, WITHDRAWAL, OCCURRENCE, LIST_DEPOSITS, LOAD, RESET, CACHE, MILESTONE, BMM, LOAD_SESSION, RESET_SESSION, APPEND_SESSION, DEPOSIT_ADMISSION, CONFIRMED_DEPOSIT, DEPOSIT_SESSION, SCAN_SESSION, DEPOSIT_CANDIDATES, PARENT_NETWORK, ACTIVE_HASH, CONFIRMATION_DEPTH, ALPHA_PEGIN_IDENTITY, RPC_TRANSPORT, RPC_TRANSPORT_CHECKED, RPC_HOST, LOCAL_BID, BID_SUBMISSION, BMM_CONTEXT, WALLET_WITHDRAWAL, JOURNAL_VALIDATE, JOURNAL_READ, JOURNAL_WRITE, JOURNAL_CLEAR, BMM_PROOF_REQUIRED, BMM_HEADER_POLICY, BMM_STATE_READ, BMM_STATE_EFFECTIVE, BMM_STATE_CONTEXT, STATE_STORE, STATE_RESTORE, PROOF_ENCODE, PROOF_DECODE, PROOF_ATTACH, PROOF_ENTRIES, PROOF_BLOCK, PROOF_PARENT, CHAIN_CONNECT, CHAIN_DISCONNECT, COMMITMENT };
uint32_t RunReplayStore(ReplayStoreWorkflow mode, const NativeWorkflow& native);
enum class ParentHeaderWorkflow : uint32_t { POW, WORK, CHAINWORK, RAW, MEDIAN, RPC_MEDIAN,
    HASH, METADATA, PREDECESSOR, VERIFY, RPC_VERIFY, RAW_DEADLINE, RPC_MEDIAN_DEADLINE, RPC_VERIFY_DEADLINE,
    BLOCK_TRANSACTIONS, BLOCK_SIGNET, BLOCK, BLOCK_DEADLINE,
    SIGNET_VERIFY, SIGNET_MERKLE, SIGNET_BUILD, SIGNET_DATA, SIGNET_COMMITMENT, NETWORK_VERIFY,
    READ_BODY, READ_BLOCK };
bool RunParentHeader(ParentHeaderWorkflow kind, uint32_t height,
    const std::function<uint64_t(uint32_t, uint64_t)>& native);
bool RunParentHeader(ParentHeaderWorkflow kind, uint32_t height, const NativeWorkflow& native);
enum class BitcoinSignatureWorkflow : uint32_t { BMM, PARENT, HASH };
bool RunBitcoinSignature(BitcoinSignatureWorkflow kind, int32_t hash_type, bool witness,
    uint32_t index, uint64_t inputs, uint64_t outputs, std::span<const unsigned char> signature,
    const NativeWorkflow& native);
bool ValidateWithdrawalEnvelope(bool inactive, const NativeWorkflow& native, std::string& error);
bool MeasureWork(bool saturate, uint64_t count, const std::function<const CTransaction&(uint64_t)>& transaction,
    uint64_t& total, uint64_t* last = nullptr);
enum class TransactionAdmission : uint32_t { ORDINARY_INPUTS, EXPLICIT_CREATIONS, PUBLIC_BOND, DEPLOYMENT };
bool AdmitTransaction(TransactionAdmission kind, const CTransaction& tx,
    uint64_t issuance = 0, uint64_t inventory = 0, uint64_t burn = 0, uint64_t authority = 0,
    const std::function<std::array<unsigned char,64>()>& derive = {});
struct UsddResourceSource;
enum class StandardnessGate : uint32_t { ANNEX_NETWORK, OUTPUT_EXCEPTIONS, WITNESS_RESOURCES };
bool AdmitStandardness(StandardnessGate kind, uint32_t facts, uint64_t count = 0, uint64_t limit = 0);
using RustVerifierVersion = uint32_t (*)();
using RustVerifierIdentity = uint32_t (*)(unsigned char*, size_t);
using RustCustody = bool (*)(const unsigned char*, size_t, const unsigned char*, size_t, const unsigned char*, size_t);
bool VerifyCustody(RustCustody verify, std::span<const unsigned char> bundle,
    std::span<const unsigned char> registry, std::span<const unsigned char> receipts, size_t count);
using RustGroth16 = bool (*)(void*, const unsigned char*, size_t, const uint32_t*, const unsigned char*);
bool VerifyGroth16(RustGroth16 verify, void* context, const unsigned char* proof, size_t size,
    const uint32_t* program, const unsigned char* digest);
using RustVerifyAnnex = uint32_t (*)(uint32_t, const unsigned char*, size_t, const unsigned char*, size_t, const unsigned char*, size_t);
int VerifyJournal(RustVerifierVersion version, RustVerifyAnnex verify, std::span<const unsigned char> annex,
    std::span<const unsigned char> program, std::span<const unsigned char> digest);
bool TransactionWeight(bool bond, uint64_t total, uint64_t annex, uint64_t ordinary, uint64_t proof);
bool BondMarkerPolicy(bool exact, std::span<const unsigned char> script);
bool ReturnMarker(std::span<const unsigned char,4> magic, std::span<const unsigned char> script);
uint32_t TaprootWitnessPolicy(bool annex, bool bond, uint64_t count, uint32_t leaf, uint64_t script_size, uint64_t input);
uint32_t UsddPolicyWeight(uint32_t flags, uint64_t count,
    const std::function<uint64_t(uint32_t,uint64_t)>& read, bool expanded_activation = false,
    const UsddResourceSource* source = nullptr);
bool UsddPackageResources(uint32_t flags, uint64_t count, uint64_t initial, uint64_t lane,
    const std::function<uint64_t(uint32_t,uint64_t)>& read, const UsddResourceSource* source = nullptr);
uint32_t UsddBlockResources(uint64_t count, uint64_t lane, uint64_t weight,
    const std::function<uint64_t(uint32_t,uint64_t)>& read, const UsddResourceSource* source = nullptr);
bool AnchorRule(std::span<const std::byte> encoded);
std::optional<std::array<unsigned char,80>> AnchorCheckpoint(std::span<const std::byte> encoded);
bool BmmWorkQuote(int64_t fees, uint64_t work, int64_t rate, int64_t reserve, std::array<int64_t,3>& fields);
/** RPC view: rejected quotes clear all fields; true means a positive funded bid. */
bool BmmWorkQuoteDisplay(int64_t fees, uint64_t work, int64_t rate, int64_t reserve, std::array<int64_t,3>& fields);
enum class BmmMessageKind : uint32_t { DEFINITIVE_WAIT, DUPLICATE_REQUEST };
bool BmmMessageMatches(BmmMessageKind kind, const std::string& message);
int BmmWorkBid(uint32_t hashes, int64_t height, int64_t fees, int64_t work, int64_t reserve,
    int64_t requested, const std::function<int64_t(uint32_t)>& rate, std::array<int64_t,4>& fields);
bool DepositInputLimit(bool enabled, uint64_t count, uint64_t limit,
    const std::function<uint64_t(uint32_t,uint64_t,uint64_t)>& read);
bool StartupArgs(uint32_t slot, uint32_t timeout_maximum, const std::function<uint64_t(uint32_t)>& read);
void FeeFreeSelection(int64_t age, const std::function<uint64_t(uint32_t)>& read);
bool ExchangeTemplateBudget(int64_t height, int64_t activation, const std::function<uint64_t(uint32_t)>& read,
    uint64_t& budget, std::string& error);
bool ExchangeSourcePackage(bool enabled, uint64_t count,
    const std::function<uint64_t(uint32_t,uint64_t)>& action, uint64_t& selected, bool modified=false);
enum class ConfigurationField : uint32_t { RAW_HASH, NONZERO_HASH, OUTPOINT, SPENDABLE_SCRIPT, DISPLAY_HASH, CONFIGURATION_HEX, CUSTODIAN_REGISTRY, PROPOSAL_DESCRIPTION = 9 };
enum class NetworkSelection : uint32_t { PRODUCTION, CHAIN_NAME, REGTEST_OPTION };
uint8_t ContextPresence(uint32_t count, uint32_t required);
void ScriptCacheEncode(bool endpoint_only, std::span<const std::byte> input, std::span<unsigned char> output);
enum class CtvAction : uint8_t { IGNORE, DISCOURAGE, EMPTY_STACK, CHECK_HASH };
CtvAction CtvAdmission(uint32_t flags, uint64_t size);
bool VerifierIdentity(bool active, uint32_t abi, uint32_t format,
    const std::array<unsigned char,32>& expected, RustVerifierVersion version,
    RustVerifierVersion identity_version, RustVerifierIdentity identity, std::string* error);
bool ActivationShape(const std::function<int64_t(uint32_t)>& read);
int64_t ActivationBudget(int64_t ordinary, uint32_t input, const std::function<bool(uint32_t)>& read);
uint32_t NetworkSelectionStatus(NetworkSelection kind, const std::string& text, bool elements_mode = false);
void ValidateNetworkSelection(NetworkSelection kind, const std::string& text, bool elements_mode = false);
bool RejectWalletIssueAmount(double amount);
bool MainchainCookieAtRoot(const std::string& chain);
std::string WideDecimal(std::span<const unsigned char,16> bytes, bool signed_value = false);
bool AcceptAddressAlias(bool parent, bool confidential, const std::string& network, const std::string& prefix);
bool AcceptPaymentUri(bool elements_mode, bool canonical, std::string_view scheme);
std::string_view PaymentUriScheme(bool elements_mode, bool canonical, bool liquid_testnet);
// Callbacks must not reenter Haskell. Failure is {zero-based role, nonzero violation}.
std::optional<std::pair<uint32_t,bool>> ParseHashArguments(bool direct, const std::function<std::string(uint32_t)>& read,
    const std::function<void(uint32_t,std::span<const unsigned char,32>)>& publish);
std::vector<unsigned char> ParseConfigurationField(ConfigurationField kind, const std::string& text,
    const std::string& syntax_error, const std::string& value_error);
// One field admits a method; two admit method/payload; eight also build argv.
std::vector<std::string> GrpcPlan(std::span<const std::string> fields);
struct GrpcResponse { int status; std::string output; };
GrpcResponse GrpcRequest(std::span<const std::string, 7> fields, int64_t timeout_ms,
    size_t max_output, const std::function<bool()>& should_cancel);
struct GrpcTextAdmission { bool address_shape, address_characters, authority_characters; };
GrpcTextAdmission AdmitGrpcText(const std::string& address, const std::string& authority);
// Result bits: 1 = identities valid, 2 = evaluator active. Bridge failures throw.
int EvaluatorIdentity(bool frozen, bool private_catalogue, const std::string& catalogue, const std::string& program);
bool AdmitTlsCredentialFile(bool private_key, const std::function<uint64_t(uint32_t)>& read);
int UsddExtractBlock(bool zero_genesis, std::span<const unsigned char,69> profile,
    const std::function<int64_t(uint32_t,uint64_t,uint64_t,uint64_t,unsigned char*)>& effect,
    std::span<const unsigned char> state = {}, std::span<const unsigned char> empty_roots = {},
    uint64_t count = 0, uint8_t prefix = 0, bool derive = false);
std::array<unsigned char,64> UsddClaimHashes(uint32_t mode, std::span<const unsigned char,69> profile,
    std::span<const unsigned char,168> input);
int UsddClaimPrefix(uint64_t index, std::span<const unsigned char,69> profile,
    std::span<const unsigned char> input, std::vector<unsigned char>& leaves);
int UsddCheckpoint(uint64_t before_count, uint64_t after_count, uint8_t prefix,
    std::span<const unsigned char,2080> before, std::span<const unsigned char,2080> after,
    std::span<const unsigned char,2080> empty_roots, std::span<const unsigned char> profile,
    std::span<unsigned char,32> output);
bool UsddAccumulator(uint32_t mode, uint64_t count, uint8_t prefix, std::span<unsigned char,2080> state,
    std::span<const unsigned char,2080> empty_roots, std::span<const unsigned char> leaf, uint64_t* next_count = nullptr);
bool UsddAccumulatorVersion(uint32_t version);
void UsddFrontierWire(uint64_t count, bool reading, const std::function<bool(uint32_t)>& action);
int64_t WalletBalanceTotal(int64_t trusted, int64_t pending, int64_t immature);
enum class GenesisCodec : uint32_t { BOND, PRIVATE_STATE, COVENANT, TAP_LEAF, TAP_BRANCH, AVAILABILITY_SCHEME, CUSTODY_RECEIPT, RISK_PROFILE,
    FINITE_SNAPSHOT, INCREMENTAL_SNAPSHOT, ACTIVATION_SNAPSHOT, GENESIS_SNAPSHOT };
std::vector<unsigned char> ExchangeGenesisState(GenesisCodec codec, uint64_t height, uint64_t price,
    std::initializer_list<const unsigned char*> hashes, std::span<const unsigned char> bond = {}, std::span<const unsigned char> funding = {});
enum class InboxCodec : uint32_t { FORCED, DEPOSIT, STEP, WIDE_STEP, BOND, WIDE_BOND, MARKER_CONTEXT, NO_STAGING_AUTH = 9, STAGING_AUTH, REGISTRY, STAGING_DESCRIPTOR = 13, STAGING_HIDDEN, BOND_DEPLOYMENT };
/** Fresh inactive exact-inbox codecs. These do not authenticate signatures or
 * source headers. Full-width fields always use (high64, low64). */
// Internal structural codecs. They never produce a verified execution receipt.
std::optional<std::vector<unsigned char>> ExchangeForcedV3BlockBytes(
    uint32_t mode, std::span<const unsigned char> bytes);
bool ExchangeForcedV3Frame(std::span<const unsigned char> script,
    std::span<const unsigned char,32> economic_hash, std::vector<unsigned char>& payload);
std::vector<unsigned char> ExchangeInboxEntry(InboxCodec codec, std::array<uint64_t, 7> fields,
    std::initializer_list<const unsigned char*> hashes, std::span<const unsigned char> body = {});
bool ExchangeSpendScan(bool unique, uint64_t start, uint64_t end,
    const std::function<uint64_t(uint64_t)>& read, std::optional<uint64_t>& match);
bool ExchangeDeploymentOutputs(uint64_t skipped, uint64_t count, const std::function<uint64_t(uint64_t)>& read);
bool ExchangeFrozenBounds(std::span<const uint64_t> fields);
bool FitsU32(std::span<const uint64_t> fields);
std::pair<bool, int32_t> ExchangeRuntimeActivation(int32_t activation, std::optional<int32_t> private_height);
uint32_t PegEventRange(int32_t start, int32_t count, int32_t tip, int32_t& end);
int32_t PegEventStart(int32_t tip);
uint32_t ExchangeExportRange(int32_t start, int32_t count, int32_t activation,
    std::optional<int32_t> tip, int32_t& end);
void ExchangeDeploymentBlinders(bool public_deployment, std::span<const unsigned char* const,3> identities);
void ExchangeDeploymentIdentities(bool direct_price, std::span<const unsigned char* const,22> identities);
bool ExchangeFrozenIdentities(bool direct_price, std::span<const unsigned char* const,22> identities, std::string& error);
void ExchangeActivationFacts(std::span<const unsigned char* const,40> identities);
void ExchangeRuntimeIdentities(std::span<const unsigned char* const,16> identities);
bool ExchangeCarryIdentity(uint32_t profile, std::span<const unsigned char* const,15> identities);
bool ExchangeDistinct(std::span<const unsigned char* const> identities);
uint32_t UsddAdmission(uint32_t lane, std::span<const unsigned char> bytes, uint64_t limit,
    std::array<uint32_t, 3> profile, bool bmm, bool active, const std::function<int32_t(uint32_t)>& identity);
uint32_t UsddAnnex(std::span<const unsigned char> bytes, uint64_t limit, std::array<uint32_t, 3> profile);
uint32_t UsddLegacy(uint32_t mode, std::array<std::span<const unsigned char>, 7> fields,
    std::array<uint32_t, 5> profile, uint64_t limit, bool bmm, bool active,
    std::array<uint64_t,4> shape = {});
struct UsddWitness {
    std::span<const unsigned char> annex, cmr, control;
    uint64_t items;
};
struct UsddResourceSource {
    std::array<std::span<const unsigned char>,7> fields;
    std::array<uint32_t,5> profile;
    uint64_t limit;
    bool parameterized;
    std::function<UsddWitness(uint64_t)> read;
};
std::pair<uint32_t,uint64_t> UsddResources(uint64_t count,
    std::array<std::span<const unsigned char>,7> fields, std::array<uint32_t,5> profile,
    uint64_t limit, bool parameterized, const std::function<UsddWitness(uint64_t)>& read);
bool ExchangeAbsent(std::span<const unsigned char* const> identities);
bool ExchangeRegistry(std::span<const std::array<unsigned char, 32>, 5> encryption,
    std::span<const std::array<unsigned char, 32>, 5> attestation, std::string& error);
std::vector<unsigned char> ExchangeRegistryEncoding(std::span<const std::array<unsigned char,32>,5> encryption,
    std::span<const std::array<unsigned char,32>,5> attestation);
void ExchangeRegistryDecoding(std::span<const unsigned char> bytes, std::span<std::array<unsigned char,32>,5> encryption,
    std::span<std::array<unsigned char,32>,5> attestation);
/** Strict fresh exact-custody codec/pin/lineage checks; no proof authentication. */
bool ExchangeCustodyCheck(uint32_t mode, std::span<const unsigned char> values,
    std::span<const unsigned char> context = {});

bool ExchangeCapitalIdentity(uint32_t profile, std::span<const unsigned char, 32> program,
    std::span<const unsigned char> values, std::initializer_list<const unsigned char*> identities,
    std::initializer_list<uint64_t> context = {}, std::initializer_list<const unsigned char*> snapshot_context = {},
    std::span<unsigned char> snapshot = {});
bool ExchangeSuccessorBinding(bool incremental, std::span<const unsigned char> values,
    std::span<const unsigned char* const,4> identities, std::span<const uint64_t,3> context);
bool ExchangeSwapSuccessorBinding(std::span<const unsigned char> values,
    std::span<const unsigned char* const,6> identities, std::span<const uint64_t,4> context);
std::vector<unsigned char> ExchangeEnvelopePayload(uint32_t height, const unsigned char* checkpoint, std::span<const unsigned char> body);
enum class SourceMarker : uint32_t { FORCED, DEPOSIT, ACTIVATION };
bool ExchangeSourceMarker(uint32_t& seen, SourceMarker kind, bool present, std::string& error);
bool ExchangeDeriveInbox(uint64_t count, uint64_t forced, uint64_t deposits,
    const std::function<int64_t(uint32_t,uint64_t,uint64_t)>& action, std::string& error);
bool ExchangeSourceAdmission(const std::function<uint64_t(uint64_t)>& read, std::string& error);
enum class Availability : uint32_t { ROOT, CURSORS, SNAPSHOT, RPC };
bool ExchangeAvailable(Availability kind, const std::function<bool(uint32_t)>& read);
bool ExchangeSnapshot(const std::function<bool(uint32_t)>& read, std::string& error);
bool ExchangeGenesisInitialization(uint32_t version, const std::function<bool(uint32_t)>& read, std::string& error);
bool ExchangeDeployment(uint32_t version, const std::function<bool(uint32_t)>& read, std::string& error);
int ExchangeRequiredIdentity(bool public_deployment, bool direct_price, const std::function<bool(uint32_t)>& read);
bool ExchangePhysicalInputs(bool public_deployment, const std::function<bool(uint32_t)>& read);
enum class TransactionShape : uint32_t { TRANSITION, DEPLOYMENT_LINKAGE, ISSUANCE, PRIVATE_OUTPUTS, PUBLIC_OUTPUTS, CONFIRMED_COINS, GENESIS_SINGLETON, CUSTODY_WITNESS,
    MARKER_UNIQUENESS, STAGING_INDEX, STAGING_OUTPUT, STAGING_BYTES, SOURCE_AUTHORIZATION, SOURCE_SINGLETON, STAGING_RENDERER, RUNTIME_SETTINGS,
    DEPLOYMENT_ARGUMENTS = 18, CANONICAL_FORCED, FORCED_ENVELOPE, DEPOSIT_ENVELOPE, DEPOSIT_REFERENCE, FORCED_SIGNATURE, TRACKED_COIN };
bool ExchangeTransactionShape(TransactionShape phase, const std::function<bool(uint32_t)>& read, std::string& error);
bool ExchangeActivationSettings(const std::function<bool(uint32_t)>& read);
uint32_t ExchangeBondSettings(const std::function<bool(uint32_t)>& read);
enum class DisconnectPhase : uint32_t { PRIOR_HEADER, UNDO, REMOVE, COUNTS };
// REMOVE performs ordered mutations; a later failure does not roll back earlier steps.
bool ExchangeDisconnect(DisconnectPhase phase, const std::function<bool(uint32_t)>& perform, std::string& error);
bool ExchangeConnection(bool activation, const std::function<bool(uint32_t)>& read, std::string& error);
bool ExchangeParentTarget(std::optional<uint64_t>& height,
    const std::function<uint64_t(uint32_t)>& read, std::string& error);
enum class HeaderPhase : uint32_t { BEFORE_ACTIVATION, ACTIVE, GENESIS };
bool ExchangeHeader(HeaderPhase phase, const std::function<bool(uint32_t)>& read, std::string& error);
bool ExchangeConfiguration(const std::function<bool(uint32_t)>& read, std::string& error);
bool ProductionIdentity(const std::function<bool(uint32_t)>& read, std::string* error);
enum class TrackerPhase : uint32_t { ENCODING, SCRIPT, PAYLOAD };
// 0: valid; 1: malformed; 2: missing coin (encoding phase only).
uint32_t ExchangeTracker(TrackerPhase phase, const std::function<bool(uint32_t)>& read);
bool ExchangeTranche(std::span<const uint8_t> kinds, uint32_t& work, std::string& error);
bool ExchangeProfile(bool collateral, const std::function<bool(uint32_t)>& read);
int ExchangeForcedBody(uint32_t kind, std::span<const unsigned char> body,
    std::span<const unsigned char, 32> chain, std::span<const unsigned char, 16> market);
bool ExchangeDeriveCursors(uint64_t count, uint32_t flags, uint64_t previous_forced, uint64_t previous_deposit,
    const std::function<int32_t(uint32_t, uint64_t, uint64_t, uint64_t*)>& read,
    uint64_t& forced, uint64_t& deposit, std::string& error);
enum class ExchangeStateWorkflow : uint32_t { AUTHORITY, SUCCESSOR_AUTHORITY, TRACKED_COIN, TRANSITION };
bool RunExchangeStateWorkflow(ExchangeStateWorkflow kind, uint64_t count,
    const std::function<uint64_t(uint32_t,uint64_t,uint64_t)>& action, std::string& error);
bool ExchangeInbox(std::span<const uint64_t> fields, uint64_t& output, std::string& error);
std::array<uint64_t, 2> ExchangePending(std::array<uint64_t, 4> fields);
bool ExchangeTrackSource(bool successor, std::array<uint64_t, 4> fields,
    std::initializer_list<const unsigned char*> hashes, std::vector<unsigned char>& state, std::string& error);
bool ExchangeSourcePredecessor(bool successor, uint64_t proof_profile, uint64_t height, uint64_t parent,
    std::span<const unsigned char,32> head, std::span<const unsigned char,16> count,
    std::span<const unsigned char,16> processed, std::string& error);
bool ExchangeAppendMarker(std::array<uint64_t, 14> fields,
    std::initializer_list<const unsigned char*> hashes, std::span<const unsigned char, 16> count,
    std::span<const unsigned char> script,
    const std::function<void(uint32_t, std::span<const unsigned char>, std::span<unsigned char, 32>)>& effect,
    std::array<unsigned char, 48>& state, std::string& error);
bool ExchangeBondMarker(uint64_t limit, std::span<const unsigned char> payload,
    std::initializer_list<const unsigned char*> identities, std::string& error);
bool ExchangeMarkerFrame(bool successor, std::span<const unsigned char> script, std::vector<unsigned char>& payload);
bool ExchangeLegacyMarkerFrame(bool forced, std::span<const unsigned char> script, std::vector<unsigned char>& payload);
bool ExchangeCursorPayload(std::span<const unsigned char> payload, bool& marker,
    uint64_t& forced, uint64_t& deposit, std::string& error);
bool ExchangeCustodyReceipts(uint32_t count, std::span<const unsigned char> encoded, std::vector<unsigned char>& receipts, uint8_t& bitmap, std::string& error);
bool ExchangeAnnexHeader(std::span<const unsigned char> annex, uint64_t expected, uint64_t limit, uint32_t& bundle_length, uint8_t& receipt_count, std::string& error);
using CustodyHash = std::function<std::array<unsigned char,32>(uint32_t, std::span<const unsigned char>)>;
std::string ConfigurationIdentity(const std::string& network, std::span<const unsigned char,64> identities, const CustodyHash& hash);
bool MaterialName(bool chainstates, const std::string& filename);
bool IdentityWrite(const std::function<bool(uint32_t)>& perform);
bool ExchangeFrozenConfiguration(std::span<const unsigned char> input, std::span<const unsigned char,16> market,
    const CustodyHash& effect, std::string& error);
std::array<unsigned char,128> ExchangeGenesisRoots(uint64_t height, uint64_t mtp, uint64_t price,
    std::initializer_list<const unsigned char*> identities, const CustodyHash& hash);
std::array<unsigned char,32> ExchangeCustodyRoot(uint64_t bundle_length,
    std::initializer_list<const unsigned char*> identities, std::span<const unsigned char> receipts, const CustodyHash& hash);
// Reader supplies borrowed bytes (group 1) or scalars; no callback may reenter Haskell.
using FingerprintReader = std::function<bool(uint32_t, uint32_t, uint64_t&, const unsigned char*&)>;
// Profiles: 0 BMM v4, 1 exchange v9, 2 activation. Unknown profiles fail closed.
std::vector<unsigned char> BmmFingerprint(const FingerprintReader& reader, uint32_t profile = 0);
int64_t BoundedWait(int64_t value, int64_t maximum);
uint64_t BoundedAppend(uint64_t limit, uint64_t used, int64_t count);
int64_t BmmDifficultyInterval(int64_t timespan, int64_t spacing);
void BmmFixedIdentity(std::span<uint32_t, 2> fields, std::span<unsigned char, 121> payload);
void BmmCheckpointPreset(uint32_t mode, std::span<uint32_t, 16> fields,
    std::span<unsigned char, 32> block_hash);
uint32_t BmmConsensusPreset(uint32_t mode, std::span<uint64_t, 6> fields,
    std::span<unsigned char, 32> pow_limit, std::span<unsigned char, 22> challenge);
void BmmPrivateTemplate(uint32_t height, uint32_t time, uint32_t median, uint32_t slot,
    std::span<const unsigned char, 32> critical, std::span<uint32_t, 4> fields,
    std::span<unsigned char, 37> commitment);
enum class LiveEvidencePhase : uint32_t { NETWORK, CONFIRMATION, CTIP_OUTPUT, CTIP_STATE, SIDECHAIN, DEPOSITS };
bool BmmState(bool hash, int64_t interval, uint32_t height, uint32_t time, uint32_t bits,
    uint32_t start, uint32_t start_time, uint64_t count, uint32_t latest, std::string& error);
std::array<uint32_t,2> BmmHeaderLayout(uint32_t version, uint32_t flags);
bool MerkleReplacement(uint32_t mode, uint32_t index, uint32_t position, uint32_t flags);
enum class SignetStep : uint32_t { START, WITNESS, EXTRACT, BUILD, DECODE, MERKLE, COINBASE, VERIFY };
int32_t BmmActivation(uint32_t phase, uint32_t facts, int64_t height = 0, int64_t activation = 0);
void RunBmmRetarget(uint32_t height, int64_t interval, int64_t target, uint32_t time, uint32_t start,
    const NativeWorkflow& native);
uint32_t BmmMedian(std::span<const uint32_t> times);
enum class BmmProofPhase : uint32_t { ENVELOPE, BOUNDS, CANONICAL, MERKLE, EXTENSION, PARENT, CRITICAL, BLOCK_BOUNDS, BLOCK_HASH, PRIOR, MERKLE_HASH, POW_TARGET, POW_HASH, COINBASE_PRESENT };
enum class BmmTraversalStep : uint32_t {
    START, PREFLIGHT, ENTRY_BOUNDS, MERKLE, COINBASE, EXTENSION, SIGNET, ADVANCE, PARENT, COMMITMENT, CRITICAL,
    BLOCK_START, BLOCK_BOUNDS, BLOCK_HASH, BLOCK_DECODE, BLOCK_PRIOR, BLOCK_PARENT, BLOCK_ENTRIES,
    INITIALIZE_ENTRIES, PUBLISH_ENTRIES, PREPARE_ENTRY,
    PARENT_START, PARENT_COINBASE, PARENT_EXTRACT,
    VALID_STATE = 147, EXTEND_PARENT = 150, EXTEND_BITS, EXTEND_TIME,
    POW_TARGET = 154, POW_HASH, RESET_ENTRY = 200, DECODE_COINBASE,
    DECODE_MERKLE, CANONICAL_COINBASE, CANONICAL_MERKLE, COINBASE_SHAPE
};
enum class BmmLifecyclePhase : uint32_t {
    CONNECT_KIND, NATIVE_STATE, CONNECT_CHECKPOINT, INITIALIZE, REQUIRED, INCOMPLETE,
    DISCONNECT_KIND, REMOVE_CHECKPOINT, REMOVED, DISCONNECT_PROOF, LOAD_CURRENT, RESTORE
};
enum class BmmStateStep : uint32_t {
    CONNECT_START, CONNECT_KIND, NATIVE_HEADER, NATIVE_STATE, CHECKPOINT, INITIALIZE, STORE_INITIAL,
    REQUIRED, INCOMPLETE, EFFECTIVE, VERIFY, STORE_NEXT, DISCONNECT_START, DISCONNECT_KIND,
    REMOVE_CHECKPOINT, REMOVE, HAS_PROOF, DECODE_PROOF, LOAD_CURRENT, EXTRACT_PARENT, STORE_PRIOR,
    VERIFY_ENTRIES, COMPARE_CURRENT, REJECT_PRIOR,
    PRIVATE_START, PRIVATE_ENABLED, PRIVATE_VALID, PRIVATE_COINBASE, PRIVATE_HEADER,
    PRIVATE_POW, PRIVATE_NONCE, PRIVATE_ASSEMBLE, PRIVATE_VERIFY,
    READ_START, READ_PUSH, READ_DROP, READ_END, READ_MARKER, READ_STATE, READ_PAYLOAD, READ_VALID,
    ENTRY_START, ENTRY_TX, ENTRY_PROOF, ENTRY_TX_CANONICAL, ENTRY_PROOF_CANONICAL,
    PREFLIGHT_START, PREFLIGHT_ENVELOPE, PREFLIGHT_STATE,
    EXTEND_START, EXTEND_PARENT, EXTEND_DIFFICULTY, EXTEND_TIME, EXTEND_CHECK, EXTEND_POW,
    ATTACH_START, ATTACH_GATE, ATTACH_SERIALIZE, ATTACH_PUBLISH,
    CONTEXT_START, CONTEXT_VALID, CONTEXT_MEDIAN, CONTEXT_PUBLISH,
    PROOF_START, PROOF_SIZE, PROOF_DECODE, PROOF_SHAPE, PROOF_CANONICAL,
    EFFECTIVE_START, EFFECTIVE_NETWORK, EFFECTIVE_LOAD, EFFECTIVE_PUBLIC, EFFECTIVE_PUBLISH_PUBLIC,
    EFFECTIVE_PRIVATE, EFFECTIVE_PUBLISH_PRIVATE,
    ACTIVATION_START, ACTIVATION_PREFLIGHT, MODE_SELECT, MODE_PRIVATE, MODE_PUBLIC,
    CONSENSUS_START, RETARGET_START, RETARGET_SPAN, RETARGET_SCALE,
    POW_START, POW_TARGET, POW_HASH,
    EXTRACT_START, EXTRACT_SELECT, EXTRACT_FIRST, EXTRACT_SECOND, EXTRACT_PUBLISH,
    PARENT_START, PARENT_COINBASE, PARENT_EXTRACT,
    SIGNATURE_START, SIGNATURE_GATE, SIGNATURE_KEY, SIGNATURE_SPLIT, SIGNATURE_HASH, SIGNATURE_VERIFY,
    COIN_START, COIN_UNSPENT, COIN_ASSET, COIN_PEGGED, COIN_VALUE, COIN_ZERO,
    NATIVE_CHECK_START, NATIVE_CHECK_PROOF, NATIVE_CHECK_LOOKUP, NATIVE_CHECK_RESULT,
    PARENT_SIGNATURE_START, PARENT_SIGNATURE_GATE, PARENT_SIGNATURE_ENCODING, SIGNATURE_MODE
};
bool RunBmmStateFlow(BmmStateStep start, const std::function<int32_t(BmmStateStep)>& action);
enum class PegEventKind : uint32_t { LIFECYCLE, DEPOSIT_NUMBERS, STATUS };
enum class EventIdentityKind : uint32_t { BUNDLE, DEPOSIT, WITHDRAWAL, L1_DEPOSIT, L1_WITHDRAWAL };
enum class EventLayoutKind : uint32_t {
    BUNDLE, DEPOSIT, WITHDRAWAL, L1_DEPOSIT, L1_WITHDRAWAL, BUNDLE_ID, SIDECHAIN,
    SEQUENCE, TRANSACTION, ACKNOWLEDGEMENT, L1, SIDECHAIN_BLOCK, BLOCK_HASH, HEIGHT, TIMESTAMP,
    BMM_REQUEST, HEX, TWO_WAY_PEG_REQUEST
};
// Views are borrowed only for the duration of append, outside any interpreter call.
void EventFields(EventLayoutKind kind, uint32_t status,
    const std::function<void(uint32_t, std::string_view, std::optional<std::string_view>)>& append);
std::string EventIdentity(EventIdentityKind kind, const std::string& hash, uint64_t number, uint32_t status = 0);
int64_t PegEvent(PegEventKind kind, int64_t a, int64_t b, int64_t c = 0);
int64_t WithdrawalStatus(int64_t state, const std::string& status);
void WithdrawalStatusFlow(const std::function<bool(uint32_t)>& action);
void L1NormalizationFlow(const std::function<bool(uint32_t)>& action);
void SidechainEventFlow(const std::function<bool(uint32_t)>& action);
void L1LocationFlow(const std::function<bool(uint32_t)>& action);
enum class PegSchemaKind : uint32_t { TYPE, INTEGER, HEX, FIELD, NULL_DEFAULT, FALSE_BOOLEAN, GUARDED };
bool PegSchema(PegSchemaKind kind, uint64_t limit, const std::function<uint64_t(uint32_t)>& read);
void ReadWhen(bool present, const std::function<void()>& read);
uint32_t ParentReplaySchema(uint32_t rule, uint32_t unique_version, uint32_t reproposal_version);
enum class ReplayRecordKind : uint32_t { DEPOSIT = 1, EDGE, WITHDRAWAL, HEIGHT, PROPOSAL_VOTES, WITHDRAWAL_VOTES, AMOUNT, ADVANCEABLE_HEIGHT, SUCCESSOR_HEIGHT, POSITIVE, LESS, SNAPSHOT, MTP_SAMPLE, PERIODIC_DEADLINE, SIGNED_POSITIVE, CHECKPOINT_CTIP, ACTIVATION_WINDOW, CTIP_BALANCE, PROPOSAL_EXPIRED, ANCHOR_EPOCH, EPOCH_CHANGED, SIGNED_HEIGHT_WINDOW, CONFIGURED_SLOT, AMOUNT_SUM, CACHE_EXPIRED = 27, LANE_EXCEEDED, NONEMPTY_BOUNDED, CURRENT_EPOCH = 31, SIGNED_PREDECESSOR };
bool ParentReplayRecord(ReplayRecordKind kind, uint32_t flags, int64_t value = 0, uint64_t first = 0, uint64_t second = 0);
enum class OutputTotalMode { DEFERRED, AGGREGATE, PER_ASSET, REJECT };
enum class DepositRoute { FEDERATED, NATIVE, ECX, REJECT_ECX, REJECT_FEDERATED };
struct DepositRouting { DepositRoute route; uint32_t expected_stack_size; };
DepositRouting SelectDepositRoute(uint64_t count, bool legacy_marker, bool native_marker, bool configured_slot);
OutputTotalMode SelectOutputTotalMode(bool deferred, bool per_asset, bool explicit_asset);
bool RejectParentResult(bool invalid, bool unavailable);
enum class ReplayStoreFlow : uint32_t {
    READ_RECORD, LOAD, LOAD_PREFLIGHT, RESET_PREFLIGHT, RESET,
    READ_PREFLIGHT, OCCURRENCE_PREFLIGHT, DEPOSIT, EDGE, WITHDRAWAL, OCCURRENCE, APPEND, IDENTITY,
    CACHE_CONFIG, CACHE_MATCH, CACHE_PREFLIGHT, CACHE_LOAD, BOOTSTRAP_PREIMAGE, CACHE_REBUILD,
    REPLAY_PREFLIGHT, REPLAY_PUBLISH, REPLAY_ADVANCE, REPLAY_BUDGET, REPLAY_SNAPSHOT, REPLAY_LOCK,
    PARENT_DEADLINE, PARENT_CIRCUIT, MILESTONE_HASH, MILESTONE,
    EXACT_MESSAGE, PINNED_STATE, SINGLE_PUSH, EXACT_ADDRESS, CANONICAL_HASH,
    HEIGHT_PREFLIGHT, HEIGHT_PARSE, PARENT_POW, BLOCK_PROOF, CHAINWORK,
    RAW_PREFLIGHT, RAW_DECODE, RAW_POSTFLIGHT, RAW_REQUEST, MEDIAN_TIME, HEADER_METADATA, HEADER_PREDECESSOR,
    VERIFIED_HEADER, BLOCK_TRANSACTIONS, BLOCK_SIGNET, VERIFIED_BLOCK, RECOVERY_DEADLINE, SIGNET_MERKLE, PARENT_SIGNET, WARM_PARENT, RPC_REPLY, AUTH_RETRY, RPC_TIMEOUT, COOKIE_CACHE, CREDENTIAL_SOURCE, CREDENTIAL_LOAD, CHECKPOINT_IDENTITY, HEADER_MTP,
    PROPOSAL_CONSISTENCY, OTHER_SLOT_PREFLIGHT, PRIOR_M4_PREFLIGHT, COINBASE_PREFLIGHT, M8_ACCEPTANCE, COINBASE_MESSAGES, PROPOSAL_ACK,
    PROPOSAL_INSERT, WITHDRAWAL_PROPOSAL, M4_UPVOTE, M4_ALARM, M4_LEADER, M4_EXPLICIT, M4_REPEAT,
    EXPIRE_PROPOSALS, EXPIRE_WITHDRAWALS, CTIP_OWNERS, CTIP_SPENDS, CTIP_OUTPUTS, CTIP_REPLACEMENTS, CTIP_CHANGES, M5_DEPOSIT, M6_WITHDRAWAL,
    PRUNE_SLOTS, BLOCK_PUBLISH, M6_ID, M4_MODE, ACTIVE_SLOTS, EACH, MESSAGE_DISPATCH, M8_PARSE,
    CONFIRMED_DEPOSIT, DEPOSIT_PREFLIGHT, WITHDRAWAL_LOOKUP, EXECUTION_ANCHOR, MEMPOOL_CONTEXT,
    BLOCK_PARENT_CONTEXT, EXTEND_PARENT_CONTEXT, BMM_BLOCK_PREFLIGHT, BMM_CONTEXT_RESULT,
    ANCHOR_RECONCILE, SNAPSHOT_MATCH, SNAPSHOT_ADD, SNAPSHOT_CONTAINS,
    SNAPSHOT_EPOCH_FENCE, SNAPSHOT_TIP_FENCE, SNAPSHOT_WARM_ANCHOR, SNAPSHOT_WARM,
    ANCHOR_PREFLIGHT, SNAPSHOT_WARM_PREFLIGHT, VERIFIED_PARENT_CONTEXT, PARENT_PROBE_ERROR,
    PARENT_PROBE_METADATA, BMM_EDGE_RECHECK, BMM_CACHE_PREFLIGHT, BMM_CACHE_HIT, BMM_CACHE_KEY,
    BMM_UNTRUSTED_ADMISSION, BMM_PROBE_RESULT, BMM_PUBLICATION, BMM_SUCCESSOR, AUTHENTICATED_JSON,
    BMM_BID_PREFLIGHT, BMM_BID_TXID, BLOCK_ADMISSION, TRANSACTION_REPLAY, BLOCK_REPLAY, USDD_GENESIS, USDD_ACCUMULATOR_CONNECTION, USDD_CHECKPOINT_CONNECTION, WITHDRAWAL_DESTINATION, WITHDRAWAL_BUNDLE, WITHDRAWAL_EVENT, WITHDRAWAL_SUBMISSION, WITHDRAWAL_OUTPUT, DEPOSIT_BROADCAST, DEPOSIT_SATOSHIS, DEPOSIT_SPONSORSHIP, DEPOSIT_IMPORT, DEPOSIT_NATIVE_IMPORT, DEFAULT_WALLET, WITHDRAWAL_PREFLIGHT, GRPC_CONFIG, GRPC_REQUEST, GRPC_EXECUTABLE, RPC_SERVER, CREDENTIAL, EXCHANGE_SOURCE_TRANSACTION, EXCHANGE_BLOCK_SOURCES, EXCHANGE_ISSUANCE, BOND_ISSUANCE, PUBLIC_BOND_ISSUANCE, EXPLICIT_CREATIONS, ACTIVATION_PREDECESSOR
    , FINITE_CONTEXT, INCREMENTAL_CONTEXT, HEADER_INACTIVE, HEADER_ACTIVE, HEADER_GENESIS, SUCCESSOR_SCAN, GENESIS_ADMISSION, CAPITAL_PROJECTION, FROZEN_ADMISSION, STARTUP_DEPLOYMENT, CONFIGURATION_BINDING, IDENTITY_FILE_CHECK, IDENTITY_FILE_RESET, IDENTITY_BINDING, IDENTITY_AUDIT, IDENTITY_TREE, IDENTITY_ANCESTRY, IDENTITY_COINS, IDENTITY_WRITE, MATERIAL_SCAN, MATERIAL_LOCATIONS, WITHDRAWAL_JOURNAL_READ, WITHDRAWAL_JOURNAL_WRITE, WITHDRAWAL_JOURNAL_CLEAR, WITHDRAWAL_RPC_BURN, WITHDRAWAL_RPC_CLAIM, WITHDRAWAL_RPC_VERIFY
    , RETIRED_BMM_GRPC_SUBMISSION, CHILD_MONITOR, CHILD_GRACE, CHILD_REAP, CHILD_DRAIN, CONFIGURATION_TRANSACTIONS, CONFIGURATION_COVENANTS, RECOVERY_PEER, RECOVERY_BODY, RECOVERY_PRUNED, RECOVERY_REPLY, RECOVERY_HEADER, RECOVERY_PEER_REPLY, CREDENTIAL_FILE, GRPC_REQUEST_ADMISSION, WALLET_REFRESH, WALLET_SEND_PREFLIGHT, WALLET_SEND_RESULT, WALLET_ISSUE_PREFLIGHT, WALLET_ISSUE_RESULT, PEER_BLOCK
    , PEER_TIMER, PEER_HEADERS, PEER_DISPATCH, INDEX_DERIVED, INDEX_CONTINUITY, INDEX_CAPITAL
    , HEADER_AUTHENTICATION, PARENT_CONTEXT_ADMISSION, ACTIVATION_POLICY, TEMPLATE_PARENT, TEMPLATE_ADMISSION, TEMPLATE_SELECTION, TEMPLATE_VERSION, TEMPLATE_ENVELOPE, FEE_FREE_SELECTION, CHILD_CHECKPOINT
    , CHECKPOINT_METADATA, CHECKPOINT_CLAIM, CHECKPOINT_COIN_KEY, CHECKPOINT_COIN_VALUE, RPC_BMM_AUTHENTICATION, RPC_BMM_SOURCE, RPC_BLOCK_PREPARATION, RPC_WITHDRAWAL_HISTORY, CHILD_PREFLIGHT, PERIODIC_REVERIFICATION, SYNC_PREFLIGHT, SYNC_LOOP, BID_PARENT, WALLET_COMMAND, BMM_MINED_PREFLIGHT, CONFIGURED_SLOT, BMM_CACHE_ROUTING, REQUIRED_PROPOSAL, REQUIRED_PAIR, CONFIGURED_BID, PARSED_BID, FUNDED_SUBMISSION, COMMITMENT_PROBE, SUCCESSOR_PROBE, TEMPLATE_CREATION, REWARD_WALLET
    , FROZEN_PROFILE, CAPITAL_DECODE, REQUIRED_QUAD, CONNECTION_PREFLIGHT, DISCONNECT_PREFLIGHT, SINGLETON_RECOVERY, HEADER_CHECK, HEADER_PREPARE, EXPECTED_CONTEXT, INCREMENTAL_SCAN, PARENT_REQUEST, BUNDLE_EVENT_CHECK, BUNDLE_EVENT_CLEAR, CAPITAL_REPORT, PARENT_REPORT, EXPORT_RECONSTRUCT, AUTHENTICATED_HEIGHT
    , WITNESS_ANNEX, PEER_REQUEST, PEER_SYNC, RESERVED_INPUTS, FEE_FREE_DEPOSIT, NATIVE_DEPOSIT_ADMISSION, EVALUATOR_SOURCE, NATIVE_WITHDRAWAL_SUBMISSION, BOND_CONTEXT_ADMISSION, ACTIVATION_ANCHOR, CREDENTIAL_RECORD, ANNEX_ACCOUNTING, PEER_BLOCK_DISPATCH, CAPITAL_CONNECTION, MEMPOOL_WITNESS, PRELIMINARY_WITNESS, CANONICAL_MATCH, EXPLICIT_VOTE, PARENT_CONTEXT, BLOCK_DEPOSIT_PREFLIGHT
    , BRANCH_REPLAY, RECOVERY_ANCESTOR, RECOVERY_ADMISSION, EPHEMERAL_HEADER, CONNECTION_ANCHOR, CONNECTION_STATE, LEGACY_MARKER, MARKER_AUTHENTICATION, STARTUP_PARENT, EXPORT_INITIALIZE, EXPORT_RECHECK, REQUIRED_PAIR_ERRORS, RPC_WITHDRAWAL_PROOF, CONNECTION_CONTEXT, SNAPSHOT_PREPARE, ANCHOR_CACHE, ANCHOR_PUBLISH, ANCHOR_DISCONNECT, CANDIDATE_ADMISSION, SNAPSHOT_BACKLOG, ANCHOR_REPLACEMENT, RECONCILIATION_GATE, ANCHOR_ORDER, ANCHOR_COLLECT
    , PRODUCTION_ROUTING, BLOCK_PREPARATION, BLOCK_ACCEPTANCE, MEMPOOL_SWEEP_PREFLIGHT, PARENT_RPC_HOST
    , FULL_BLOCK_PREFLIGHT, BLOCK_ANCHOR_ADMISSION, BLOCK_ANCHOR_PUBLICATION
    , STARTUP_PARENT_LOAD, STARTUP_PARENT_VERIFY, STARTUP_BUNDLE
    , CONTEXTUAL_HEADER, CONTEXTUAL_OUTPUTS, CANDIDATE_SELF_CHECK
    , BRANCH_CHOICE, STARTUP_RECONCILE, EXCHANGE_PARENT
    , FINAL_BMM, BMM_FAILURE, BOND_TREE, BLOCK_REPLAY_COMPOSED, BLOCK_REPLAY_PRELUDE
    , RPC_CREDENTIALS_COMPOSED, RPC_TIMEOUT_COMPOSED
    , RPC_CALL, RPC_CALL_CHECKED
    , CACHE_INITIALIZE, RECOVERY_COMPOSED
};
uint32_t ParentReplayStore(ReplayStoreFlow kind, const std::function<int64_t(uint32_t)>& action);
// Condition, true branch, false branch; only the selected branch is evaluated.
bool ParentReplayChoose(const std::array<std::function<bool()>,3>& actions);
// Bind lazy facts; Haskell owns their order, short-circuiting and acceptance.
template <size_t N>
bool ParentReplayAll(const std::array<std::function<bool()>, N>& facts)
{
    static_assert(N >= 2 && N <= 4);
    constexpr ReplayStoreFlow flows[]{ReplayStoreFlow::REQUIRED_PAIR,
        ReplayStoreFlow::REQUIRED_PROPOSAL, ReplayStoreFlow::REQUIRED_QUAD};
    return ParentReplayStore(flows[N - 2], [&](uint32_t step) -> uint32_t {
        if (step == N + 1) return 0;
        if (step == 0 || step > N) throw std::logic_error("invalid required fact action");
        return facts[step - 1]();
    });
}
bool BmmReplacementBid(const std::string& message, int64_t current, int64_t maximum, int64_t& replacement);
int64_t BmmSelectedBid(int64_t configured, int64_t fees);
uint32_t PeerRejectionStrikes(bool complete, bool same_edge, uint32_t count);
uint32_t NextExtraNonce(bool same_parent, uint32_t current);
int32_t NextBlockHeight(bool present, int32_t height);
int32_t ExchangeTrackerHeight(bool previous, int32_t height);
uint64_t NextBondContextHeight(int32_t height);
bool ApprovingParentHeight(int64_t parent, uint64_t& successor);
int BmmRewardAddress(const std::function<bool(uint32_t)>& read);
bool BmmWait(const std::function<int32_t(uint32_t)>& action);
bool BmmProduction(bool ecx, const std::function<bool(uint32_t)>& action);
bool BmmSyncTick(int64_t parent, int64_t child, const std::function<bool(uint32_t)>& action);
void BmmProofBuild(uint64_t previous, int64_t parent, const std::function<bool(uint32_t,uint64_t)>& action);
void ConstructDepositEvidence(int64_t sequence, int64_t height, uint32_t flags, int32_t slot, const NativeWorkflow& native);
void DepositVerify(uint64_t index, uint64_t inputs, uint64_t witnesses, const std::function<bool(uint32_t)>& action);
bool FeeAsset(const std::optional<std::string>& configured, bool canonical,
    std::span<const unsigned char,32> pegged, std::span<unsigned char,32> output, std::string* error);
// Callbacks run synchronously; false admission/action stops before advancement.
template <typename Condition, typename Action, typename Advance>
bool ParentReplayWhile(Condition&& condition, Action&& action, Advance&& advance)
{
    return ParentReplayStore(ReplayStoreFlow::EACH, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return bool(condition());
        case 2: return bool(action());
        case 3: advance(); return 1;
        default: throw std::logic_error("invalid replay traversal action");
        }
    });
}
// Like a short-circuiting range-for; the action must not invalidate its iterators.
template <typename Range, typename Action>
bool ParentReplayEach(Range&& range, Action&& action)
{
    auto entry = std::begin(range);
    const auto end = std::end(range);
    return ParentReplayWhile([&] { return entry != end; },
        [&] { return bool(action(*entry)); }, [&] { ++entry; });
}
using PegFields = int32_t (*)(void*, uint32_t, int64_t*);
bool LiveEvidence(LiveEvidencePhase phase, PegFields read, void* context,
    const std::string& parse_error, std::string& error);
bool DepositPreflight(uint32_t rule, int64_t amount, int64_t bound);
// 0: confirmed broadcast, 1: mempool broadcast, 2: fatal CTIP lookup failure.
bool DepositMessageMatches(uint32_t kind, const std::string& message);
bool TreasuryDelta(int64_t previous, int64_t current, int64_t claimed, int64_t maximum);
uint64_t CountMatches(uint64_t count, const std::function<bool(uint64_t)>& matches);
enum class MatchResult { UNIQUE, MISSING, DUPLICATE };
MatchResult FindUniqueMatch(uint64_t count, const std::function<bool(uint64_t)>& matches, uint64_t& index);
int DepositMatch(int64_t slot, int64_t amount, int64_t bound, bool has_address, const std::function<int64_t(uint32_t)>& fact);
enum class ReplayMaintenance : uint32_t { BEFORE_TREASURY, AFTER_TREASURY };
int M6Id(uint64_t outputs, uint64_t inputs, int64_t previous, int64_t maximum, bool has_slot,
    const std::function<int64_t(uint32_t,uint64_t)>& action);
using DestinationInspect = int32_t (*)(void*, uint32_t, uint32_t);
enum class DepositStatePhase : uint32_t {
    CHECK_CHECKPOINT, CHECK_PRIOR, CONNECT_PRIOR, DISCONNECT_PRESENT,
    DISCONNECT_CHECKPOINT, DISCONNECT_CURRENT, CHECK_CHECKPOINT_ANCHOR, CHECK_ANCHOR,
};
enum class DepositVerifyStep : uint32_t {
    CHECKPOINT = 1, CHECKPOINT_STATE, BUILD_CHECKPOINT, VERIFY_CHECKPOINT,
    HAS_WITNESS, LEGACY_WITNESS, REJECT_LEGACY, PARSE, PRIOR_STATE, VERIFY,
    ANCHOR_START, ANCHOR_CHECKPOINT, CHECKPOINT_ANCHOR, ANCHOR_HAS_WITNESS,
    ANCHOR_LEGACY_WITNESS, PARSE_ANCHOR, CHECK_ANCHOR, REJECT_ANCHOR,
    CONNECT_START, CONNECT_CHECKPOINT, CONNECT_BUILD, CONNECT_VERIFY, CONNECT_PUBLISH_CHECKPOINT,
    CONNECT_PARSE, CONNECT_PRIOR, CONNECT_PUBLISH_NEXT,
    DISCONNECT_START, DISCONNECT_PRESENT, DISCONNECT_CHECKPOINT, DISCONNECT_CHECK,
    DISCONNECT_REMOVE, DISCONNECT_PARSE, DISCONNECT_CURRENT, DISCONNECT_RESTORE,
    PARSE_START, INPUT_BOUNDS, WITNESS_BOUNDS, REJECT_INDEX, READ_EVIDENCE,
    DECODE_DEPOSIT, DECODE_PREVIOUS, DECODE_PROOF, REJECT_ENCODING, INCLUSION,
    SET_ANCHOR, FIND_PREVIOUS, READ_WITNESS, CTIP, DESTINATION, PUBLISH_PARSED,
    SCAN_START, SCAN_BOUNDS, SCAN_HASH, SCAN_OUTPUT_BOUNDS, SCAN_SCRIPT,
    SCAN_MATCH, SCAN_ADVANCE, SCAN_PRESENT, SCAN_VALUE, SCAN_EMPTY,
    AUTH_START, AUTH_NETWORK, AUTH_IDENTITY, AUTH_DEPOSIT, AUTH_CTIP, AUTH_PUBLISH,
    LOOKUP_START, LOOKUP_INPUT, LOOKUP_WITNESS, LOOKUP_MATCH, LOOKUP_PUBLISH,
    CLAIM_START, CLAIM_WITNESS, CLAIM_DESTINATION, CLAIM_VERIFY, CLAIM_PUBLISH,
    CTIP_READ_START, CTIP_READ_PRESENT, CTIP_READ_DECODE, CTIP_READ_ERROR_TARGET, CTIP_READ_ERROR, CTIP_READ_PUBLISH,
};
enum class DepositWorkflow : uint32_t { VERIFY = 0, ANCHOR = 11, CONNECT = 19, DISCONNECT = 27 };
uint32_t DepositStateFacts(bool present, bool matches, const std::string& decode_error);
bool RunDepositStateWorkflow(DepositWorkflow kind, const std::function<uint32_t(DepositVerifyStep)>& action,
    const std::string& decode_error, std::string& error);
bool RunDepositAuthentication(const std::function<bool(DepositVerifyStep)>& action);
bool RunCtipRead(const std::function<bool(DepositVerifyStep)>& action);
using TransactionHash = int32_t (*)(const unsigned char*, uint32_t, unsigned char*);
using EvidenceDecode = int32_t (*)(void*, int64_t*);
enum class DepositClaimWorkflow : uint32_t { CHECKPOINT, LEGACY, TRANSACTION };
bool RunDepositClaim(DepositClaimWorkflow kind, uint64_t inputs, uint64_t index, uint64_t witnesses,
    uint64_t outputs, std::span<const std::vector<unsigned char>> stack, const unsigned char* asset,
    const unsigned char* genesis, const unsigned char* prevout, TransactionHash hash_transaction,
    const NativeWorkflow& native, std::string& error);
bool ReadPersistedCtip(uint32_t facts, int64_t amount, const std::function<int32_t(uint32_t)>& read,
    EvidenceDecode decode, void* context, std::string& error);
using ParentHeaderCheck = int32_t (*)(void*, uint32_t);
bool ParseDeterministicDeposit(uint64_t inputs, uint64_t index, uint64_t witnesses,
    std::span<const std::vector<unsigned char>> stack, const unsigned char* asset,
    const unsigned char* genesis, const unsigned char* prevout, TransactionHash hash_transaction,
    EvidenceDecode decode, void* context, const NativeWorkflow& native, std::string& error);
// Callbacks are synchronous upstream codec adapters; no pointer may escape.
bool DepositEvidence(std::span<const std::vector<unsigned char>> stack, const unsigned char* prevout,
    TransactionHash hash_transaction, EvidenceDecode decode, void* context, std::string& error);
// 0 invalid, 1 historical v1, 2 native, 3 deterministic v2. Modes: 0 all,
// 1 historical/deterministic only, 2 native only. Value is unchanged on rejection.
int32_t DepositWitness(std::span<const std::vector<unsigned char>> stack, uint32_t mode,
    const unsigned char* asset, const unsigned char* genesis, const unsigned char* prevout,
    TransactionHash hash_transaction, int64_t& value);
enum class NativeRecipient : uint32_t { DECODE, ENCODE, CONSTRUCT };
bool RunNativeRecipient(NativeRecipient kind, int64_t amount, std::string_view source, const NativeWorkflow& native);
bool CheckNativeDeposit(const CTransaction& tx, uint64_t index, bool canonical,
    const unsigned char* asset, const unsigned char* genesis, TransactionHash hash_transaction,
    const NativeWorkflow& native, std::string& error);
// -1 means invalid script; 0..255 is the decoded slot.
int32_t TreasurySlot(uint32_t script, uint32_t opcode);
bool TreasuryMatches(std::span<const unsigned char> script, uint32_t opcode, int32_t expected);
// Positive payout, or -1 (burn), -2 (fee), -3 (burn <= fee).
enum class WithdrawalOp : uint32_t {
    BUILD_SCRIPT = 1, PARSE_SCRIPT, BUILD_REFERENCE, PARSE_REFERENCE, LEGACY_FRAME,
    DECODE_FEE, ENCODE_FEE, BUILD_OUTPUT, PARSE_OUTPUT, BUILD_M6, PARSE_M6, EXTRACT_ETHEREUM_CLAIM, STATE_ANCHOR, WALLET_BUNDLE, WALLET_ANCHOR, STATE_MARKER, WALLET_TRANSPORT, RPC_FEE, EVENT_POLICY, BUNDLE_ADMISSION, NATIVE_AMOUNT, PARENT_DUST, NATIVE_GUARD, NATIVE_GUARD_RESULT, INPUTS_COMMITMENT, NATIVE_PAYOUT, NATIVE_BURN_PLAN, NATIVE_OUTPUT_SELECTION,
    JOURNAL_ADMISSION, PARENT_POLICY, RPC_ADMISSION, SUBMISSION_POLICY, PROOF_BOUNDS, JOURNAL_LEGACY, JOURNAL_IDENTITY,
};
std::vector<unsigned char> WithdrawalTransport(std::span<const unsigned char> transaction, bool strip_marker = false);
struct WithdrawalEventDecision { uint8_t rejection; bool clear; };
struct WithdrawalBundleAdmission { bool begin; bool clear; };
WithdrawalBundleAdmission AdmitWithdrawalBundle(bool busy, const unsigned char* current, const unsigned char* requested);
bool WithdrawalBytes(WithdrawalOp op, std::span<const unsigned char> input,
                     std::vector<unsigned char>& output, std::string* error);
} // namespace drivechain::haskell
#endif
