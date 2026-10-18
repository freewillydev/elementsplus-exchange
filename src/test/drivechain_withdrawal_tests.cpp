// Copyright (c) 2026 The Elements developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <drivechain_withdrawal.h>

#include <asset.h>
#include <coins.h>
#include <consensus/amount.h>
#include <haskell/bridge.h>
#include <haskell/bmm_constants.h>
#include <init.h>
#include <mainchainrpc.h>
#include <node/context.h>
#include <node/drivechain_withdrawal_bundle.h>
#include <primitives/txwitness.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>
#include <util/moneystr.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace Bitcoin = Sidechain::Bitcoin;

namespace {

struct NativeWithdrawalSetup : public BasicTestingSetup
{
    NativeWithdrawalSetup() : BasicTestingSetup(ChainType::CUSTOM) {}
};

const CAsset PEGGED_ASSET{uint256S(
    "11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff")};
const CAsset OTHER_ASSET{uint256S(
    "ffeeddccbbaa00998877665544332211ffeeddccbbaa00998877665544332211")};
const uint256 PARENT_GENESIS{uint256S(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")};
const uint256 ELEMENTS_GENESIS{uint256S(
    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")};
const uint256 BURN_TXID{uint256S(
    "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f")};
const CScript DESTINATION = CScript() << OP_0 << ParseHex(
    "606162636465666768696a6b6c6d6e6f70717273");

drivechain::NativeWithdrawal BuildAndParseWithdrawal(const CAmount burn_amount = 100000,
                                                      const CAmount parent_fee = 1000)
{
    CTxOut output;
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        drivechain::BuildNativeWithdrawalOutput(
            PEGGED_ASSET, PARENT_GENESIS, DESTINATION,
            burn_amount, parent_fee, output, &error),
        error);
    drivechain::NativeWithdrawal withdrawal;
    BOOST_REQUIRE_MESSAGE(
        drivechain::ParseNativeWithdrawalOutput(
            output, nullptr, PEGGED_ASSET, PARENT_GENESIS,
            withdrawal, &error),
        error);
    return withdrawal;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(drivechain_withdrawal_tests, NativeWithdrawalSetup)

BOOST_AUTO_TEST_CASE(bundle_event_clearing_preserves_terminal_policy_and_exceptions)
{
    namespace hs = drivechain::haskell;
    for (bool present : {false,true}) for (const std::string status : {"", "pending", "failed", "succeeded"}) {
        unsigned fetched{0}, cleared{0};
        BOOST_CHECK_EQUAL(hs::ParentReplayStore(hs::ReplayStoreFlow::BUNDLE_EVENT_CLEAR,
            [&](uint32_t step) -> uint32_t {
                switch (step) {
                case 1: return present;
                case 2: ++fetched; return 1;
                case 3: return hs::ClassifyWithdrawalEvent(status).clear;
                case 4: ++cleared; return 1;
                default: throw std::logic_error("unexpected bundle clear step");
                }
            }), 1);
        BOOST_CHECK_EQUAL(fetched, unsigned{present});
        BOOST_CHECK_EQUAL(cleared, unsigned{present && (status == "failed" || status == "succeeded")});
    }
    for (const auto flow : {hs::ReplayStoreFlow::BUNDLE_EVENT_CLEAR, hs::ReplayStoreFlow::BUNDLE_EVENT_CHECK}) {
        unsigned calls{0};
        // RPC errors are UniValue exceptions, not necessarily std::exception.
        BOOST_CHECK_THROW(hs::ParentReplayStore(flow, [&](uint32_t step) -> uint32_t {
            ++calls;
            if (step == 2) throw 42;
            return 1;
        }), int);
        BOOST_CHECK_EQUAL(calls, 2U);
    }
}

BOOST_AUTO_TEST_CASE(haskell_rpc_claim_effect_order)
{
    using namespace drivechain::haskell;
    for (uint32_t fault : {0U,1U,3U,4U,5U,7U,9U,11U}) {
        auto withdrawal = BuildAndParseWithdrawal();
        drivechain::NativeWithdrawalM6 built, parsed, published;
        std::string error;
        std::vector<uint32_t> trace;
        const std::vector<uint32_t> success{1,3,4,5,7,8,9,11};
        auto expected = success;
        if (fault) {
            expected.erase(std::find(expected.begin(),expected.end(),fault)+1,expected.end());
            if (fault == 1) expected.push_back(2);
            else if (fault >= 3 && fault <= 5) expected.push_back(6);
            else if (fault == 9) expected.push_back(10);
        }
        const auto execute = [&] {
            return ParentReplayStore(ReplayStoreFlow::WITHDRAWAL_RPC_CLAIM,[&](uint32_t action) -> uint32_t {
                trace.push_back(action);
                switch (action) {
                case 1: return drivechain::BuildNativeWithdrawalM6(ELEMENTS_GENESIS,24,BURN_TXID,0,withdrawal,built,&error) && fault != 1;
                case 3: return drivechain::ParseNativeWithdrawalM6(built.blinded_transaction,ELEMENTS_GENESIS,24,BURN_TXID,0,parsed,&error) && fault != 3;
                case 4: return parsed.m6id == built.m6id && fault != 4;
                case 5: return parsed.legacy_serialization == built.legacy_serialization && fault != 5;
                case 7:
                case 11:
                    if (fault == action) throw std::runtime_error("anchor changed");
                    return 1;
                case 8: published = std::move(built); return 1;
                case 9:
                    BOOST_CHECK(!published.legacy_serialization.empty());
                    return fault != 9;
                case 2:
                case 6:
                case 10: throw std::runtime_error("claim rejected");
                default: throw std::logic_error("unexpected claim action");
                }
            });
        };
        if (fault) BOOST_CHECK_THROW(execute(),std::runtime_error);
        else BOOST_CHECK_EQUAL(execute(),1U);
        BOOST_CHECK(trace == expected);
        BOOST_CHECK_EQUAL(published.legacy_serialization.empty(),fault != 0 && fault < 8);
    }
}

BOOST_AUTO_TEST_CASE(withdrawal_submission_result_policy)
{
    using namespace drivechain::haskell;
    for (unsigned flags = 0; flags < 256; ++flags) {
        const auto has = [&](unsigned bit) { return (flags & bit) != 0; };
        const unsigned expected = has(1) ? 4 : !has(2) ? 5 : has(4) ? 6 :
            has(8) ? 7 : has(16) ? 8 : !has(32) ? 9 : !(has(64) || has(128)) ? 10 : 0;
        const std::array<unsigned char,2> input{1,static_cast<unsigned char>(flags)};
        std::vector<unsigned char> output;
        BOOST_REQUIRE(WithdrawalBytes(WithdrawalOp::SUBMISSION_POLICY,input,output,nullptr));
        BOOST_REQUIRE_EQUAL(output.size(),1U);
        BOOST_CHECK_EQUAL(output[0],expected);
    }
}

BOOST_AUTO_TEST_CASE(bmm_replacement_parser_reference)
{
    const auto reference = [](const std::string& error,CAmount current,CAmount maximum,CAmount& replacement) {
        if (current <= 0 || !MoneyRange(current) || !MoneyRange(maximum) || current >= maximum) return false;
        if (error.find("insufficient fee, rejecting replacement ") == std::string::npos) return false;
        std::string marker{"not enough additional fees to relay; "};
        auto start = error.find(marker);
        if (start == std::string::npos) { marker = "less fees than conflicting txs; "; start = error.find(marker); }
        if (start == std::string::npos) return false;
        const auto value_start = start + marker.size();
        const auto separator = error.find(" < ",value_start);
        if (separator == std::string::npos) return false;
        std::string paid = error.substr(value_start,separator-value_start);
        const bool negative = !paid.empty() && paid.front() == '-';
        if (negative) paid.erase(0,1);
        const auto paid_amount = ParseMoney(paid);
        const auto needed_start = separator+3;
        const auto end = error.find_first_not_of("0123456789.",needed_start);
        if (end == needed_start || (end != std::string::npos && error[end] != '"' && error[end] != '\n')) return false;
        const auto needed = ParseMoney(error.substr(needed_start,end-needed_start));
        if (!paid_amount || !needed) return false;
        const CAmount delta = *needed - (negative ? -*paid_amount : *paid_amount);
        if (delta <= 0 || delta > maximum-current) return false;
        replacement = current+delta;
        return true;
    };
    for (const std::string marker : {"not enough additional fees to relay; ","less fees than conflicting txs; ","not enough additional fees to relay; invalid; less fees than conflicting txs; "})
    for (const std::string paid : {"0.00","-0.00000019","0.00000010","-","NaN"," 0.00","21000001"})
    for (const std::string needed : {"0.00000019","0.00","-1","0.000000001","21000001"})
    for (const std::string suffix : {"","\" tail","\n tail","garbage"," "})
    for (const CAmount current : {CAmount{-1},CAmount{1},CAmount{1000},MAX_MONEY})
    for (const CAmount maximum : {CAmount{1000},CAmount{2000},MAX_MONEY,MAX_MONEY+1}) {
        const auto message = "insufficient fee, rejecting replacement txid; " + marker + paid + " < " + needed + suffix;
        CAmount expected{42}, actual{42};
        BOOST_CHECK_EQUAL(ComputeDrivechainBmmReplacementBid(message,current,maximum,actual),reference(message,current,maximum,expected));
        BOOST_CHECK_EQUAL(actual,expected);
    }
}

BOOST_AUTO_TEST_CASE(retired_bmm_submission_rejects_without_effects)
{
    using namespace drivechain::haskell;
    static_assert(static_cast<uint32_t>(ReplayStoreFlow::RETIRED_BMM_GRPC_SUBMISSION)==183);
    static_assert(static_cast<uint32_t>(ReplayStoreFlow::CHILD_MONITOR)==184);
    unsigned calls{0};
    BOOST_CHECK_THROW(ParentReplayStore(ReplayStoreFlow::RETIRED_BMM_GRPC_SUBMISSION,
        [&](uint32_t) { ++calls; return 1U; }),std::runtime_error);
    BOOST_CHECK_EQUAL(calls,0U);
}

BOOST_AUTO_TEST_CASE(bmm_submission_typed_workflow)
{
    using namespace drivechain::haskell;
    for (unsigned parent_failure : {0U,1U,2U,3U})
    for (bool final_success : {false,true})
    for (bool duplicate : {false,true})
    for (CAmount cap : {1000,2000}) {
        unsigned attempts{0}, requests{0}, replacements{0}, replacement_checks{0};
        CAmount bid{1000};
        bool published{false};
        BoundedCommandResult child;
        std::string error;
        const int result = BmmSubmit(bid,cap,[&](uint32_t step, uint64_t value) -> int64_t {
            switch (step) {
            case 1: return parent_failure != ++attempts;
            case 2:
                ++requests;
                BOOST_CHECK_EQUAL(value,bid);
                child.started = child.exited = true;
                child.exit_code = final_success && requests == 3 ? 0 : 17;
                child.output = "insufficient fee, rejecting replacement txid, not enough additional fees to relay; 0.00 < 0.00000019";
                return ClassifyDrivechainGrpcResult(child,false,error) == DrivechainGrpcStatus::SUCCESS ? 2 : 1;
            case 3: {
                ++replacement_checks;
                BOOST_CHECK_LT(requests,3U);
                CAmount replacement{0};
                return ComputeDrivechainBmmReplacementBid(child.output,value,cap,replacement) ? replacement : 0;
            }
            case 4: bid = value; ++replacements; return 1;
            case 5: return duplicate;
            case 6:
                BOOST_CHECK_EQUAL(value,final_success && requests == 3 ? 1U : 0U);
                published = true;
                return 1;
            default: throw std::logic_error("unexpected typed submission action");
            }
        });
        const unsigned limit = cap == 1000 ? 1 : 3;
        const bool stale = parent_failure && parent_failure <= limit;
        const unsigned expected_requests = stale ? parent_failure-1 : limit;
        const bool accepted = !stale && (duplicate || (final_success && limit == 3));
        BOOST_CHECK_EQUAL(result,stale ? 1 : accepted ? 0 : 2);
        BOOST_CHECK_EQUAL(requests,expected_requests);
        BOOST_CHECK_EQUAL(replacements,cap == 1000 ? 0U : std::min(expected_requests,2U));
        BOOST_CHECK_EQUAL(replacement_checks,std::min(expected_requests,2U));
        BOOST_CHECK_EQUAL(bid,1000 + 19*replacements);
        BOOST_CHECK_EQUAL(published,accepted);
    }
}

BOOST_AUTO_TEST_CASE(bmm_submission_callback_containment)
{
    using namespace drivechain::haskell;
    for (uint32_t fault : {1,2,3,4,5,6})
    for (bool exception : {false,true}) {
        std::vector<uint32_t> trace;
        const auto run = [&] {
            return BmmSubmit(1000,2000,[&](uint32_t step, uint64_t value) -> int64_t {
                trace.push_back(step);
                if (step == fault) {
                    if (exception) throw std::logic_error("submission callback sentinel");
                    return std::numeric_limits<int64_t>::max();
                }
                if (step == 3) return fault >= 5 ? 0 : value+19;
                return 1;
            });
        };
        if (exception) BOOST_CHECK_EXCEPTION(run(),std::logic_error,[](const auto& error) {
            return std::string(error.what()) == "submission callback sentinel";
        });
        else BOOST_CHECK_THROW(run(),std::runtime_error);
        BOOST_REQUIRE(!trace.empty());
        BOOST_CHECK_EQUAL(trace.back(),fault);
        BOOST_CHECK_EQUAL(std::count(trace.begin(),trace.end(),fault),1);
    }
    for (const auto& [bid,cap] : std::vector<std::pair<int64_t,int64_t>>{{0,1},{-1,1},{2,1},{1,-1}}) {
        unsigned calls{0};
        BOOST_CHECK_THROW(BmmSubmit(bid,cap,[&](uint32_t, uint64_t) { ++calls; return 1; }),std::runtime_error);
        BOOST_CHECK_EQUAL(calls,0U);
    }
    unsigned calls{0};
    BOOST_CHECK_EQUAL(BmmSubmit(1000,2000,[&](uint32_t step, uint64_t) { ++calls; return step == 1 ? 1 : 0; }),2);
    BOOST_CHECK_EQUAL(calls,2U);
    const auto maximum = std::numeric_limits<int64_t>::max();
    unsigned requests{0};
    BOOST_CHECK_EQUAL(BmmSubmit(maximum-1,maximum,[&](uint32_t step, uint64_t value) -> int64_t {
        if (step == 2) {
            BOOST_CHECK_EQUAL(value,requests ? maximum : maximum-1);
            return ++requests == 2 ? 2 : 1;
        }
        if (step == 3) return maximum;
        if (step == 4) BOOST_CHECK_EQUAL(value,maximum);
        return 1;
    }),0);
    BOOST_CHECK_EQUAL(requests,2U);
}

BOOST_AUTO_TEST_CASE(bmm_submission_nested_process_boundary)
{
#ifndef WIN32
    for (bool timeout : {false,true}) {
        BoundedCommandResult child;
        std::string error;
        unsigned published{0};
        const int result = drivechain::haskell::BmmSubmit(1000,1000,[&](uint32_t step, uint64_t) -> int64_t {
            if (step == 1) return 1;
            if (step == 2) {
                child = RunBoundedCommand(timeout ? std::vector<std::string>{"/bin/sleep","2"} :
                    std::vector<std::string>{"/usr/bin/printf","nested-bmm"},
                    timeout ? std::chrono::milliseconds{25} : std::chrono::milliseconds{1000},128);
                return ClassifyDrivechainGrpcResult(child,false,error) == DrivechainGrpcStatus::SUCCESS ? 2 : 0;
            }
            BOOST_CHECK_EQUAL(step,6U);
            ++published;
            return 1;
        });
        BOOST_CHECK_EQUAL(result,timeout ? 2 : 0);
        BOOST_CHECK(child.started);
        BOOST_CHECK(child.exited);
        BOOST_CHECK_EQUAL(child.timed_out,timeout);
        BOOST_CHECK_EQUAL(published,timeout ? 0U : 1U);
        if (!timeout) BOOST_CHECK_EQUAL(child.output,"nested-bmm");
    }
#endif
}

BOOST_AUTO_TEST_CASE(grpc_submission_result_parity)
{
    for (unsigned flags = 0; flags < 256; ++flags) {
        for (bool accept_duplicate : {false,true}) {
          for (const std::string& message : {std::string{}, std::string{"failure"},
              std::string{"AlreadyExists"}, std::string{"prefix AlreadyExists suffix"},
              std::string{"alreadyexists"}, std::string{"AlreadyExist"},
              std::string{"Already\0Exists",14}, std::string{"\0AlreadyExists\0",15}}) {
            BoundedCommandResult child;
            child.cancelled = flags & 1;
            child.started = flags & 2;
            child.timed_out = flags & 4;
            child.output_truncated = flags & 8;
            child.error = flags & 16 ? "detail" : "";
            child.exited = flags & 32;
            child.exit_code = flags & 64 ? 0 : 17;
            child.output = flags & 128 ? message : "failure";
            std::string expected;
            auto expected_status = DrivechainGrpcStatus::PROCESS_FAILURE;
            if (child.cancelled) expected = "enforcer gRPC cancelled during shutdown";
            else if (!child.started) expected = "enforcer gRPC request rejected: " + child.error;
            else if (child.timed_out) expected = "enforcer gRPC exceeded its deadline";
            else if (child.output_truncated) expected = "enforcer gRPC exceeded its output limit";
            else if (!child.error.empty()) expected = "enforcer gRPC transport failed: " + child.error;
            else if (!child.exited) expected = "enforcer gRPC did not complete";
            else if (child.exit_code != 0) {
                expected = "enforcer gRPC status 17: " + child.output;
                expected_status = DrivechainGrpcStatus::NONZERO_EXIT;
            } else expected_status = DrivechainGrpcStatus::SUCCESS;
            std::string actual{"stale"};
            BOOST_CHECK(ClassifyDrivechainGrpcResult(child,accept_duplicate,actual) == expected_status);
            BOOST_CHECK_EQUAL(actual,expected);
          }
        }
    }
    BoundedCommandResult duplicate;
    duplicate.started = duplicate.exited = true;
    duplicate.output = "AlreadyExists: bundle exists";
    duplicate.exit_code = 6;
    std::string error;
    BOOST_CHECK(ClassifyDrivechainGrpcResult(duplicate,true,error) == DrivechainGrpcStatus::SUCCESS);
    BOOST_CHECK(ClassifyDrivechainGrpcResult(duplicate,false,error) == DrivechainGrpcStatus::NONZERO_EXIT);
    duplicate.exit_code = 7;
    BOOST_CHECK(ClassifyDrivechainGrpcResult(duplicate,true,error) == DrivechainGrpcStatus::NONZERO_EXIT);
}

BOOST_AUTO_TEST_CASE(withdrawal_submission_preflight)
{
    node::NodeContext node;
    for (const int slot : {-1,0,255,256}) {
        for (const size_t size : {size_t{0},size_t{1024*1024+1}}) {
            std::string response{"stale"}, error{"stale"};
            BOOST_CHECK(!SubmitDrivechainWithdrawalBundle(node,slot,std::vector<unsigned char>(size),&response,&error));
            BOOST_CHECK(response.empty());
            BOOST_CHECK_EQUAL(error,slot < 0 || slot > 255 ?
                "drivechain withdrawal slot is outside the BIP300 range" :
                "blinded withdrawal bundle must be between 1 byte and 1 MiB");
        }
    }
    BOOST_CHECK(!SubmitDrivechainWithdrawalBundle(node,-1,{},nullptr,nullptr));
}

BOOST_AUTO_TEST_CASE(haskell_rpc_verify_exception_boundary)
{
    using namespace drivechain::haskell;
    const std::vector<uint32_t> success{1,3,5,7,9,11,12,13,14,16,17};
    for (const auto fault : success) {
        std::vector<uint32_t> trace;
        const auto execute = [&] {
            return ParentReplayStore(ReplayStoreFlow::WITHDRAWAL_RPC_VERIFY,[&](uint32_t action) -> uint32_t {
                trace.push_back(action);
                if (action == fault) throw std::runtime_error("verification interrupted");
                return 1;
            });
        };
        BOOST_CHECK_EXCEPTION(execute(),std::runtime_error,[](const std::runtime_error& error) {
            return std::string(error.what()) == "verification interrupted";
        });
        const std::vector<uint32_t> expected(success.begin(),std::find(success.begin(),success.end(),fault)+1);
        BOOST_CHECK(trace == expected);
    }
    std::vector<uint32_t> trace;
    BOOST_CHECK_EQUAL(ParentReplayStore(ReplayStoreFlow::WITHDRAWAL_RPC_VERIFY,[&](uint32_t action) {
        trace.push_back(action);
        return 1U;
    }),1U);
    BOOST_CHECK(trace == success);
}

BOOST_AUTO_TEST_CASE(haskell_wallet_bundle_construction_boundary)
{
    using namespace drivechain::haskell;
    for (const auto amount : {int64_t{-1},int64_t{0},int64_t{1},int64_t{1000},int64_t{MAX_MONEY},int64_t{MAX_MONEY+1}})
    for (const auto fee : {int64_t{-1},int64_t{0},int64_t{1},int64_t{1000}})
    for (const auto size : {uint64_t{0},uint64_t{1},uint64_t{10000},uint64_t{10001}})
    for (const bool known : {false,true}) {
        unsigned calls{0};
        const std::vector<unsigned char> serialized{2,0,0,0,0,3,7};
        const bool accepted=amount>0 && amount<=MAX_MONEY && fee>=0 && fee<amount && size>0 && size<=10000 && known;
        const auto construct=[&](const WithdrawalBundlePlan& plan) -> const std::vector<unsigned char>& {
            ++calls;
            BOOST_CHECK_EQUAL(plan.payout,amount-fee);
            BOOST_CHECK_EQUAL(plan.fee_script.size(),10);
            BOOST_CHECK_EQUAL(plan.version,2);
            BOOST_CHECK(plan.outputs == std::vector<unsigned char>({0,1,2}));
            return serialized;
        };
        if (accepted) {
            const auto expected=WithdrawalTransport(serialized);
            const auto actual=BuildWithdrawalBundle(amount,fee,size,known,construct);
            BOOST_CHECK(actual==expected);
        } else BOOST_CHECK_THROW(BuildWithdrawalBundle(amount,fee,size,known,construct),std::invalid_argument);
        BOOST_CHECK_EQUAL(calls,accepted ? 1 : 0);
    }
    BOOST_CHECK_EXCEPTION(BuildWithdrawalBundle(100,1,1,true,[](const auto&) -> const std::vector<unsigned char>& {
        throw std::logic_error("native construction fault");
    }),std::logic_error,[](const auto& error) { return std::string(error.what())=="native construction fault"; });
    for (size_t size=0;size<4;++size) {
        const std::vector<unsigned char> short_reply(size);
        BOOST_CHECK_THROW(BuildWithdrawalBundle(100,1,1,true,[&](const auto&) -> const std::vector<unsigned char>& {
            return short_reply;
        }),std::runtime_error);
    }
}

BOOST_AUTO_TEST_CASE(haskell_wallet_bundle_commitment_context)
{
    using namespace drivechain::haskell;
    const std::vector<unsigned char> serialized{2,0,0,0};
    std::array<unsigned char,40> context{};
    for (size_t i=0; i<context.size(); ++i) context[i]=i;
    std::vector<unsigned char> expected{2};
    expected.insert(expected.end(),context.begin(),context.begin()+36);
    expected.insert(expected.end(),32,0);
    expected.insert(expected.end(),context.begin()+36,context.end());
    unsigned calls{0};
    const auto construct = [&](const WithdrawalBundlePlan& plan) -> const std::vector<unsigned char>& {
        ++calls;
        BOOST_CHECK(plan.inputs==expected);
        BOOST_CHECK_EQUAL(plan.version,2);
        BOOST_CHECK(plan.outputs == std::vector<unsigned char>({0,1,2}));
        return serialized;
    };
    BOOST_CHECK(BuildWithdrawalBundle(100,1,1,true,construct,context)==WithdrawalTransport(serialized));
    BOOST_CHECK_EQUAL(calls,1U);
    for (const size_t size : {1U,39U,41U}) {
        const std::vector<unsigned char> malformed(size,0);
        BOOST_CHECK_THROW(BuildWithdrawalBundle(100,1,1,true,construct,malformed),std::invalid_argument);
    }
    BOOST_CHECK_EQUAL(calls,1U);
    std::vector<unsigned char> payload;
    BOOST_REQUIRE(WithdrawalBytes(WithdrawalOp::INPUTS_COMMITMENT,context,payload,nullptr));
    BOOST_CHECK(payload==expected);
    for (const size_t size : {0U,1U,39U,41U}) {
        const std::vector<unsigned char> malformed(size,0);
        BOOST_CHECK_THROW(WithdrawalBytes(WithdrawalOp::INPUTS_COMMITMENT,malformed,payload,nullptr),std::runtime_error);
    }
}

BOOST_AUTO_TEST_CASE(bundle_creation_lifecycle)
{
    // Restore process-global state even when a required assertion aborts the test.
    struct ResetBundle {
        ~ResetBundle() { node::RestoreCurrentDrivechainWithdrawalBundleHash(uint256::ZERO); }
    } reset;
    node::RestoreCurrentDrivechainWithdrawalBundleHash(uint256::ZERO);
    uint256 current;
    bool busy{true};
    BOOST_REQUIRE(node::TryBeginDrivechainWithdrawalBundleCreation(current, busy));
    BOOST_CHECK(current.IsNull());
    BOOST_CHECK(!busy);
    BOOST_CHECK_EQUAL(drivechain::WITHDRAWAL_BUNDLE_RESERVE_ACTIONS[2U | unsigned{busy}][0], 1);
    BOOST_CHECK(!node::TryBeginDrivechainWithdrawalBundleCreation(current, busy));
    BOOST_CHECK(busy);
    BOOST_CHECK_EQUAL(drivechain::WITHDRAWAL_BUNDLE_RESERVE_ACTIONS[unsigned{busy}][0], 2);
    BOOST_CHECK(node::ClearCurrentDrivechainWithdrawalBundleHash(uint256::ZERO));
    BOOST_CHECK(!node::TryBeginDrivechainWithdrawalBundleCreation(current, busy));
    BOOST_CHECK(busy);
    node::AbortDrivechainWithdrawalBundleCreation();
    BOOST_REQUIRE(node::TryBeginDrivechainWithdrawalBundleCreation(current, busy));
    BOOST_CHECK(!busy);
    node::CompleteDrivechainWithdrawalBundleCreation(
        BURN_TXID, node::DrivechainWithdrawalBundleEnvelope{42, PARENT_GENESIS, {1, 2, 3}});
    BOOST_CHECK(!node::TryBeginDrivechainWithdrawalBundleCreation(current, busy));
    BOOST_CHECK(!busy);
    BOOST_CHECK(current == BURN_TXID);
    BOOST_CHECK_EQUAL(drivechain::WITHDRAWAL_BUNDLE_RESERVE_ACTIONS[unsigned{busy}][0], 3);
    auto envelope = node::GetCurrentDrivechainWithdrawalBundleEnvelope();
    BOOST_REQUIRE(envelope);
    BOOST_CHECK_EQUAL(envelope->checkpoint_height, 42U);
    BOOST_CHECK(envelope->checkpoint_block_hash == PARENT_GENESIS);
    BOOST_CHECK(envelope->m6_no_witness == std::vector<unsigned char>({1, 2, 3}));
    node::AbortDrivechainWithdrawalBundleCreation();
    BOOST_CHECK(!node::ClearCurrentDrivechainWithdrawalBundleHash(PARENT_GENESIS));
    BOOST_CHECK(node::GetCurrentDrivechainWithdrawalBundleHash() == BURN_TXID);
    BOOST_CHECK(node::GetCurrentDrivechainWithdrawalBundleEnvelope().has_value());
    BOOST_REQUIRE(node::ClearCurrentDrivechainWithdrawalBundleHash(BURN_TXID));
    BOOST_CHECK(!node::GetCurrentDrivechainWithdrawalBundleEnvelope());
    BOOST_REQUIRE(node::TryBeginDrivechainWithdrawalBundleCreation(current, busy));
    node::CompleteDrivechainWithdrawalBundleCreation(BURN_TXID);
    BOOST_CHECK(!node::TryBeginDrivechainWithdrawalBundleCreation(current, busy));
    BOOST_CHECK(!busy);
    BOOST_CHECK(current == BURN_TXID);
    BOOST_CHECK(!node::GetCurrentDrivechainWithdrawalBundleEnvelope());
    node::RestoreCurrentDrivechainWithdrawalBundleHash(uint256::ZERO);
    BOOST_REQUIRE(node::TryBeginDrivechainWithdrawalBundleCreation(current, busy));
    node::RestoreCurrentDrivechainWithdrawalBundleHash(uint256::ZERO);
    BOOST_CHECK(node::TryBeginDrivechainWithdrawalBundleCreation(current, busy));
    BOOST_CHECK(!busy);
}

BOOST_AUTO_TEST_CASE(native_burn_output_round_trip)
{
    CTxOut output;
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        drivechain::BuildNativeWithdrawalOutput(
            PEGGED_ASSET, PARENT_GENESIS, DESTINATION,
            100000, 1000, output, &error),
        error);

    BOOST_REQUIRE(output.nAsset.IsExplicit());
    BOOST_CHECK(output.nAsset.GetAsset() == PEGGED_ASSET);
    BOOST_REQUIRE(output.nValue.IsExplicit());
    BOOST_CHECK_EQUAL(output.nValue.GetAmount(), 100000);
    BOOST_CHECK(output.nNonce.IsNull());
    BOOST_CHECK(output.scriptPubKey.IsUnspendable());
    BOOST_CHECK_EQUAL(
        HexStr(output.scriptPubKey),
        "6a201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201"
        "00160014606162636465666768696a6b6c6d6e6f707172730800000000000003e8");

    // ConnectBlock reaches this same AddCoin primitive. Unspendable outputs
    // are deliberately never inserted into the UTXO set, so the pegged asset
    // cannot be recovered or spent after this transaction confirms.
    CCoinsView base;
    CCoinsViewCache coins(&base);
    const COutPoint burn_outpoint(Txid::FromUint256(BURN_TXID), 7);
    coins.AddCoin(burn_outpoint, Coin(output, 1, false), false);
    BOOST_CHECK(!coins.HaveCoinInCache(burn_outpoint));
    BOOST_CHECK(!coins.HaveCoin(burn_outpoint));

    CTxOutWitness empty_witness;
    drivechain::NativeWithdrawal parsed;
    BOOST_REQUIRE_MESSAGE(
        drivechain::ParseNativeWithdrawalOutput(
            output, &empty_witness, PEGGED_ASSET, PARENT_GENESIS,
            parsed, &error),
        error);
    BOOST_CHECK(parsed.parent_genesis == PARENT_GENESIS);
    BOOST_CHECK(parsed.destination == DESTINATION);
    BOOST_CHECK_EQUAL(parsed.burn_amount, 100000);
    BOOST_CHECK_EQUAL(parsed.parent_fee, 1000);
    BOOST_CHECK_EQUAL(parsed.payout_amount, 99000);
}

BOOST_AUTO_TEST_CASE(native_burn_output_rejects_noncanonical_forms)
{
    CTxOut canonical;
    std::string error;
    BOOST_REQUIRE(drivechain::BuildNativeWithdrawalOutput(
        PEGGED_ASSET, PARENT_GENESIS, DESTINATION,
        100000, 1000, canonical, &error));

    const auto rejected = [&](const CTxOut& output,
                              const CTxOutWitness* witness = nullptr) {
        drivechain::NativeWithdrawal parsed;
        return !drivechain::ParseNativeWithdrawalOutput(
            output, witness, PEGGED_ASSET, PARENT_GENESIS, parsed, &error);
    };

    CTxOut mutated = canonical;
    mutated.nAsset.SetToAsset(OTHER_ASSET);
    BOOST_CHECK(rejected(mutated));

    mutated = canonical;
    mutated.nAsset.vchCommitment.assign(33, 0);
    mutated.nAsset.vchCommitment[0] = 10;
    BOOST_CHECK(rejected(mutated));

    mutated = canonical;
    mutated.nValue.vchCommitment.assign(33, 0);
    mutated.nValue.vchCommitment[0] = 8;
    BOOST_CHECK(rejected(mutated));

    mutated = canonical;
    mutated.nNonce.vchCommitment.assign(33, 0);
    mutated.nNonce.vchCommitment[0] = 2;
    BOOST_CHECK(rejected(mutated));

    CTxOutWitness nonempty_witness;
    nonempty_witness.vchRangeproof = {1};
    BOOST_CHECK(rejected(canonical, &nonempty_witness));
    nonempty_witness.SetNull();
    nonempty_witness.vchSurjectionproof = {1};
    BOOST_CHECK(rejected(canonical, &nonempty_witness));

    mutated = canonical;
    mutated.nValue.SetToAmount(1000);
    BOOST_CHECK(rejected(mutated));

    mutated = canonical;
    mutated.scriptPubKey << OP_0;
    BOOST_CHECK(rejected(mutated));

    // Re-encode the 32-byte genesis with OP_PUSHDATA1. It is semantically the
    // same push but not the one canonical byte serialization.
    std::vector<unsigned char> nonminimal{OP_RETURN, OP_PUSHDATA1, 32};
    nonminimal.insert(nonminimal.end(), PARENT_GENESIS.begin(), PARENT_GENESIS.end());
    const std::vector<unsigned char> destination(DESTINATION.begin(), DESTINATION.end());
    nonminimal.push_back(destination.size());
    nonminimal.insert(nonminimal.end(), destination.begin(), destination.end());
    nonminimal.push_back(8);
    const std::vector<unsigned char> fee = ParseHex("00000000000003e8");
    nonminimal.insert(nonminimal.end(), fee.begin(), fee.end());
    mutated = canonical;
    mutated.scriptPubKey = CScript(nonminimal.begin(), nonminimal.end());
    BOOST_CHECK(rejected(mutated));

    CScript script;
    BOOST_CHECK(!drivechain::BuildNativeWithdrawalScript(
        PARENT_GENESIS, CScript(), 1, script, &error));
    CScript oversized_destination;
    oversized_destination.insert(oversized_destination.end(), 129, OP_TRUE);
    BOOST_CHECK(!drivechain::BuildNativeWithdrawalScript(
        PARENT_GENESIS, oversized_destination, 1, script, &error));
    BOOST_CHECK(!drivechain::BuildNativeWithdrawalOutput(
        PEGGED_ASSET, PARENT_GENESIS, DESTINATION,
        0, 0, mutated, &error));
    BOOST_CHECK(!drivechain::BuildNativeWithdrawalOutput(
        PEGGED_ASSET, PARENT_GENESIS, DESTINATION,
        1000, 1000, mutated, &error));
    BOOST_CHECK(!drivechain::BuildNativeWithdrawalOutput(
        PEGGED_ASSET, PARENT_GENESIS, DESTINATION,
        999, 1000, mutated, &error));
}

BOOST_AUTO_TEST_CASE(native_blinded_m6_is_unique_and_legacy_serialized)
{
    const auto withdrawal = BuildAndParseWithdrawal();
    drivechain::NativeWithdrawalM6 m6;
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        drivechain::BuildNativeWithdrawalM6(
            ELEMENTS_GENESIS, 24, BURN_TXID, 7,
            withdrawal, m6, &error),
        error);

    BOOST_CHECK_EQUAL(m6.blinded_transaction.version, 2);
    BOOST_CHECK(m6.blinded_transaction.vin.empty());
    BOOST_REQUIRE_EQUAL(m6.blinded_transaction.vout.size(), 3U);
    BOOST_CHECK_EQUAL(m6.blinded_transaction.vout[0].nValue, 0);
    BOOST_CHECK_EQUAL(m6.blinded_transaction.vout[1].nValue, 0);
    BOOST_CHECK_EQUAL(m6.blinded_transaction.vout[2].nValue, 99000);
    BOOST_CHECK(m6.blinded_transaction.vout[2].scriptPubKey == DESTINATION);
    BOOST_CHECK_LE(m6.blinded_transaction.vout[1].scriptPubKey.size(), 83U);
    BOOST_CHECK_EQUAL(HexStr(m6.burn_commitment),
                      "454c5744013f3e3d3c3b3a393837363534333231302f2e2d2c2b2a29282726252423222120"
                      "185f5e5d5c5b5a595857565554535251504f4e4d4c4b4a4948474645444342414000000007");
    BOOST_CHECK_EQUAL(
        HexStr(m6.legacy_serialization),
        "02000000000300000000000000000a6a0800000000000003e8"
        "00000000000000004c6a4a"
        "454c5744013f3e3d3c3b3a393837363534333231302f2e2d2c2b2a29282726252423222120"
        "185f5e5d5c5b5a595857565554535251504f4e4d4c4b4a4948474645444342414000000007"
        "b882010000000000160014606162636465666768696a6b6c6d6e6f7071727300000000");
    BOOST_CHECK_EQUAL(
        m6.m6id.GetHex(),
        "a7e1da09da7c62eda3f3bcb3902d6a79bb1d4a348858346c4152c10b714d3572");
    BOOST_CHECK(m6.m6id == drivechain::ComputeNativeWithdrawalM6Id(
                              m6.blinded_transaction));
    BOOST_CHECK(m6.m6id == m6.blinded_transaction.GetHash());

    uint256 parsed_elements_genesis;
    uint8_t parsed_slot{0};
    uint256 parsed_burn_txid;
    uint32_t parsed_burn_vout{0};
    BOOST_REQUIRE_MESSAGE(
        drivechain::ParseNativeWithdrawalM6Commitment(
            m6.blinded_transaction.vout[1].scriptPubKey,
            parsed_elements_genesis, parsed_slot, parsed_burn_txid,
            parsed_burn_vout, &error),
        error);
    BOOST_CHECK(parsed_elements_genesis == ELEMENTS_GENESIS);
    BOOST_CHECK_EQUAL(parsed_slot, 24U);
    BOOST_CHECK(parsed_burn_txid == BURN_TXID);
    BOOST_CHECK_EQUAL(parsed_burn_vout, 7U);

    Bitcoin::CMutableTransaction decoded;
    BOOST_REQUIRE_MESSAGE(
        drivechain::DeserializeNativeWithdrawalM6Legacy(
            m6.legacy_serialization, decoded, &error),
        error);
    BOOST_CHECK_EQUAL(HexStr(drivechain::SerializeNativeWithdrawalM6Legacy(decoded)),
                      HexStr(m6.legacy_serialization));

    drivechain::NativeWithdrawalM6 parsed;
    BOOST_REQUIRE_MESSAGE(
        drivechain::ParseNativeWithdrawalM6(
            decoded, ELEMENTS_GENESIS, 24, BURN_TXID, 7,
            parsed, &error),
        error);
    BOOST_CHECK_EQUAL(parsed.burn_amount, withdrawal.burn_amount);
    BOOST_CHECK_EQUAL(parsed.parent_fee, withdrawal.parent_fee);
    BOOST_CHECK_EQUAL(parsed.payout_amount, withdrawal.payout_amount);
    BOOST_CHECK(parsed.destination == withdrawal.destination);
    BOOST_CHECK(parsed.m6id == m6.m6id);
}

BOOST_AUTO_TEST_CASE(native_blinded_m6_rejects_mutation_and_replay_aliases)
{
    const auto withdrawal = BuildAndParseWithdrawal();
    drivechain::NativeWithdrawalM6 canonical;
    std::string error;
    BOOST_REQUIRE(drivechain::BuildNativeWithdrawalM6(
        ELEMENTS_GENESIS, 24, BURN_TXID, 7,
        withdrawal, canonical, &error));

    const auto parse_rejected = [&](const Bitcoin::CMutableTransaction& tx,
                                    const uint256& burn_txid = BURN_TXID,
                                    const uint32_t burn_vout = 7) {
        drivechain::NativeWithdrawalM6 parsed;
        return !drivechain::ParseNativeWithdrawalM6(
            tx, ELEMENTS_GENESIS, 24, burn_txid, burn_vout,
            parsed, &error);
    };

    Bitcoin::CMutableTransaction mutated = canonical.blinded_transaction;
    mutated.version = 1;
    BOOST_CHECK(parse_rejected(mutated));

    mutated = canonical.blinded_transaction;
    mutated.nLockTime = 1;
    BOOST_CHECK(parse_rejected(mutated));

    mutated = canonical.blinded_transaction;
    mutated.vin.emplace_back(Bitcoin::COutPoint(uint256::ONE, 0));
    BOOST_CHECK(parse_rejected(mutated));

    mutated = canonical.blinded_transaction;
    mutated.vout[0].nValue = 1;
    BOOST_CHECK(parse_rejected(mutated));

    mutated = canonical.blinded_transaction;
    mutated.vout[0].scriptPubKey << OP_0;
    BOOST_CHECK(parse_rejected(mutated));

    mutated = canonical.blinded_transaction;
    mutated.vout[1].scriptPubKey[2] ^= 1;
    BOOST_CHECK(parse_rejected(mutated));

    mutated = canonical.blinded_transaction;
    mutated.vout[1].scriptPubKey[6] = 2;
    BOOST_CHECK(parse_rejected(mutated));

    std::vector<unsigned char> nonminimal_reference{
        OP_RETURN, OP_PUSHDATA1,
        static_cast<unsigned char>(
            drivechain::NATIVE_WITHDRAWAL_M6_REFERENCE_SIZE)};
    nonminimal_reference.insert(nonminimal_reference.end(),
                                canonical.burn_commitment.begin(),
                                canonical.burn_commitment.end());
    mutated = canonical.blinded_transaction;
    mutated.vout[1].scriptPubKey = CScript(nonminimal_reference.begin(),
                                           nonminimal_reference.end());
    BOOST_CHECK(parse_rejected(mutated));

    mutated = canonical.blinded_transaction;
    mutated.vout[2].nValue++;
    drivechain::NativeWithdrawalM6 amount_mutation;
    BOOST_REQUIRE(drivechain::ParseNativeWithdrawalM6(
        mutated, ELEMENTS_GENESIS, 24, BURN_TXID, 7,
        amount_mutation, &error));
    BOOST_CHECK(amount_mutation.m6id != canonical.m6id);

    BOOST_CHECK(parse_rejected(canonical.blinded_transaction,
                               uint256S("01"), 7));
    BOOST_CHECK(parse_rejected(canonical.blinded_transaction,
                               BURN_TXID, 8));

    drivechain::NativeWithdrawalM6 distinct;
    BOOST_REQUIRE(drivechain::BuildNativeWithdrawalM6(
        ELEMENTS_GENESIS, 24, BURN_TXID, 8,
        withdrawal, distinct, &error));
    BOOST_CHECK(distinct.burn_commitment != canonical.burn_commitment);
    BOOST_CHECK(distinct.m6id != canonical.m6id);

    BOOST_CHECK(!drivechain::BuildNativeWithdrawalM6(
        ELEMENTS_GENESIS, 24, uint256(), 7,
        withdrawal, distinct, &error));
    BOOST_CHECK(!drivechain::BuildNativeWithdrawalM6(
        ELEMENTS_GENESIS, 24, BURN_TXID,
        std::numeric_limits<uint32_t>::max(),
        withdrawal, distinct, &error));

    std::vector<unsigned char> with_trailing = canonical.legacy_serialization;
    with_trailing.push_back(0);
    Bitcoin::CMutableTransaction decoded;
    BOOST_CHECK(!drivechain::DeserializeNativeWithdrawalM6Legacy(
        with_trailing, decoded, &error));

    std::vector<unsigned char> oversized(
        drivechain::NATIVE_WITHDRAWAL_MAX_M6_LEGACY_SIZE + 1, 0);
    BOOST_CHECK(!drivechain::DeserializeNativeWithdrawalM6Legacy(
        oversized, decoded, &error));

    // A huge attacker-controlled CompactSize count must be rejected by the
    // fixed-frame preflight before the generic deserializer can allocate.
    std::vector<unsigned char> huge_vout_count = canonical.legacy_serialization;
    huge_vout_count[5] = 0xff;
    BOOST_CHECK(!drivechain::DeserializeNativeWithdrawalM6Legacy(
        huge_vout_count, decoded, &error));

    std::vector<unsigned char> huge_script = canonical.legacy_serialization;
    huge_script[14] = 0xfd;
    BOOST_CHECK(!drivechain::DeserializeNativeWithdrawalM6Legacy(
        huge_script, decoded, &error));
}

BOOST_AUTO_TEST_CASE(native_withdrawal_haskell_matches_upstream_wire_encodings)
{
    for (size_t length = 1; length <= 128; ++length) {
        CScript destination;
        for (size_t i = 0; i < length; ++i) destination.push_back(static_cast<unsigned char>(i));
        for (const CAmount fee : {CAmount{0}, CAmount{1}, MAX_MONEY - 1}) {
            std::vector<unsigned char> fee_bytes(8);
            for (size_t i = 0; i < 8; ++i) fee_bytes[i] = static_cast<uint64_t>(fee) >> (56 - 8*i);
            const CScript expected = CScript() << OP_RETURN << ToByteVector(PARENT_GENESIS)
                << std::vector<unsigned char>(destination.begin(), destination.end()) << fee_bytes;
            CTxOut output;
            std::string error;
            BOOST_REQUIRE_MESSAGE(drivechain::BuildNativeWithdrawalOutput(
                PEGGED_ASSET, PARENT_GENESIS, destination, fee + 1, fee, output, &error), error);
            BOOST_CHECK(output.scriptPubKey == expected);
            drivechain::NativeWithdrawal withdrawal;
            BOOST_REQUIRE(drivechain::ParseNativeWithdrawalOutput(
                output, nullptr, PEGGED_ASSET, PARENT_GENESIS, withdrawal, &error));
            drivechain::NativeWithdrawalM6 m6, parsed;
            BOOST_REQUIRE(drivechain::BuildNativeWithdrawalM6(
                ELEMENTS_GENESIS, static_cast<uint8_t>(length), BURN_TXID, length, withdrawal, m6, &error));
            BOOST_CHECK_EQUAL(m6.legacy_serialization.size(), 123 + length);
            BOOST_CHECK(m6.legacy_serialization == drivechain::SerializeNativeWithdrawalM6Legacy(m6.blinded_transaction));
            BOOST_CHECK(m6.m6id == m6.blinded_transaction.GetHash());
            BOOST_CHECK(m6.blinded_transaction.vout[0].scriptPubKey == (CScript() << OP_RETURN << fee_bytes));
            BOOST_CHECK(m6.blinded_transaction.vout[1].scriptPubKey ==
                (CScript() << OP_RETURN << std::vector<unsigned char>(m6.burn_commitment.begin(), m6.burn_commitment.end())));
            BOOST_REQUIRE(drivechain::ParseNativeWithdrawalM6(
                m6.blinded_transaction, ELEMENTS_GENESIS, static_cast<uint8_t>(length), BURN_TXID, length, parsed, &error));
            BOOST_CHECK_EQUAL(parsed.burn_amount, fee + 1);
            BOOST_CHECK_EQUAL(parsed.parent_fee, fee);
            BOOST_CHECK_EQUAL(parsed.payout_amount, 1);
            BOOST_CHECK(parsed.legacy_serialization == m6.legacy_serialization);
            BOOST_CHECK(parsed.m6id == m6.m6id);
            Bitcoin::CMutableTransaction truncated;
            for (size_t size = 0; size < m6.legacy_serialization.size(); ++size) {
                const std::vector<unsigned char> bytes(m6.legacy_serialization.begin(), m6.legacy_serialization.begin() + size);
                BOOST_CHECK(!drivechain::DeserializeNativeWithdrawalM6Legacy(bytes, truncated, &error));
            }
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
