// Copyright (c) 2020-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/haskell_reference.h>
#include <consensus/amount.h>
#include <policy/fees.h>
#include <policy/policy.h>
#include <script/ecx_activation_annex.h>
#include <crypto/sha256.h>
#include <haskell/bridge.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <usdd_sp1_resources.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <limits>
#include <set>
#include <vector>

namespace drivechain::haskell {
uint64_t BmmWorkBudget(uint64_t count, const std::function<uint64_t(uint32_t,uint64_t,uint64_t)>& read)
{
    uint64_t result{0};
    ReferenceCheckedStatus(ReferenceReadScalarAdmission(elements_hs_bmm_work_budget_v1,read,count,&result),
        0,"Haskell work budget evaluation failed");
    return result;
}

bool BmmWorkTotal(bool saturate, uint64_t count, const std::function<uint64_t(uint64_t)>& read, uint64_t& total)
{
    return ReferenceCheckedStatus(ReferenceReadScalarAdmission(elements_hs_bmm_work_total_v1,
        [&](uint32_t, uint64_t index, uint64_t) { return read(index); },
        static_cast<uint32_t>(saturate),count,total,&total),1,"Haskell work total evaluation failed") == 0;
}
}

BOOST_AUTO_TEST_SUITE(policy_fee_tests)

BOOST_AUTO_TEST_CASE(standardness_gate_parity)
{
    using namespace drivechain::haskell;
    for (uint32_t facts = 0; facts < 8; ++facts) {
        BOOST_CHECK_EQUAL(AdmitStandardness(StandardnessGate::ANNEX_NETWORK,facts),
            bool(facts&1) && bool(facts&2) && bool(facts&4));
        BOOST_CHECK_EQUAL(AdmitStandardness(StandardnessGate::OUTPUT_EXCEPTIONS,facts),
            bool(facts&1) || bool(facts&2) || bool(facts&4));
    }
    for (uint32_t flags : {0U,1U,2U,511U,512U,UINT32_MAX})
    for (uint64_t count : {uint64_t{0},uint64_t{1},uint64_t{2},UINT64_MAX})
    for (uint64_t limit : {uint64_t{0},uint64_t{1},uint64_t{2},UINT64_MAX}) {
        BOOST_CHECK_EQUAL(AdmitStandardness(StandardnessGate::WITNESS_RESOURCES,flags,count,limit),
            !(flags != 0 || count > limit));
    }
    BOOST_CHECK_THROW(AdmitStandardness(StandardnessGate::ANNEX_NETWORK,8),std::runtime_error);
    BOOST_CHECK_THROW(AdmitStandardness(StandardnessGate::OUTPUT_EXCEPTIONS,0,1),std::runtime_error);
    BOOST_CHECK_THROW(AdmitStandardness(static_cast<StandardnessGate>(3),0),std::runtime_error);
}

BOOST_AUTO_TEST_CASE(taproot_witness_policy_parity)
{
    for (bool annex : {false,true}) for (bool bond : {false,true})
    for (uint64_t count : {0,1,2,3,4,5}) for (uint32_t leaf = 0; leaf <= 256; leaf += 2)
    for (uint64_t size : {0,31,32,33}) for (uint64_t input : {0,1}) {
        uint32_t expected{0};
        if (count >= 2) {
            if (leaf == 256) expected=0;
            else if (leaf == TAPROOT_LEAF_TAPSCRIPT) expected=annex ? 0 : 2;
            else if (leaf == TAPROOT_LEAF_TAPSIMPLICITY) expected=(count-2==2 && size==32) ? 1 : 0;
            else expected=annex ? 0 : 1;
        } else if (count == 1) expected=(!annex || (bond && input==0)) ? 1 : 0;
        // Compose the retained native shape/leaf checks with fork-only policy.
        uint32_t actual{0};
        if (count != 0 && (count == 1 || leaf != 256)) {
            actual = drivechain::haskell::TaprootWitnessPolicy(annex,bond,count,
                count == 1 ? 0 : leaf,size,input);
            if (actual && count >= 2 && leaf == TAPROOT_LEAF_TAPSCRIPT) actual=2;
        }
        BOOST_CHECK_EQUAL(actual, expected);
    }
    BOOST_CHECK_THROW(drivechain::haskell::TaprootWitnessPolicy(false,false,0,0,0,0),std::runtime_error);
    BOOST_CHECK_THROW(drivechain::haskell::TaprootWitnessPolicy(false,false,2,256,0,0),std::runtime_error);
}

BOOST_AUTO_TEST_CASE(bond_marker_policy_parity)
{
    const std::vector<unsigned char> magic{'E','C','X','B'};
    for (size_t size : {0U,1U,2U,7U,8U,9U,506U,507U,508U,600U}) {
        for (size_t offset = 0; offset <= size; ++offset) {
            std::vector<unsigned char> script(size, 0);
            if (size) script[0] = OP_RETURN;
            if (size > 1) script[1] = OP_PUSHDATA2;
            if (size-offset >= magic.size()) std::copy(magic.begin(),magic.end(),script.begin()+offset);
            const bool candidate = size >= 8 && script[0] == OP_RETURN &&
                std::search(script.begin()+1,script.end(),magic.begin(),magic.end()) != script.end();
            const bool framed = size == 507 && script[0] == OP_RETURN && script[1] == OP_PUSHDATA2;
            BOOST_CHECK_EQUAL(drivechain::haskell::BondMarkerPolicy(false,script), candidate);
            BOOST_CHECK_EQUAL(drivechain::haskell::BondMarkerPolicy(true,script), framed);
        }
    }
}

BOOST_AUTO_TEST_CASE(witness_annex_policy_parity)
{
    using namespace drivechain::haskell;
    static_assert(static_cast<uint32_t>(ReplayStoreFlow::WITNESS_ANNEX) == 263);
    for (uint32_t flags = 0; flags < 128; ++flags) {
        const bool annex=flags&1, native=flags&2, frozen=flags&4, parent=flags&8,
            enabled=flags&16, seen=flags&32, proof=flags&64;
        uint32_t expected{0};
        if (annex && native && frozen) expected=2;
        else if (annex && parent) expected=(!native || !enabled || seen || !proof) ? 1 : 3;
        else if (annex) expected=2;
        std::vector<uint32_t> calls;
        auto read = [&](uint32_t step) -> uint32_t {
            calls.push_back(step);
            switch (step) {
            case 1: return annex;
            case 2: case 5: return native;
            case 3: return frozen;
            case 4: return parent;
            case 6: return enabled;
            case 7: return seen;
            case 8: return proof;
            default: throw std::logic_error("unexpected witness policy read");
            }
        };
        BOOST_CHECK_EQUAL(ParentReplayStore(ReplayStoreFlow::WITNESS_ANNEX,read), expected);
        if (!annex) BOOST_CHECK(calls == std::vector<uint32_t>{1});
        if (!native) BOOST_CHECK(std::find(calls.begin(),calls.end(),3) == calls.end());
        const auto trace = calls;
        for (uint32_t fault : trace) {
            BOOST_CHECK_THROW(ParentReplayStore(ReplayStoreFlow::WITNESS_ANNEX,
                [&](uint32_t step) { if (step==fault) throw std::logic_error("sentinel"); return read(step); }), std::logic_error);
        }
    }
}

BOOST_AUTO_TEST_CASE(transaction_weight_exception_parity)
{
    const uint64_t ordinary = MAX_STANDARD_TX_WEIGHT, proof = usdd::SP1_PROOF_TX_MAX_WEIGHT;
    const std::vector<uint64_t> edges{0,1,ordinary-1,ordinary,ordinary+1,
        proof-1,proof,proof+1,UINT64_MAX};
    for (bool bond : {false,true}) for (auto total : edges) for (auto annex : edges) {
        const bool rejected = annex > total || (bond && annex != 0) ||
            (total-annex > ordinary && !bond) || (annex != 0 && total > proof);
        BOOST_CHECK_EQUAL(drivechain::haskell::TransactionWeight(bond,total,annex,ordinary,proof), !rejected);
    }
}

BOOST_AUTO_TEST_CASE(FeeRounder)
{
    FastRandomContext rng{/*fDeterministic=*/true};
    FeeFilterRounder fee_rounder{CFeeRate{1000}, rng};

    // check that 1000 rounds to 974 or 1071
    std::set<CAmount> results;
    while (results.size() < 2) {
        results.emplace(fee_rounder.round(1000));
    }
    BOOST_CHECK_EQUAL(*results.begin(), 974);
    BOOST_CHECK_EQUAL(*++results.begin(), 1071);

    // check that negative amounts rounds to 0
    BOOST_CHECK_EQUAL(fee_rounder.round(-0), 0);
    BOOST_CHECK_EQUAL(fee_rounder.round(-1), 0);

    // check that MAX_MONEY rounds to 9170997
    BOOST_CHECK_EQUAL(fee_rounder.round(MAX_MONEY), 9170997);
}

BOOST_AUTO_TEST_CASE(bmm_work_fee_quote)
{
    BmmWorkFeeQuote quote;
    BOOST_REQUIRE(CalculateBmmWorkFeeQuote(20'000, 1'500'000, 1'000, 500, quote));
    BOOST_CHECK_EQUAL(quote.verification_fee, 1'500);
    BOOST_CHECK_EQUAL(quote.producer_reserve, 500);
    BOOST_CHECK_EQUAL(quote.bid, 18'000);

    BOOST_REQUIRE(CalculateBmmWorkFeeQuote(10, 1, 1, 0, quote));
    BOOST_CHECK_EQUAL(quote.verification_fee, 1);
    BOOST_CHECK_EQUAL(quote.bid, 9);

    BOOST_CHECK(!CalculateBmmWorkFeeQuote(1'000, 2'000'000, 1'000, 0, quote));
    BOOST_CHECK(!CalculateBmmWorkFeeQuote(-1, 0, 0, 0, quote));
    BOOST_CHECK(!CalculateBmmWorkFeeQuote(
        MAX_MONEY,
        std::numeric_limits<uint64_t>::max(),
        MAX_MONEY,
        0,
        quote));
}

BOOST_AUTO_TEST_CASE(bmm_work_fee_quote_legacy_parity)
{
    // Frozen pre-migration rule, including partial results on insufficient funds.
    const auto legacy = [](CAmount fees, uint64_t work, CAmount rate, CAmount reserve, BmmWorkFeeQuote& quote) {
        quote = {};
        if (!MoneyRange(fees) || !MoneyRange(rate) || !MoneyRange(reserve)) return false;
        const uint64_t unsigned_rate = static_cast<uint64_t>(rate);
        if (unsigned_rate && work > (UINT64_MAX - 999999) / unsigned_rate) return false;
        const uint64_t priced = (work * unsigned_rate + 999999) / 1000000;
        if (priced > static_cast<uint64_t>(MAX_MONEY)) return false;
        quote.verification_fee = priced;
        quote.producer_reserve = reserve;
        if (quote.verification_fee > fees || reserve > fees - quote.verification_fee) return false;
        quote.bid = fees - quote.verification_fee - reserve;
        return MoneyRange(quote.bid);
    };
    FastRandomContext rng{/*fDeterministic=*/true};
    const std::array<CAmount,9> amounts{INT64_MIN,-1,0,1,1000,MAX_MONEY-1,MAX_MONEY,MAX_MONEY+1,INT64_MAX};
    const std::array<uint64_t,7> weights{0,1,999999,1000000,1000001,UINT64_MAX-999999,UINT64_MAX};
    const auto check = [&](CAmount fees, uint64_t work, CAmount rate, CAmount reserve) {
        BmmWorkFeeQuote expected{17,18,19}, actual{17,18,19};
        const bool accepted = legacy(fees,work,rate,reserve,expected);
        BOOST_CHECK_EQUAL(CalculateBmmWorkFeeQuote(fees,work,rate,reserve,actual),accepted);
        BOOST_CHECK_EQUAL(actual.verification_fee,expected.verification_fee);
        BOOST_CHECK_EQUAL(actual.producer_reserve,expected.producer_reserve);
        BOOST_CHECK_EQUAL(actual.bid,expected.bid);
        std::array<int64_t,3> display{17,18,19};
        BOOST_CHECK_EQUAL(drivechain::haskell::BmmWorkQuoteDisplay(fees,work,rate,reserve,display),accepted && expected.bid>0);
        BOOST_CHECK_EQUAL(display[0],accepted ? expected.verification_fee : 0);
        BOOST_CHECK_EQUAL(display[1],accepted ? expected.producer_reserve : 0);
        BOOST_CHECK_EQUAL(display[2],accepted ? expected.bid : 0);
        // The producer must stop at the quote gate, before submission or proof
        // acquisition, for every unfunded or zero-bid boundary above.
        std::vector<uint32_t> stages;
        std::array<int64_t,3> production{17,18,19};
        const bool produced = drivechain::haskell::BmmProduction(true, [&](uint32_t stage) {
            stages.push_back(stage);
            if (stage == 16) return drivechain::haskell::BmmWorkQuoteDisplay(fees,work,rate,reserve,production);
            if (stage == 10) {
                BOOST_CHECK_EQUAL(production[0], expected.verification_fee);
                BOOST_CHECK_EQUAL(production[1], expected.producer_reserve);
                BOOST_CHECK_EQUAL(production[2], expected.bid);
            }
            return true;
        });
        BOOST_CHECK_EQUAL(produced, accepted && expected.bid > 0);
        const std::vector<uint32_t> expected_stages = produced ?
            std::vector<uint32_t>{1,19,2,20,3,15,4,5,6,16,7,8,9,17,10,18,11,12,13,14} :
            std::vector<uint32_t>{1,19,2,20,3,15,4,5,6,16,116};
        BOOST_CHECK(stages == expected_stages);
    };
    for (const auto fees : amounts)
        for (const auto rate : amounts)
            for (const auto reserve : amounts)
                for (const auto work : weights) check(fees,work,rate,reserve);
    for (int i=0; i<10000; ++i) {
        const auto rate = static_cast<CAmount>(rng.randrange(MAX_MONEY+1));
        const auto boundary = rate ? (UINT64_MAX-999999)/rate : UINT64_MAX;
        check(static_cast<CAmount>(rng.randrange(MAX_MONEY+1)),rng.rand64(),rate,0);
        check(MAX_MONEY,boundary,rate,1);
        if (boundary != UINT64_MAX) check(MAX_MONEY,boundary+1,rate,1);
    }
}

BOOST_AUTO_TEST_CASE(simplicity_work_budget_legacy_parity)
{
    const auto legacy = [](const CTransaction& tx) {
        uint64_t total{0};
        for (const auto& witness : tx.witness.vtxinwit) {
            const auto& stack = witness.scriptWitness.stack;
            if (stack.size() < 4) continue;
            size_t control = stack.size()-1;
            if (!stack[control].empty() && stack[control][0] == 0x50) --control;
            if (control < 1 || stack[control].empty() ||
                (stack[control][0] & 0xfe) != 0xbe || stack[control-1].size() != 32) continue;
            const uint64_t budget = static_cast<uint64_t>(GetSerializeSize(stack)) + 50;
            if (budget > UINT64_MAX/1000 || total > UINT64_MAX-budget*1000) return UINT64_MAX;
            total += budget*1000;
        }
        return total;
    };
    FastRandomContext rng{/*fDeterministic=*/true};
    const std::array<size_t,7> sizes{0,1,31,32,33,252,253};
    const std::array<unsigned char,6> tags{0,0x50,0xbd,0xbe,0xbf,0xff};
    for (int trial=0; trial<5000; ++trial) {
        CMutableTransaction tx;
        tx.witness.vtxinwit.resize(rng.randrange(8));
        tx.vin.resize(tx.witness.vtxinwit.size());
        for (auto& witness : tx.witness.vtxinwit) {
            auto& stack = witness.scriptWitness.stack;
            stack.resize(rng.randrange(8));
            for (auto& item : stack) item.assign(sizes[rng.randrange(sizes.size())],tags[rng.randrange(tags.size())]);
        }
        const CTransaction immutable(tx);
        BOOST_CHECK_EQUAL(GetSimplicityValidationMilliweight(immutable),legacy(immutable));
    }
    // Callback failures must rethrow the original exception, not become saturation.
    BOOST_CHECK_EXCEPTION(drivechain::haskell::BmmWorkBudget(1,[](uint32_t, uint64_t, uint64_t) -> uint64_t {
        throw std::logic_error("work read fault");
    }), std::logic_error, [](const auto& error) { return std::string(error.what()) == "work read fault"; });
}

BOOST_AUTO_TEST_CASE(bmm_whole_candidate_measurement)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.witness.vtxinwit.resize(1);
    tx.witness.vtxinwit[0].scriptWitness.stack = {{0}, {0}, std::vector<unsigned char>(32), {0xbe}};
    const CTransaction immutable{tx};
    const auto work = uint64_t(GetSerializeSize(tx.witness.vtxinwit[0].scriptWitness.stack)+50)*1000;
    for (const bool saturate : {false, true}) {
        uint64_t total{UINT64_MAX-1}, last{0};
        std::vector<uint64_t> reads;
        const bool accepted = drivechain::haskell::MeasureWork(saturate, 3,
            [&](uint64_t index) -> const CTransaction& { reads.push_back(index); return immutable; }, total, &last);
        BOOST_CHECK_EQUAL(accepted, saturate);
        BOOST_CHECK_EQUAL(total, saturate ? UINT64_MAX : UINT64_MAX-1);
        BOOST_CHECK_EQUAL(last, work);
        BOOST_CHECK(reads == (saturate ? std::vector<uint64_t>{0,0,1,1,2,2} : std::vector<uint64_t>{0,0}));
    }
    uint64_t total{UINT64_MAX-1};
    BOOST_CHECK_EQUAL(GetSimplicityValidationMilliweight(immutable, &total), work);
    BOOST_CHECK_EQUAL(total, UINT64_MAX);
    total = 7;
    BOOST_CHECK_EXCEPTION(drivechain::haskell::MeasureWork(false, 3,
        [&](uint64_t index) -> const CTransaction& {
            if (index == 1) throw std::logic_error("whole candidate read fault");
            return immutable;
        }, total), std::logic_error, [](const auto& error) { return std::string(error.what()) == "whole candidate read fault"; });
    BOOST_CHECK_EQUAL(total, 7U);
    BOOST_CHECK(drivechain::haskell::MeasureWork(false, 0,
        [](uint64_t) -> const CTransaction& { throw std::logic_error("empty candidate read"); }, total));
    BOOST_CHECK_EQUAL(total, 7U);
}

BOOST_AUTO_TEST_CASE(bmm_work_total_modes)
{
    for (bool saturate : {false,true}) {
        uint64_t amount = UINT64_MAX-1;
        std::vector<uint64_t> seen;
        const bool accepted = drivechain::haskell::BmmWorkTotal(saturate,3,[&](uint64_t index) {
            seen.push_back(index);
            // The former production path nested a witness-budget entry here.
            BOOST_CHECK_EQUAL(drivechain::haskell::BmmWorkBudget(0,[](uint32_t,uint64_t,uint64_t) {
                throw std::logic_error("empty budget read"); return uint64_t{0};
            }),0U);
            return uint64_t{1};
        },amount);
        BOOST_CHECK_EQUAL(accepted,saturate);
        BOOST_CHECK_EQUAL(amount,UINT64_MAX);
        BOOST_CHECK_EQUAL(seen.size(),saturate ? 3U : 2U);
        for (size_t i=0; i<seen.size(); ++i) BOOST_CHECK_EQUAL(seen[i],i);
    }
    uint64_t amount{7};
    BOOST_CHECK_EXCEPTION(drivechain::haskell::BmmWorkTotal(false,3,[](uint64_t index) -> uint64_t {
        if (index == 1) throw std::logic_error("total read fault");
        return 1;
    },amount),std::logic_error,[](const auto& error) { return std::string(error.what()) == "total read fault"; });
    BOOST_CHECK_EQUAL(amount,7U);
    BOOST_CHECK(drivechain::haskell::BmmWorkTotal(false,0,[](uint64_t) -> uint64_t {
        throw std::logic_error("empty total read");
    },amount));
    BOOST_CHECK_EQUAL(amount,7U);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(ecx_activation_annex_tests)

// Transport-only fixture. Its zero proof is deliberately NOT cryptographically
// valid; budget eligibility must never be confused with script acceptance.
static std::vector<std::vector<unsigned char>> ActivationStack()
{
    std::vector<std::vector<unsigned char>> stack(5);
    stack[2].assign(ecx::ACTIVATION_BUDGET_CMR.begin(), ecx::ACTIVATION_BUDGET_CMR.end());
    stack[3].resize(33); stack[3][0] = 0xbe;
    auto& a = stack[4]; a.resize(800);
    const unsigned char prefix[]{0x50,'E','C','X','S','P','1',0,5,2,1,0};
    std::copy(std::begin(prefix), std::end(prefix), a.begin());
    a[15] = 1; // canonical nonzero program ID word
    a[78] = 1; a[79] = 100; // 356 proof bytes
    a[439] = 1; // public-value version
    for (unsigned i=0; i<10; ++i) a[436+4+32*i+31] = i+1;
    for (unsigned offset : {324,332,340,348,356}) a[436+offset+7] = 1;
    CSHA256().Write(a.data()+436,364).Finalize(a.data()+44);
    return stack;
}

BOOST_AUTO_TEST_CASE(exact_frozen_budget_and_fail_closed_mutations)
{
    for (const int64_t ordinary : {INT64_MIN, int64_t{-1}, INT64_MAX}) {
        BOOST_CHECK_EQUAL(drivechain::haskell::ActivationBudget(ordinary,0,[](uint32_t) -> bool {
            throw std::logic_error("ineligible budget read a fact");
        }),ordinary);
    }
    for (uint32_t failure=0; failure<7; ++failure) {
        uint32_t calls=0;
        BOOST_CHECK_THROW(drivechain::haskell::ActivationBudget(0,0,[&](uint32_t step) {
            BOOST_CHECK_EQUAL(step,calls++);
            if (step==failure) throw std::logic_error("budget callback failure");
            return true;
        }),std::logic_error);
        BOOST_CHECK_EQUAL(calls,failure+1);
    }
    BOOST_CHECK_EQUAL(ecx::ACTIVATION_EXECUTION_BUDGET_WU,1002636);
    BOOST_CHECK_EQUAL(HexStr(ecx::ACTIVATION_BUDGET_CMR),
        "d9ef88a9389f87114f62539d7e0e2d070fed1a4ea90fdaa7c206ac140ecf2e87");
    const auto stack = ActivationStack();
    uint256 cmr, program;
    std::copy(stack[2].begin(),stack[2].end(),cmr.begin());
    std::copy(stack[4].begin()+12,stack[4].begin()+44,program.begin());
    std::array<unsigned char,32> parsed_program{};
    std::array<unsigned char,364> values{};
    BOOST_REQUIRE(ecx::ParseActivationAnnex(stack,parsed_program,values));
    const auto allowance=ecx::ACTIVATION_EXECUTION_BUDGET_WU;
    BOOST_CHECK_EQUAL(ecx::ActivationExecutionBudget(4161,0,stack,&cmr,&program),allowance);
    BOOST_CHECK_EQUAL(ecx::ActivationExecutionBudget(-1,0,stack,&cmr,&program),-1);
    BOOST_CHECK_EQUAL(ecx::ActivationExecutionBudget(allowance+1,0,stack,&cmr,&program),allowance+1);
    BOOST_CHECK_EQUAL(ecx::ActivationExecutionBudget(4161,1,stack,&cmr,&program),4161);
    BOOST_CHECK_EQUAL(ecx::ActivationExecutionBudget(4161,0,stack,nullptr,&program),4161);
    BOOST_CHECK_EQUAL(ecx::ActivationExecutionBudget(4161,0,stack,&cmr,nullptr),4161);
    const uint256 zero_program{};
    BOOST_CHECK_EQUAL(ecx::ActivationExecutionBudget(4161,0,stack,&cmr,&zero_program),4161);
    BOOST_CHECK_EQUAL(ecx::ActivationExecutionBudget(0,0,stack,&cmr,&program),allowance);
    BOOST_CHECK_EQUAL(ecx::ActivationExecutionBudget(allowance,0,stack,&cmr,&program),allowance);
    uint256 wrong=program; wrong.begin()[0]^=1;
    BOOST_CHECK_EQUAL(ecx::ActivationExecutionBudget(4161,0,stack,&cmr,&wrong),4161);
    auto other=stack; other[2][0]^=1;
    std::copy(other[2].begin(),other[2].end(),wrong.begin());
    BOOST_CHECK_EQUAL(ecx::ActivationExecutionBudget(4161,0,other,&wrong,&program),4161);
    for (size_t offset : {0,1,8,9,10,11,44,76,79,436,799}) {
        auto bad=stack; bad[4][offset]^=1;
        BOOST_CHECK_EQUAL(ecx::ActivationExecutionBudget(4161,0,bad,&cmr,&program),4161);
    }
    for (size_t size : {0,32,34,4130}) {
        auto bad=stack; bad[3].resize(size);
        BOOST_CHECK_EQUAL(ecx::ActivationExecutionBudget(4161,0,bad,&cmr,&program),4161);
    }
    auto bad=stack; bad[3][0]=0xc0;
    BOOST_CHECK_EQUAL(ecx::ActivationExecutionBudget(4161,0,bad,&cmr,&program),4161);
    bad=stack; bad.push_back({});
    BOOST_CHECK_EQUAL(ecx::ActivationExecutionBudget(4161,0,bad,&cmr,&program),4161);
    bad=stack; bad[4].pop_back();
    BOOST_CHECK_EQUAL(ecx::ActivationExecutionBudget(4161,0,bad,&cmr,&program),4161);
    // Even a rehashed malformed public statement must fail the native parser.
    bad=stack; std::fill(bad[4].begin()+440,bad[4].begin()+472,0);
    CSHA256().Write(bad[4].data()+436,364).Finalize(bad[4].data()+44);
    BOOST_CHECK_EQUAL(ecx::ActivationExecutionBudget(4161,0,bad,&cmr,&program),4161);
}

BOOST_AUTO_TEST_CASE(activation_shape_boundaries_preserve_outputs)
{
    for (size_t count = 0; count <= 6; ++count) {
        auto stack = ActivationStack();
        stack.resize(count);
        std::array<unsigned char,32> program;
        std::array<unsigned char,364> values;
        program.fill(0xa5); values.fill(0xa5);
        const auto old_program = program;
        const auto old_values = values;
        BOOST_CHECK_EQUAL(ecx::ParseActivationAnnex(stack,program,values), count == 5);
        if (count != 5) {
            BOOST_CHECK(program == old_program);
            BOOST_CHECK(values == old_values);
        }
    }
    for (size_t size : {0,1,32,33,34,64,65,4128,4129,4130}) {
        for (unsigned char tag : {0xbe,0xbf,0xc0}) {
            auto stack = ActivationStack();
            stack[3].resize(size);
            if (size) stack[3][0] = tag;
            std::array<unsigned char,32> program{};
            std::array<unsigned char,364> values{};
            BOOST_CHECK_EQUAL(ecx::ParseActivationAnnex(stack,program,values),
                (size == 33 || size == 65 || size == 4129) && tag != 0xc0);
        }
    }
}

BOOST_AUTO_TEST_CASE(activation_credit_short_circuits_every_fact)
{
    for (unsigned mask = 0; mask < 128; ++mask) {
        unsigned failure = 0;
        while (failure < 7 && (mask & (1U << failure))) ++failure;
        unsigned calls = 0;
        const int64_t budget = drivechain::haskell::ActivationBudget(0,0,[&](uint32_t step) {
            BOOST_CHECK_EQUAL(step, calls++);
            return bool(mask & (1U << step));
        });
        BOOST_CHECK_EQUAL(budget, failure == 7 ? 1002636 : 0);
        BOOST_CHECK_EQUAL(calls, std::min(7U,failure+1));
    }
    const auto unexpected = [](uint32_t) -> bool { throw std::logic_error("unexpected activation read"); };
    BOOST_CHECK_EQUAL(drivechain::haskell::ActivationBudget(-1,0,unexpected),-1);
    BOOST_CHECK_EQUAL(drivechain::haskell::ActivationBudget(1002637,0,unexpected),1002637);
    BOOST_CHECK_EQUAL(drivechain::haskell::ActivationBudget(0,1,unexpected),0);
    BOOST_CHECK_THROW(drivechain::haskell::ActivationBudget(0,0,unexpected), std::logic_error);
}

BOOST_AUTO_TEST_SUITE_END()
