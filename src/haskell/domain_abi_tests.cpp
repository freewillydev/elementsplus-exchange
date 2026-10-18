// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#include <haskell/domain_abi.h>
#include <iostream>
#include <limits>

extern "C" void elements_hs_runtime_init(void);
static void Require(bool condition)
{
    if (!condition) throw std::runtime_error("domain ABI test failed");
}

int main()
{
    try {
        elements_hs_runtime_init();
        const auto& domains = elements_hs_domains_v1;
        constexpr uint64_t CANARY{0x123456789abcdef0};
        uint32_t handlers{0};
        for (const auto& [domain, count] : domains) {
            uint64_t result{CANARY};
            handlers += count;
            Require(domain(count,0,nullptr,0,nullptr,0,nullptr,&result) == -1);
            Require(domain(UINT32_MAX,0,nullptr,0,nullptr,0,nullptr,&result) == -1);
            // Every handler rejects malformed shape before touching borrowed memory.
            for (uint32_t operation = 0; operation < count; ++operation) {
                Require(domain(operation,UINT32_MAX,nullptr,0,nullptr,0,nullptr,&result) == -1);
                Require(domain(operation,0,nullptr,UINT32_MAX,nullptr,0,nullptr,&result) == -1);
                Require(domain(operation,0,nullptr,0,nullptr,UINT32_MAX,nullptr,&result) == -1);
                Require(domain(operation,0,nullptr,0,nullptr,0,nullptr,nullptr) == -1);
            }
            Require(result == CANARY);
        }
        uint64_t result{CANARY};
        for (uint64_t f : {uint64_t{0}, uint64_t{1}, uint64_t{UINT32_MAX}, UINT64_MAX})
        for (uint64_t fc : {uint64_t{0}, uint64_t{1}, uint64_t{UINT32_MAX}, UINT64_MAX})
        for (uint64_t d : {uint64_t{0}, uint64_t{1}, uint64_t{UINT32_MAX}, UINT64_MAX})
        for (uint64_t dc : {uint64_t{0}, uint64_t{1}, uint64_t{UINT32_MAX}, UINT64_MAX}) {
            uint64_t fields[]{f,fc,d,dc}, output[]{CANARY,91,92,CANARY};
            const bool valid = fc <= f && dc <= d;
            Require(elements_hs_exchange_inbox_v1(5,4,fields,output+1) == (valid ? 0 : 1));
            Require(output[0] == CANARY && output[3] == CANARY);
            Require(output[1] == (valid ? f-fc : 91) && output[2] == (valid ? d-dc : 92));
            Require(elements_hs_exchange_inbox_v1(5,3,fields,output+1) == -1);
            Require(elements_hs_exchange_inbox_v1(5,4,nullptr,output+1) == -1);
            Require(elements_hs_exchange_inbox_v1(5,4,fields,nullptr) == -1);
        }
        uint64_t depth[]{100,105,6};
        Require(elements_hs_deposit_evidence_api_v1(8,3,depth,0,nullptr,0,nullptr,&result) == 0 && result == 1);
        depth[1] = uint64_t{1} << 32;
        result = CANARY;
        Require(elements_hs_deposit_evidence_api_v1(8,3,depth,0,nullptr,0,nullptr,&result) == -2 && result == CANARY);
        Require(elements_hs_deposit_evidence_api_v1(8,3,nullptr,0,nullptr,0,nullptr,&result) == -1 && result == CANARY);
        uint64_t envelope[]{0,256,0};
        Require(elements_hs_exchange_codec_api_v1(9,3,envelope,0,nullptr,0,nullptr,&result) == -2 && result == CANARY);
        uint64_t state[]{0,0xffffffff};
        Require(elements_hs_bmm_state_api_v1(4,2,state,0,nullptr,0,nullptr,&result) == -2 && result == CANARY);
        // Canonical sign extension, including INT64_MIN, survives the new transport.
        for (const int64_t amount : {int64_t{-1}, std::numeric_limits<int64_t>::min(), std::numeric_limits<int64_t>::max()}) {
            uint64_t args[]{static_cast<uint64_t>(amount),0,0};
            Require(elements_hs_withdrawal_api_v1(2,3,args,0,nullptr,0,nullptr,&result) == 0);
            Require(elements_hs_withdrawal_payout_v1(amount,0,0) == std::bit_cast<int64_t>(result));
        }
        Require(elements_hs_deposit_depth_v1(100,105,6) == 1);
        Require(elements_hs_deposit_depth_v1(100,104,6) == 0);
        for (uint32_t upper : {0U, 1U, uint32_t{INT32_MAX}, UINT32_MAX}) {
            for (uint32_t lower : {0U, 1U, uint32_t{INT32_MAX}, UINT32_MAX}) {
                uint64_t args[]{upper, lower};
                const int64_t expected = lower <= upper ? int64_t{upper} - lower : -1;
                Require(elements_hs_parent_replay_api_v1(31,2,args,0,nullptr,0,nullptr,&result) == 0);
                Require(std::bit_cast<int64_t>(result) == expected);
                Require(elements_hs_replay_distance_v1(upper,lower) == expected);
            }
        }
        for (unsigned wide = 0; wide < 2; ++wide) {
            uint64_t args[]{0,0};
            args[wide] = uint64_t{1} << 32;
            result = CANARY;
            Require(elements_hs_parent_replay_api_v1(31,2,args,0,nullptr,0,nullptr,&result) == -2);
            Require(result == CANARY);
        }
        for (int64_t height : {INT64_MIN,int64_t{-1},int64_t{0},int64_t{4294967294},int64_t{4294967295},INT64_MAX}) {
            uint64_t args[]{std::bit_cast<uint64_t>(height)};
            Require(elements_hs_configuration_api_v1(39,1,args,0,nullptr,0,nullptr,&result) == 0);
            Require(std::bit_cast<int64_t>(result) == elements_hs_approving_parent_height_v1(height));
            for (int64_t parent : {INT64_MIN,int64_t{0},INT64_MAX}) {
                uint64_t pair[]{args[0],std::bit_cast<uint64_t>(parent)};
                Require(elements_hs_configuration_api_v1(40,2,pair,0,nullptr,0,nullptr,&result) == 0);
                Require(result == uint64_t(height < parent));
            }
        }
        std::cout << domains.size() << " domains, " << handlers << " handlers: shape/range/null rejection, canaries, signed values and typed adapters passed\n";
        return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
