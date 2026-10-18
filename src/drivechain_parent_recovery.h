// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef ELEMENTS_DRIVECHAIN_PARENT_RECOVERY_H
#define ELEMENTS_DRIVECHAIN_PARENT_RECOVERY_H

#include <univalue.h>
#include <haskell/bridge.h>
#include <haskell/bmm_constants.h>

#include <chrono>
#include <stdexcept>
#include <string>

namespace drivechain {

inline bool IsPrunedBlockReply(const UniValue& reply)
{
    const auto& error = reply["error"];
    return haskell::ParentReplayStore(haskell::ReplayStoreFlow::RECOVERY_PRUNED,[&](uint32_t step) {
        switch (step) {
        case 1: return error.isObject();
        case 2: return error["code"].isNum();
        case 3: return error["code"].getInt<int>()==-1;
        case 4: return error["message"].isStr();
        case 5: return error["message"].get_str()=="Block not available (pruned data)";
        default: throw std::logic_error("invalid pruned reply action");
        }
    })==0;
}

/** Availability only. The caller must authenticate the returned block bytes.
 * RPC, deadline and wait callbacks allow deterministic testing of recovery.
 * Never allow recovery while holding consensus locks.
 */
template <typename Rpc, typename Check, typename Wait>
UniValue FetchParentBlockBody(const std::string& hash, bool allow_recovery,
                             Rpc&& rpc, Check&& check, Wait&& wait)
{
    auto checked = [&](const std::string& method, const UniValue& params) -> UniValue {
        check();
        const auto reply = rpc(method, params);
        if (haskell::ParentReplayStore(haskell::ReplayStoreFlow::RECOVERY_REPLY,[&](uint32_t step) {
            return step==1 ? reply["error"].isNull() : !reply["result"].isNull();
        }))
            throw std::runtime_error(method + " failed during parent block retrieval");
        return reply["result"];
    };
    UniValue block_params(UniValue::VARR);
    block_params.push_back(hash);
    block_params.push_back(0);
    auto active_height = [&]() {
        UniValue params(UniValue::VARR);
        params.push_back(hash);
        params.push_back(true);
        const UniValue header = checked("getblockheader", params);
        int height=0;
        UniValue active;
        haskell::ParentReplayStore(haskell::ReplayStoreFlow::RECOVERY_HEADER,[&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return header["hash"].isStr();
            case 2: return header["hash"].get_str()==hash;
            case 3: return header["height"].isNum();
            case 4: return header["confirmations"].isNum();
            case 5: return header["height"].getInt<int>()>=0;
            case 6: return header["confirmations"].getInt<int>()>0;
            case 7: {
                height=header["height"].getInt<int>();
                UniValue height_params(UniValue::VARR);
                height_params.push_back(height); active=checked("getblockhash",height_params); return 1;
            }
            case 8: return active.isStr();
            case 9: return active.get_str()==hash;
            case 10: throw std::runtime_error("pruned parent block is not active");
            case 11: throw std::runtime_error("parent chain changed during block recovery");
            default: throw std::logic_error("invalid parent recovery header action");
            }
        });
        return height;
    };
    auto request_peer = [&] {
        const auto peers = checked("getpeerinfo", UniValue(UniValue::VARR));
        std::vector<UniValue>::const_iterator peer,service;
        haskell::ParentReplayStore(haskell::ReplayStoreFlow::RECOVERY_PEER_REPLY,[&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return peer!=peers.getValues().end();
            case 2: return (*peer)["id"].isNum();
            case 3: return (*peer)["servicesnames"].isArray();
            case 4: service=(*peer)["servicesnames"].getValues().begin(); return 1;
            case 5: return service!=(*peer)["servicesnames"].getValues().end();
            case 6: return service->isStr();
            case 7: return service->get_str()=="NETWORK";
            case 8: ++service; return 1;
            case 9: ++peer; return 1;
            case 10: throw std::runtime_error("no parent peer offers full block service");
            case 11: {
                UniValue params(UniValue::VARR);
                params.push_back(hash); params.push_back((*peer)["id"]);
                checked("getblockfrompeer",params); return 1;
            }
            case 12: return peers.isArray();
            case 13: throw std::runtime_error("invalid parent peer response");
            case 14: peer=peers.getValues().begin(); return 1;
            default: throw std::logic_error("invalid parent recovery peer action");
            }
        });
    };
    UniValue reply;
    std::chrono::steady_clock::time_point deadline;
    int height=0;
    haskell::ParentReplayStore(haskell::ReplayStoreFlow::RECOVERY_BODY,[&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: check(); reply=rpc("getblock",block_params); return 1;
        case 2: case 15: return IsPrunedBlockReply(reply);
        case 3: case 17: return reply["error"].isNull();
        case 4: case 18: return !reply["result"].isNull();
        case 5: throw std::runtime_error("getblock failed: "+reply["error"].write());
        case 6: return allow_recovery;
        case 7: throw std::runtime_error("pruned parent block requires recovery outside consensus locks");
        case 8: deadline=std::chrono::steady_clock::now()+std::chrono::seconds{PARENT_RECOVERY_SECONDS}; return 1;
        case 9: height=active_height(); return 1;
        case 10: request_peer(); return 1;
        case 11: check(); return 1;
        case 12: return std::chrono::steady_clock::now()>=deadline;
        case 13: throw std::runtime_error("parent block recovery timed out");
        case 14: reply=rpc("getblock",block_params); return 1;
        case 16: wait(); return 1;
        case 19: throw std::runtime_error("getblock failed during parent block recovery");
        case 20: return active_height()==height;
        case 21: throw std::runtime_error("parent block height changed during recovery");
        default: throw std::logic_error("invalid parent recovery body action");
        }
    });
    return reply["result"];
}
} // namespace drivechain
#endif
