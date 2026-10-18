// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/drivechain_withdrawal_journal.h>

#include <hash.h>
#include <haskell/bridge.h>
#include <haskell/journal_constants.h>
#include <logging.h>
#include <random.h>
#include <streams.h>
#include <tinyformat.h>
#include <util/fs_helpers.h>

#include <cstdio>
#include <algorithm>

namespace node {

namespace {
//! File name of the journal inside the network data directory.
const char* const JOURNAL_FILENAME{drivechain::WITHDRAWAL_JOURNAL_FILENAME};

//! Distinguishes this file from any other serialized blob if one is ever
//! pointed at the wrong path.
const std::string JOURNAL_MAGIC{drivechain::WITHDRAWAL_JOURNAL_MAGIC};

bool ValidJournalEntry(const WithdrawalJournalEntry& entry, std::string& error)
{
    const uint8_t facts = (entry.m6id.IsNull() || entry.sidechain_txid.IsNull()) |
        (entry.destination.empty() << 1) | (entry.payout_script.empty() << 2) |
        (entry.payout_script.IsUnspendable() << 3) | (entry.bundle_bytes.empty() << 4);
    std::array<unsigned char,7> prefix{};
    const auto prefix_size = std::min(prefix.size(), entry.bundle_bytes.size());
    std::copy_n(entry.bundle_bytes.begin(), prefix_size, prefix.begin());
    DataStream request;
    request << entry.version << entry.state << entry.amount << entry.mainchain_fee
            << entry.sidechain_slot << entry.created_time << facts << uint8_t(prefix_size) << prefix;
    std::vector<unsigned char> ignored;
    if (!drivechain::haskell::WithdrawalBytes(drivechain::haskell::WithdrawalOp::JOURNAL_ADMISSION,
            {reinterpret_cast<const unsigned char*>(request.data()), request.size()}, ignored, &error)) return false;
    const auto no_witness_bytes = drivechain::haskell::WithdrawalTransport(entry.bundle_bytes, true);
    DataStream identity;
    identity << Hash(no_witness_bytes) << entry.m6id;
    return drivechain::haskell::WithdrawalBytes(drivechain::haskell::WithdrawalOp::JOURNAL_IDENTITY,
        {reinterpret_cast<const unsigned char*>(identity.data()), identity.size()}, ignored, &error);
}
} // namespace

fs::path WithdrawalJournalPath(const fs::path& data_dir)
{
    return data_dir / JOURNAL_FILENAME;
}

bool WriteWithdrawalJournal(const fs::path& data_dir, const WithdrawalJournalEntry& entry)
{
    const fs::path path = WithdrawalJournalPath(data_dir);

    std::string validation_error;
    if (!ValidJournalEntry(entry, validation_error)) {
        LogPrintf("%s: refusing invalid journal entry: %s\n", __func__, validation_error);
        return false;
    }

    uint16_t randv{0};
    GetRandBytes(Span{reinterpret_cast<unsigned char*>(&randv), sizeof(randv)});
    const fs::path path_tmp = data_dir / fs::PathFromString(strprintf("%s.%04x", JOURNAL_FILENAME, randv));

    try {
        HashWriter hasher;
        hasher << JOURNAL_MAGIC << entry;
        const uint256 checksum = hasher.GetHash();

        FILE* file = fsbridge::fopen(path_tmp, "wb");
        AutoFile fileout{file};
        const char* function = __func__;
        if (!drivechain::haskell::ParentReplayStore(
            drivechain::haskell::ReplayStoreFlow::WITHDRAWAL_JOURNAL_WRITE,
            [&](uint32_t action) -> uint32_t {
            switch (action) {
            case 1: return !fileout.IsNull();
            case 3: fileout << JOURNAL_MAGIC << entry << checksum; break;
            case 4: return fileout.Commit();
            case 6: fileout.fclose(); break;
            case 7: return RenameOver(path_tmp, path);
            case 2:
            case 5:
            case 8:
                if (action != 8) fileout.fclose();
                fs::remove(path_tmp);
                LogPrintf("%s: %s %s\n", function,
                    action == 2 ? "failed to open" : action == 5 ? "failed to flush" : "rename into place failed for",
                    fs::PathToString(action == 8 ? path : path_tmp));
                break;
            default: throw std::logic_error("Invalid Haskell withdrawal journal write action");
            }
            return 1;
        })) return false;
    } catch (const std::exception& e) {
        fs::remove(path_tmp);
        LogPrintf("%s: serialization error: %s\n", __func__, e.what());
        return false;
    }

    // Fsync the directory too, otherwise the rename itself can be lost.
    DirectoryCommit(data_dir);

    LogDebug(BCLog::VALIDATION,
             "drivechain withdrawal journal: recorded m6id=%s state=%d txid=%s\n",
             entry.m6id.GetHex(), int{entry.state}, entry.sidechain_txid.GetHex());
    return true;
}

WithdrawalJournalReadResult ReadWithdrawalJournal(
    const fs::path& data_dir,
    WithdrawalJournalEntry& entry,
    std::string* error)
{
    if (error) error->clear();
    const fs::path path = WithdrawalJournalPath(data_dir);
    if (!fs::exists(path)) return WithdrawalJournalReadResult::MISSING;

    try {
        FILE* file = fsbridge::fopen(path, "rb");
        AutoFile filein{file};
        std::string magic;
        WithdrawalJournalEntry parsed;
        uint256 checksum;
        std::string validation_error;
        const char* function = __func__;
        const auto accepted = drivechain::haskell::ParentReplayStore(
            drivechain::haskell::ReplayStoreFlow::WITHDRAWAL_JOURNAL_READ,
            [&](uint32_t action) -> uint32_t {
            switch (action) {
            case 1: return !filein.IsNull();
            case 3: filein >> magic >> parsed >> checksum; break;
            case 4: return magic == JOURNAL_MAGIC;
            case 6: {
                HashWriter hasher;
                hasher << JOURNAL_MAGIC << parsed;
                return hasher.GetHash() == checksum;
            }
            case 8: return ValidJournalEntry(parsed, validation_error);
            case 10: entry = std::move(parsed); break;
            case 2:
            case 5:
            case 7:
            case 9: {
                const auto message = action == 2 ? strprintf("failed to open %s", fs::PathToString(path)) :
                    action == 5 ? strprintf("%s is not a withdrawal journal", fs::PathToString(path)) :
                    action == 7 ? strprintf("checksum mismatch in %s", fs::PathToString(path)) : validation_error;
                if (error) *error = message;
                if (action == 9) LogPrintf("%s: invalid journal %s: %s\n", function, fs::PathToString(path), message);
                else LogPrintf("%s: %s%s\n", function, message, action == 7 ? "; refusing to act on it" : "");
                break;
            }
            default: throw std::logic_error("Invalid Haskell withdrawal journal read action");
            }
            return 1;
        });
        return accepted ? WithdrawalJournalReadResult::OK : WithdrawalJournalReadResult::CORRUPT;
    } catch (const std::exception& e) {
        const std::string message = strprintf("failed to read %s: %s", fs::PathToString(path), e.what());
        if (error) *error = message;
        LogPrintf("%s: %s\n", __func__, message);
        return WithdrawalJournalReadResult::CORRUPT;
    }
}

bool ClearWithdrawalJournal(const fs::path& data_dir)
{
    const fs::path path = WithdrawalJournalPath(data_dir);
    std::error_code ec;
    const char* function = __func__;
    return drivechain::haskell::ParentReplayStore(
        drivechain::haskell::ReplayStoreFlow::WITHDRAWAL_JOURNAL_CLEAR,
        [&](uint32_t action) -> uint32_t {
        switch (action) {
        case 1: return fs::exists(path);
        case 2: fs::remove(path, ec); return !ec;
        case 3: LogPrintf("%s: failed to remove %s: %s\n", function, fs::PathToString(path), ec.message()); break;
        case 4: DirectoryCommit(data_dir); break;
        default: throw std::logic_error("Invalid Haskell withdrawal journal clear action");
        }
        return 1;
    });
}

} // namespace node
