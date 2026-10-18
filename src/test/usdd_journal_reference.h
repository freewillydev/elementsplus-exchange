#pragma once
// Preserved pre-migration journal parser; test-only independent reference.
#include <script/usdd_sp1_annex.h>

namespace usdd_reference {
using namespace usdd;
enum class Sp1JournalIdentityError {
    OK,
    TRUNCATED,
    BAD_MAGIC,
    BAD_SCHEMA,
    BAD_DIGEST_MODE,
    GUEST_NOT_SUCCESSFUL,
    BAD_STATEMENT_KIND,
    WRONG_GUEST_PROGRAM_ID,
    LENGTH_MISMATCH,
    PAYLOAD_DIGEST_MISMATCH,
    BAD_PAYLOAD_KIND,
    BAD_PAYLOAD_LENGTH,
};

/**
 * Extract the deployment domain from a canonical inbound strict journal.
 *
 * The proof verifier still performs the complete typed Rust decode. This
 * small consensus parser deliberately validates every field needed to make
 * the fixed offset unambiguous, verifies SHA256(payload), and accepts only
 * the exact V1 deposit/heartbeat payload length ranges. It never trusts a
 * parallel annex-header domain that the proved journal did not authenticate.
 */
inline Sp1JournalIdentityError NativeJournal(
    Span<const unsigned char> public_values,
    Span<const unsigned char> annex_guest_program_id,
    std::array<unsigned char, 32>& inbound_mint_domain_id)
{
    static constexpr std::array<unsigned char, 8> JOURNAL_MAGIC{{'U', 'S', 'D', 'D', 'J', 'N', 'L', '1'}};
    static constexpr std::array<unsigned char, 8> SUCCESS_MARKER{{'S', 'U', 'C', 'C', 'E', 'S', 'S', '!'}};
    static constexpr std::size_t JOURNAL_HEADER_SIZE{88};
    static constexpr std::size_t PAYLOAD_IDENTITY_SIZE{36};
    static constexpr uint32_t HEARTBEAT_PAYLOAD_SIZE{790};
    static constexpr uint32_t DEPOSIT_PAYLOAD_MIN_SIZE{892};
    static constexpr uint32_t DEPOSIT_PAYLOAD_MAX_SIZE{13'115};
    static constexpr uint16_t ENCODING_SCHEMA{2};
    static constexpr uint16_t DEPOSIT_PUBLIC_OUTPUT_TAG{0x5201};
    static constexpr uint16_t HEARTBEAT_PUBLIC_OUTPUT_TAG{0x5204};

    inbound_mint_domain_id.fill(0);
    if (public_values.size() < JOURNAL_HEADER_SIZE + PAYLOAD_IDENTITY_SIZE) {
        return Sp1JournalIdentityError::TRUNCATED;
    }
    if (!std::equal(JOURNAL_MAGIC.begin(), JOURNAL_MAGIC.end(), public_values.begin())) {
        return Sp1JournalIdentityError::BAD_MAGIC;
    }
    if (public_values[8] != 0 || public_values[9] != ENCODING_SCHEMA) {
        return Sp1JournalIdentityError::BAD_SCHEMA;
    }
    if (public_values[10] != ElementsDrivechainIdentity::USDD_SP1_ANNEX_DIGEST_MODE) {
        return Sp1JournalIdentityError::BAD_DIGEST_MODE;
    }
    if (!std::equal(SUCCESS_MARKER.begin(), SUCCESS_MARKER.end(), public_values.begin() + 11)) {
        return Sp1JournalIdentityError::GUEST_NOT_SUCCESSFUL;
    }
    if (public_values[19] != ElementsDrivechainIdentity::USDD_SP1_ANNEX_STATEMENT_KIND) {
        return Sp1JournalIdentityError::BAD_STATEMENT_KIND;
    }
    if (annex_guest_program_id.size() != 32 ||
        !std::equal(annex_guest_program_id.begin(), annex_guest_program_id.end(),
                    public_values.begin() + 20)) {
        return Sp1JournalIdentityError::WRONG_GUEST_PROGRAM_ID;
    }

    const uint32_t payload_size = ReadUint32BE(public_values, 84);
    if (uint64_t{JOURNAL_HEADER_SIZE} + payload_size != public_values.size()) {
        return Sp1JournalIdentityError::LENGTH_MISMATCH;
    }
    const Span<const unsigned char> payload = public_values.subspan(JOURNAL_HEADER_SIZE, payload_size);
    std::array<unsigned char, CSHA256::OUTPUT_SIZE> payload_sha256{};
    CSHA256().Write(payload.data(), payload.size()).Finalize(payload_sha256.data());
    if (!std::equal(payload_sha256.begin(), payload_sha256.end(), public_values.begin() + 52)) {
        return Sp1JournalIdentityError::PAYLOAD_DIGEST_MISMATCH;
    }
    if (payload[0] != 0 || payload[1] != ENCODING_SCHEMA) {
        return Sp1JournalIdentityError::BAD_SCHEMA;
    }
    const uint16_t payload_tag = (uint16_t{payload[2]} << 8) | uint16_t{payload[3]};
    if (payload_tag == HEARTBEAT_PUBLIC_OUTPUT_TAG) {
        if (payload_size != HEARTBEAT_PAYLOAD_SIZE) {
            return Sp1JournalIdentityError::BAD_PAYLOAD_LENGTH;
        }
    } else if (payload_tag == DEPOSIT_PUBLIC_OUTPUT_TAG) {
        if (payload_size < DEPOSIT_PAYLOAD_MIN_SIZE || payload_size > DEPOSIT_PAYLOAD_MAX_SIZE) {
            return Sp1JournalIdentityError::BAD_PAYLOAD_LENGTH;
        }
    } else {
        return Sp1JournalIdentityError::BAD_PAYLOAD_KIND;
    }

    std::copy(payload.begin() + 4, payload.begin() + 36,
              inbound_mint_domain_id.begin());
    return Sp1JournalIdentityError::OK;
}

} // namespace usdd_reference
