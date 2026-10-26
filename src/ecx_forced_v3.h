#ifndef ELEMENTS_ECX_FORCED_V3_H
#define ELEMENTS_ECX_FORCED_V3_H
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>
class CTransaction;
struct CAsset;

namespace ecx {
/** Canonical signed payload, not a source receipt or execution certificate.
 * Constructed only by the concrete linked Rust checker and Haskell native
 * output/clock admission rules. The caller still authenticates its source
 * location, queue/head and pinned fresh outer deployment. */
class VerifiedForcedActionV3
{
    std::vector<unsigned char> payload;
    std::array<unsigned char, 50> metadata;
    VerifiedForcedActionV3(std::vector<unsigned char> p, std::array<unsigned char, 50> m)
        : payload(std::move(p)), metadata(m) {}
    friend std::optional<VerifiedForcedActionV3> VerifyForcedActionV3Output(
        const CTransaction&, size_t, const CAsset&, std::span<const unsigned char, 259>,
        std::span<const unsigned char, 32>, uint64_t, std::string&);

public:
    const std::vector<unsigned char>& Payload() const { return payload; }
    uint8_t Kind() const { return metadata[1]; }
    std::span<const unsigned char, 32> ActionHash() const { return std::span<const unsigned char, 50>{metadata}.subspan<2, 32>(); }
};
bool ForcedActionV3BackendAvailable();
/** Borrowed output facts and native signature verification only; no workflow
 * dispatch and no authenticated receipt construction. */
std::vector<unsigned char> ReadForcedActionV3Output(const CTransaction&, size_t,
    const CAsset&, std::span<const unsigned char,259>, std::span<const unsigned char,32>,
    std::optional<uint64_t>, uint32_t, std::span<const unsigned char>);
/** Canonical/signature policy only, without an authenticated admission clock. */
bool IsCanonicalForcedActionV3Output(const CTransaction&, size_t, const CAsset&,
    std::span<const unsigned char,259>,std::span<const unsigned char,32>,std::string&);
std::optional<VerifiedForcedActionV3> VerifyForcedActionV3Output(
    const CTransaction& transaction, size_t output, const CAsset& policy_asset,
    std::span<const unsigned char, 259> canonical_economics,
    std::span<const unsigned char, 32> pinned_economic_hash, uint64_t authenticated_parent,
    std::string& error);
} // namespace ecx
#endif
