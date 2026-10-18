// Preserve the authenticated historical checkpoint separately from Betanet's
// empty state immediately before parent activation.
#ifndef BITCOIN_ELEMENTS_DRIVECHAIN_BOOTSTRAP_H
#define BITCOIN_ELEMENTS_DRIVECHAIN_BOOTSTRAP_H
#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <elements_drivechain_identity.h>
namespace ElementsDrivechainBootstrap {
struct Slot { uint8_t slot; const char* active; const char* ctip_txid; uint32_t ctip_vout; int64_t ctip_value; };
#include <haskell/bootstrap_constants.h>
}
#endif
