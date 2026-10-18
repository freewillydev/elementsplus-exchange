// Pre-migration activation fact predicates, retained for differential tests.
static int ReferenceActivationFacts(const std::array<uint256,40>& hashes)
{
    if (hashes[0] != hashes[1] ||
        hashes[2] !=
            hashes[3] ||
        hashes[4] !=
            hashes[5] ||
        hashes[4] !=
            hashes[6] ||
        hashes[7] !=
            hashes[8] ||
        hashes[9] !=
            hashes[10] ||
        hashes[11] !=
            hashes[12] ||
        hashes[13] !=
            hashes[14] ||
        !std::equal(ECX_BOND_STAGING_RENDERER_DOMAIN_V18.begin(),ECX_BOND_STAGING_RENDERER_DOMAIN_V18.end(),hashes[14].begin()) ||
        hashes[15] !=
            hashes[16] ||
        !std::equal(ECX_BIP341_NUMS_XONLY.begin(),ECX_BIP341_NUMS_XONLY.end(),hashes[16].begin()) ||
        hashes[17] !=
            hashes[18] ||
        hashes[19] !=
            hashes[20] ||
        hashes[21] !=
            hashes[22] ||
        hashes[22] == hashes[23] ||
        hashes[22] ==
            hashes[24] ||
        hashes[25] !=
            hashes[26] ||
        hashes[25] !=
            hashes[27] ||
        hashes[28] !=
            hashes[24] ||
        hashes[24] == hashes[23] ||
        hashes[29] !=
            hashes[30]) {
        return 1;
    }
    if (hashes[31].IsNull() || hashes[32].IsNull() ||
        hashes[33].IsNull() ||
        hashes[34].IsNull() ||
        hashes[35].IsNull() ||
        hashes[36].IsNull() ||
        hashes[37].IsNull() ||
        hashes[38].IsNull() ||
        hashes[39].IsNull() ||
        hashes[22].IsNull() ||
        hashes[24].IsNull() ||
        hashes[18].IsNull() ||
        hashes[20].IsNull()) {
        return 2;
    }

    return 0;
}
