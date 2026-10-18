// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#include <bitcoinconsensus.h>

#include <array>
#include <iostream>
#include <stdexcept>

int main()
{
    // Bitcoin-mode transaction: one empty-script input, no outputs, no witness.
    std::array<unsigned char, 52> tx{};
    tx[0] = 2;
    tx[4] = 1;
    for (unsigned i : {37, 38, 39, 40, 42, 43, 44, 45}) tx[i] = 255;
    const unsigned char script = 0x51;
    std::array<unsigned char, 10> amount{};
    amount[0] = 1;
    unsigned checks = 0;
    const auto check = [&](const unsigned char* input, unsigned size, unsigned index,
                           unsigned flags, const unsigned char* value, unsigned value_size,
                           bool with_amount, int expected, bitcoinconsensus_error wanted) {
        bitcoinconsensus_error error = bitcoinconsensus_ERR_OK;
        const auto run = [&](bitcoinconsensus_error* out) {
            return with_amount
                ? bitcoinconsensus_verify_script_with_amount(nullptr, &script, 1, value,
                    value_size, input, size, index, flags, out)
                : bitcoinconsensus_verify_script(nullptr, &script, 1, input, size, index, flags, out);
        };
        if (run(&error) != expected || error != wanted || run(nullptr) != expected)
            throw std::runtime_error("consensus reader case " + std::to_string(checks));
        ++checks;
    };
    for (bool with_amount : {false, true}) {
        for (unsigned size = 0; size < 51; ++size)
            check(tx.data(), size, 0, 0, amount.data(), 9, with_amount, 0, bitcoinconsensus_ERR_TX_DESERIALIZE);
        for (unsigned size : {0, 1, 51})
            check(nullptr, size, 0, 0, amount.data(), 9, with_amount, 0, bitcoinconsensus_ERR_TX_DESERIALIZE);
        check(tx.data(), 51, 0, 0, amount.data(), 9, with_amount, 1, bitcoinconsensus_ERR_OK);
        check(tx.data(), 52, 0, 0, amount.data(), 9, with_amount, 0, bitcoinconsensus_ERR_TX_SIZE_MISMATCH);
        check(tx.data(), 52, 1, 0, amount.data(), 9, with_amount, 0, bitcoinconsensus_ERR_TX_INDEX);
        check(nullptr, 0, 0, 1U << 31, amount.data(), 9, with_amount, 0, bitcoinconsensus_ERR_INVALID_FLAGS);
    }
    for (unsigned size = 0; size < 9; ++size)
        check(tx.data(), 51, 0, 0, amount.data(), size, true, 0, bitcoinconsensus_ERR_TX_DESERIALIZE);
    for (unsigned size : {0, 9})
        check(tx.data(), 51, 0, 0, nullptr, size, true, 0, bitcoinconsensus_ERR_TX_DESERIALIZE);
    check(tx.data(), 51, 0, 0, amount.data(), 10, true, 1, bitcoinconsensus_ERR_OK);
    check(nullptr, 0, 0, 1U << 31, nullptr, 0, true, 0, bitcoinconsensus_ERR_TX_DESERIALIZE);
    check(nullptr, 0, 0, bitcoinconsensus_SCRIPT_FLAGS_VERIFY_WITNESS, nullptr, 0,
          false, 0, bitcoinconsensus_ERR_AMOUNT_REQUIRED);
    std::cout << checks << " consensus reader cases passed\n";
}
