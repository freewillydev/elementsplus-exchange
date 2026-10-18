#!/usr/bin/env python3
# Copyright (c) 2026 The Elements Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Reconstruct generic withdrawal proofs and reject unavailable pruned history."""

from hashlib import sha256

from test_framework.messages import CTxOut
from test_framework.script import CScript, OP_RETURN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet


class WithdrawalProofTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [["-drivechainl1blocksync=0", "-prune=1", "-fastprune=1"]]

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)
        wallet.rescan_utxos()
        assert_equal(node.getusddwithdrawalaccumulator()["count"], 0)
        vault = bytes(range(32))
        recipient = bytes.fromhex("000000000000000000000000000000000000beef")
        burns, blocks = [], []
        for amount in (777, 888):
            payload = b"USDD\x01" + vault + recipient + amount.to_bytes(8, "big")
            assert_equal(len(payload), 65)
            tx = wallet.create_self_transfer()["tx"]
            tx.vout[0].nValue.setToAmount(tx.vout[0].nValue.getAmount() - amount * 100)
            vout = len(tx.vout)
            tx.vout.append(CTxOut(amount * 100, CScript([OP_RETURN, payload])))
            raw = tx.serialize().hex()
            decoded = node.decoderawtransaction(raw)
            burns.append({"txid": decoded["txid"], "sent_vout": vout,
                          "asset": decoded["vout"][vout]["asset"]})
            blocks.append(self.generateblock(node, wallet.get_address(), [raw])["hash"])
            self.generateblock(node, wallet.get_address(), [])
            wallet.rescan_utxos()

        def check(index, count, blockhash=None):
            args = [index] if blockhash is None else [index, blockhash]
            proof = node.getusddwithdrawalproof(*args)
            accumulator = node.getusddwithdrawalaccumulator(*([] if blockhash is None else [blockhash]))
            assert_equal(proof["index"], index)
            assert_equal(proof["count"], count)
            assert_equal(accumulator["count"], count)
            assert_equal(proof["root"], accumulator["root"])
            assert_equal(proof["txid"], burns[index]["txid"])
            assert_equal(proof["vout"], burns[index]["sent_vout"])
            assert_equal(proof["asset"], burns[index]["asset"])
            assert_equal(proof["amount_usdt_micro"], (777, 888)[index])
            assert_equal(proof["vault_id"], vault.hex())
            assert_equal(proof["recipient"], recipient.hex())
            assert_equal(proof["authorizing"], False)
            assert_equal(len(proof["siblings"]), 64)
            digest = bytes.fromhex(proof["leaf"])
            for level, sibling in enumerate(proof["siblings"]):
                sibling = bytes.fromhex(sibling)
                left, right = (sibling, digest) if (index >> level) & 1 else (digest, sibling)
                digest = sha256(b"\x01" + left + right).digest()
            assert_equal(digest.hex(), proof["root"])
            return proof

        original = [check(index, 2) for index in range(2)]
        check(0, 1, blocks[0])
        node.invalidateblock(blocks[1])
        check(0, 1)
        assert_raises_rpc_error(-8, "Withdrawal index is outside this accumulator", node.getusddwithdrawalproof, 1)
        assert_raises_rpc_error(-5, "Block is not in the active chain", node.getusddwithdrawalproof, 1, blocks[1])
        assert_raises_rpc_error(-5, "Block is not in the active chain", node.getusddwithdrawalaccumulator, blocks[1])
        node.reconsiderblock(blocks[1])
        for index in range(2):
            assert_equal(check(index, 2), original[index])

        # Move the burn blocks out of the retention window and prune their files.
        self.restart_node(0)
        for index in range(2):
            assert_equal(check(index, 2), original[index])
        self.generate(node, 1000)
        node.pruneblockchain(node.getblockcount() - 288)
        assert_raises_rpc_error(-1, "Block not available (pruned data)", node.getblock, blocks[0])
        for restart in (False, True):
            if restart:
                self.restart_node(0)
            accumulator = node.getusddwithdrawalaccumulator()
            assert_equal(accumulator["count"], 2)
            assert_equal(accumulator["root"], original[0]["root"])
            for index in range(2):
                assert_raises_rpc_error(-1,
                    "A withdrawal-containing block is pruned or unreadable; use an archival node or indexer",
                    node.getusddwithdrawalproof, index)


if __name__ == "__main__":
    WithdrawalProofTest(__file__).main()
