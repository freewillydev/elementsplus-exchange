#!/usr/bin/env python3
"""Mandatory parallel Utreexo commitments with unchanged confidential validation."""
from copy import deepcopy
from io import BytesIO
from test_framework.test_framework import BitcoinTestFramework
from test_framework.messages import CBlock, tx_from_hex
from test_framework.util import assert_equal


class UtreexoTest(BitcoinTestFramework):
    def set_test_params(self):
        self.chain = "elementsutreexo"
        self.num_nodes = 2
        self.setup_clean_chain = True
        base = ["-initialfreecoins=2100000000000000", "-con_blocksubsidy=0",
                "-con_connect_genesis_outputs=1", "-blindedaddresses=1"]
        self.extra_args = [base + ["-rangeproofcache=1", "-anyonecanspendaremine=1"],
                           base + ["-rangeproofcache=0"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def init_wallet(self, *, node):
        self.nodes[node].createwallet(wallet_name=self.default_wallet_name,
                                     descriptors=True, load_on_startup=True)
        self.nodes[node].rescanblockchain(0)

    def agreement(self):
        self.sync_blocks()
        a, b = self.nodes
        tip = a.getbestblockhash()
        assert_equal(tip, b.getbestblockhash())
        assert_equal(a.getblockheader(tip)["utreexo"], b.getblockheader(tip)["utreexo"])
        assert_equal(a.gettxoutsetinfo()["hash_serialized_3"], b.gettxoutsetinfo()["hash_serialized_3"])
        return tip

    def run_test(self):
        a, b = self.nodes
        self.generate(a, 1)
        # Initial test coins use OP_TRUE. Confirm a normal wallet output first,
        # so proof tests are not rejected earlier by standard-input policy.
        a.sendtoaddress(a.getnewaddress(), a.getbalance()["bitcoin"], "", "", True)
        self.generate(a, 1)
        self.agreement()
        self.disconnect_nodes(0, 1)
        txid = a.sendtoaddress(b.getnewaddress(), 2)
        raw = a.getrawtransaction(txid)
        tx = tx_from_hex(raw)
        assert any(w.vchRangeproof for w in tx.wit.vtxoutwit)

        # testmempoolaccept warms validation caches without inserting the tx.
        # Repeat with range-proof caching disabled and enabled after restart.
        for cache in [0, 1]:
            if cache:
                self.restart_node(1, self.extra_args[1] + ["-rangeproofcache=1"])
                b = self.nodes[1]
            for _ in range(2):
                accepted = b.testmempoolaccept([raw])[0]
                assert accepted["allowed"], accepted
                for field in ["vchRangeproof", "vchSurjectionproof"]:
                    broken = deepcopy(tx)
                    witness = next(w for w in broken.wit.vtxoutwit if getattr(w, field))
                    proof = bytearray(getattr(witness, field))
                    proof[len(proof)//2] ^= 1
                    setattr(witness, field, bytes(proof))
                    rejected = b.testmempoolaccept([broken.serialize().hex()])[0]
                    assert not rejected["allowed"], rejected
        self.connect_nodes(0, 1)
        b.sendrawtransaction(raw)
        self.sync_mempools()

        block = CBlock()
        block.deserialize(BytesIO(bytes.fromhex(a.getnewblockhex())))
        assert block.utreexo_roots
        altered = deepcopy(block)
        altered.utreexo_roots[0] ^= 1
        altered.rehash()
        assert_equal(a.submitblock(altered.serialize().hex()), "bad-utreexo-root")
        absent = deepcopy(block)
        absent.nVersion &= ~(1 << 15)
        absent.rehash()
        assert_equal(a.submitblock(absent.serialize().hex()), "bad-utreexo-header")
        self.generate(a, 1)
        tip = self.agreement()
        assert_equal(b.gettransaction(txid)["confirmations"], 1)

        issued = a.issueasset(5, 1)
        self.generate(a, 1)
        a.reissueasset(issued["asset"], 1)
        self.generate(a, 1)
        a.sendtoaddress(b.getnewaddress(), 1, "", "", False, False, 1, "UNSET", False, issued["asset"])
        self.generate(a, 1)
        final = self.agreement()
        committed = a.getblockheader(final)["utreexo"]
        self.restart_node(0)
        self.restart_node(1)
        self.connect_nodes(0, 1)
        assert_equal(self.nodes[0].getblockheader(final)["utreexo"], committed)
        a, b = self.nodes
        for node in [a,b]:
            node.invalidateblock(final)
            node.reconsiderblock(final)
        self.agreement()
        self.restart_node(1, self.extra_args[1] + ["-reindex-chainstate"])
        self.connect_nodes(0, 1)
        self.agreement()
        assert_equal(a.getblockheader(tip)["utreexo"], b.getblockheader(tip)["utreexo"])


if __name__ == "__main__":
    UtreexoTest(__file__).main()
