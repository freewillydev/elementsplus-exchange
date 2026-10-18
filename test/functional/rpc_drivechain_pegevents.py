#!/usr/bin/env python3
# Copyright (c) 2026 The Elements Core developers
# Distributed under the MIT software license.
"""Exercise sidechain-only peg-event ranges without an L1 service or wallet."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class DrivechainPegEventsTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-drivechainl1blocksync=0", "-mainchainrpcport=1", "-mainchainrpctimeout=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        assert_equal(node.getdrivechainpegevents()["range"], {"start_height": 0, "end_height": 0})
        self.generatetoaddress(node, 3, node.getnewaddress())
        tip = {"hash": node.getbestblockhash(), "height": 3}
        for wallet in node.listwallets():
            node.unloadwallet(wallet)
        wallet_directory = node.listwalletdir()
        mempool = node.getrawmempool()

        default = node.getdrivechainpegevents()
        assert_equal(default, {
            "schema_version": 1, "sidechain_id": 24, "sidechain_tip": tip,
            "range": {"start_height": 0, "end_height": 3}, "events": [],
        })
        for start, count, end in ((0, 1, 0), (0, 10000, 3), (3, 1, 3), (1, 2, 2)):
            result = node.getdrivechainpegevents(start, count, False)
            assert_equal(result["range"], {"start_height": start, "end_height": end})
            assert_equal(result["sidechain_tip"], tip)
            assert_equal(result["events"], [])
        for start in (-2147483648, -1, 4, 2147483647):
            for count in (0, 1, 10001):
                assert_raises_rpc_error(-8, "start_height is outside the active sidechain",
                                        node.getdrivechainpegevents, start, count, False)
        for count in (-2147483648, -1, 0, 10001, 2147483647):
            assert_raises_rpc_error(-8, "count must be between 1 and 10000",
                                    node.getdrivechainpegevents, 0, count, False)
        assert_equal(node.listwallets(), [])
        assert_equal(node.listwalletdir(), wallet_directory)
        assert_equal(node.getrawmempool(), mempool)
        self.restart_node(0)
        assert_equal(node.getdrivechainpegevents(), default)
        assert node.verifychain(4, 0)


if __name__ == "__main__":
    DrivechainPegEventsTest(__file__).main()
