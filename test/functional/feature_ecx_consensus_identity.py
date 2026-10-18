#!/usr/bin/env python3
# Copyright (c) 2026 The Elements Core developers
# Distributed under the MIT software license.
"""Fail closed on ECX/private-BMM configuration drift and direct BMM mining."""

import os
import shutil
import subprocess

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal, assert_raises_rpc_error


class EcxConsensusIdentityTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 4
        self.correct_args = [
            "-ecxprivatebmmcheckpoint=1",
            "-ecxprivatebmmactivationheight=3",
            "-drivechainl1blocksync=0",
        ]
        self.audit_args = [
            "-ecxactivationheight=3",
            "-ecxgenesisstateoutpoint=1111111111111111111111111111111111111111111111111111111111111111:0",
            "-ecxgenesisstateroot=3dd845218b21b34171bc5df2dbd69082861ede67dc92cda6e713566fb62fda62",
            "-ecxchainid=1919191919191919191919191919191919191919191919191919191919191919",
            "-ecxforcedactiondomain=4545454545454545454545454545454545454545454545454545454545454545",
            "-ecxdepositinboxdomain=4646464646464646464646464646464646464646464646464646464646464646",
            "-ecxcollateralvaultscript=5120a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
            "-ecxcollateralvaultscripthash=fe71d55db3b84e12e09fec4a925b73bd98465de02a2ecc58bc4c6596f36ac126",
            "-drivechainl1blocksync=0",
        ]
        # Node 1 proves that an explicitly requested reindex remains valid on
        # a genuinely fresh data directory; it is converted below into a
        # pre-identity legacy fixture after it has material chain data.
        self.extra_args = [self.correct_args, ["-reindex"], [], []]

    def setup_network(self):
        # These nodes deliberately exercise incompatible deployment histories;
        # never connect them to one another.
        self.setup_nodes()

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        help_text = subprocess.check_output(
            [self.options.bitcoind, "-help-debug"],
            text=True,
            stderr=subprocess.STDOUT,
        )
        if "ecxprivatebmmcheckpoint" not in help_text:
            raise SkipTest("private ECX BMM catalogue is not compiled")

    def run_test(self):
        node = self.nodes[0]
        legacy_node = self.nodes[1]
        collision_node = self.nodes[2]
        audit_node = self.nodes[3]
        identity_path = node.chain_path / "ecx_consensus.dat"
        assert os.path.isfile(identity_path)
        pegged_asset = node.getsidechaininfo()["pegged_asset"]
        other_asset = f"{int(pegged_asset, 16) ^ 1:064x}"

        for target, message in [
            (legacy_node, "private BMM checkpoint mode is disabled"),
            (node, "private BMM block template is unavailable"),
        ]:
            before = target.getbestblockhash()
            assert_raises_rpc_error(-1, message, target.generateprivatebmmblock)
            assert_equal(target.getblockcount(), 0)
            assert_equal(target.getbestblockhash(), before)

        # An invalid reserved genesis outpoint must be rejected before a fresh
        # data directory is bound or any chain database is created.  Exercise
        # every synthetic record namespace, not just the ECX trackers.
        self.stop_node(2)
        collision_chain_dir = collision_node.chain_path
        shutil.rmtree(collision_chain_dir)
        os.makedirs(collision_chain_dir)
        collision_identity_path = os.path.join(
            collision_chain_dir, "ecx_consensus.dat")
        # Reject migrated configuration rules before binding a fresh identity.
        # Combined failures also pin validation order: height, domains, digest.
        digest_error = "-ecxcollateralvaultscripthash does not match the frozen raw script bytes"
        invalid_configurations = [
            ({"ecxactivationheight": str(height)}, "invalid -ecxactivationheight")
            for height in (-9223372036854775808, -1, 0, 2147483647, 9223372036854775807)
        ] + [
            ({"ecxdepositinboxdomain": "45" * 32}, "ECX forced-action and deposit inbox domains must differ"),
            ({"ecxcollateralvaultscripthash": "00" * 32}, digest_error),
            ({"ecxcollateralvaultscripthash": "01" * 32}, digest_error),
            ({"ecxactivationheight": "0", "ecxdepositinboxdomain": "45" * 32,
              "ecxcollateralvaultscripthash": "00" * 32}, "invalid -ecxactivationheight"),
            ({"ecxdepositinboxdomain": "45" * 32, "ecxcollateralvaultscripthash": "00" * 32},
             "ECX forced-action and deposit inbox domains must differ"),
        ]
        for overrides, message in invalid_configurations:
            options = [arg for arg in self.audit_args if arg[1:].split("=", 1)[0] not in overrides]
            options += [f"-{name}={value}" for name, value in overrides.items()]
            collision_node.assert_start_raises_init_error(
                extra_args=options, expected_msg=message, match=ErrorMatch.PARTIAL_REGEX)
            assert not os.path.exists(collision_identity_path)
            assert not os.path.exists(os.path.join(collision_chain_dir, "chainstate"))

        reserved_outpoints = [
            "e31f7fb1e9489bfb9f6a73c10f80ecdcce1f276fbdf0cf85c02e3bcf174dc041:0",
            "c3fd019db845c81a68a561f5ab67d92c3ab2505cb2c8212f02511e07e8c2f2a1:0",
            "0cc4c302121a9d75c8a0e520253c1740520a6d6f4d03db6947a99565175d6586:0",
            "f0bcf7ca88c8a7c66d74d5540d5458ead1a15df5a8b6b98c08032a1300579ff9:0",
            "2d15ce4b128995291c4e38d36b8ae411a15bf80d7acee97cf5f58d2fc4de52b1:0",
        ]
        for outpoint in reserved_outpoints:
            collision_node.assert_start_raises_init_error(
                extra_args=[
                    "-ecxactivationheight=10",
                    f"-ecxgenesisstateoutpoint={outpoint}",
                    "-ecxgenesisstateroot=3dd845218b21b34171bc5df2dbd69082861ede67dc92cda6e713566fb62fda62",
                    "-ecxchainid=1919191919191919191919191919191919191919191919191919191919191919",
                    "-ecxforcedactiondomain=4545454545454545454545454545454545454545454545454545454545454545",
                    "-ecxdepositinboxdomain=4646464646464646464646464646464646464646464646464646464646464646",
                    "-ecxcollateralvaultscript=5120a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                    "-ecxcollateralvaultscripthash=fe71d55db3b84e12e09fec4a925b73bd98465de02a2ecc58bc4c6596f36ac126",
                    "-drivechainl1blocksync=0",
                ],
                expected_msg="ECX genesis state outpoint collides with a reserved chainstate record",
                match=ErrorMatch.PARTIAL_REGEX,
            )
            assert not os.path.exists(collision_identity_path)

        # Exercise the on-disk startup audit, rather than only its pure header
        # validators. Build a legacy height-3 history without ECX extensions,
        # then give it a genuine identity record produced for ECX activation at
        # height 3. The identity matches the requested runtime configuration,
        # but the persisted header tree does not and must fail before replay.
        self.generatetoaddress(
            audit_node, 3, audit_node.getnewaddress(), sync_fun=self.no_op)
        assert_equal(audit_node.getblockcount(), 3)
        self.stop_node(3)
        audit_identity_path = audit_node.chain_path / "ecx_consensus.dat"

        shutil.rmtree(collision_chain_dir)
        os.makedirs(collision_chain_dir)
        self.start_node(2, extra_args=self.audit_args)
        assert os.path.isfile(collision_identity_path)
        self.stop_node(2)
        shutil.copyfile(collision_identity_path, audit_identity_path)

        audit_node.assert_start_raises_init_error(
            extra_args=self.audit_args + ["-trim_headers=1"],
            expected_msg="ECX consensus identity: persisted block-index header [0-9a-f]{64} at height 3 violates ECX rules: .*restart with -reindex",
            match=ErrorMatch.PARTIAL_REGEX,
        )
        with open(audit_node.debug_log_path, encoding="utf-8") as debug_log:
            audit_failure_log = debug_log.read()
        assert "persisted block-index header" in audit_failure_log
        assert "violates ECX rules" in audit_failure_log
        assert "restart with -reindex" in audit_failure_log

        # A full block-index rebuild must re-run contextual header checks. The
        # legacy height-3 block is rejected, leaving a clean height-2 index that
        # subsequently survives an ordinary audited restart. Chainstate-only
        # reindex is intentionally insufficient for this recovery.
        self.start_node(3, extra_args=self.audit_args + ["-reindex"])
        self.wait_until(lambda: audit_node.getblockcount() == 2)
        assert audit_node.verifychain(4, 0)
        self.stop_node(3)
        self.start_node(3, extra_args=self.audit_args + ["-trim_headers=1"])
        assert_equal(audit_node.getblockcount(), 2)
        assert audit_node.verifychain(4, 0)
        self.stop_node(3)

        # Reproduce the original defect boundary: a legacy datadir that has
        # already crossed the requested activation height must not be silently
        # adopted and have its stored headers reinterpreted as ECX/BMM blocks.
        legacy_identity_path = legacy_node.chain_path / "ecx_consensus.dat"
        assert os.path.isfile(legacy_identity_path)
        self.generatetoaddress(
            legacy_node, 3, legacy_node.getnewaddress(), sync_fun=self.no_op)
        self.stop_node(1)
        # Model a data directory created by a binary predating the identity
        # record.  The upgraded node must inspect the stored ancestry before
        # writing its first record.
        os.remove(legacy_identity_path)
        assert not os.path.exists(legacy_identity_path)
        legacy_node.assert_start_raises_init_error(
            extra_args=["-reindex"],
            expected_msg="cannot first-bind an ECX consensus identity while reindexing existing data",
            match=ErrorMatch.PARTIAL_REGEX,
        )
        legacy_node.assert_start_raises_init_error(
            extra_args=self.correct_args,
            expected_msg="ECX consensus identity: .*block-index branch already reaches header",
            match=ErrorMatch.PARTIAL_REGEX,
        )
        with open(legacy_node.debug_log_path, encoding="utf-8") as debug_log:
            legacy_failure_log = debug_log.read()
        assert "block-index branch already reaches header" in legacy_failure_log
        assert "at height 3" in legacy_failure_log
        assert not os.path.exists(legacy_identity_path)

        self.generatetoaddress(
            node, 2, node.getnewaddress(), sync_fun=self.no_op)
        assert_equal(node.getblockcount(), 2)
        best_before = node.getbestblockhash()
        tips_before = node.getchaintips()

        # Template construction must remain available to the authenticated L1
        # producer. Proposal-validation APIs must nevertheless reject that
        # incomplete template, and every direct RPC mining family must fail
        # before it can index an invalid proofless candidate.
        template = node.getblocktemplate({"rules": ["segwit"]})
        assert_equal(template["previousblockhash"], best_before)
        assert_equal(template["height"], 3)
        assert "proposal" in template["capabilities"]
        assert template["version"] & (1 << 20)
        candidate_hex = node.getnewblockhex()
        assert_equal(
            node.getblocktemplate({
                "mode": "proposal",
                "data": candidate_hex,
                "rules": ["segwit"],
            }),
            "bad-drivechain-bmm-header",
        )
        assert_raises_rpc_error(
            -25, "bad-drivechain-bmm-header", node.testproposedblock, candidate_hex)
        message = "Direct RPC block generation is unavailable after deterministic BMM activation"
        assert_raises_rpc_error(
            -1, message, self.generatetoaddress, node, 1, node.getnewaddress())
        descriptor = node.getdescriptorinfo("raw(51)")["descriptor"]
        assert_raises_rpc_error(
            -1, message, self.generatetodescriptor, node, 1, descriptor)
        assert_raises_rpc_error(
            -1, message, self.generateblock, node, node.getnewaddress(), [])
        assert_equal(node.getblockcount(), 2)
        assert_equal(node.getbestblockhash(), best_before)
        assert_equal(node.getchaintips(), tips_before)

        self.stop_node(0)
        node.assert_start_raises_init_error(
            extra_args=[
                "-ecxprivatebmmcheckpoint=1",
                "-drivechainl1blocksync=0",
            ],
            expected_msg="ecxprivatebmmcheckpoint requires an explicit.*ecxprivatebmmactivationheight",
            match=ErrorMatch.PARTIAL_REGEX,
        )
        node.assert_start_raises_init_error(
            extra_args=[
                "-ecxprivatebmmactivationheight=3",
                "-drivechainl1blocksync=0",
            ],
            expected_msg="ecxprivatebmmactivationheight requires.*ecxprivatebmmcheckpoint=1",
            match=ErrorMatch.PARTIAL_REGEX,
        )
        for invalid_height in ["0", "-1", "2147483647"]:
            node.assert_start_raises_init_error(
                extra_args=[
                    "-ecxprivatebmmcheckpoint=1",
                    f"-ecxprivatebmmactivationheight={invalid_height}",
                    "-drivechainl1blocksync=0",
                ],
                expected_msg="invalid -ecxprivatebmmactivationheight",
                match=ErrorMatch.PARTIAL_REGEX,
            )
        node.assert_start_raises_init_error(
            extra_args=[
                "-ecxprivatebmmcheckpoint=1",
                "-ecxprivatebmmactivationheight=4",
                "-drivechainl1blocksync=0",
            ],
            expected_msg="ECX consensus configuration does not match this data directory",
            match=ErrorMatch.PARTIAL_REGEX,
        )
        node.assert_start_raises_init_error(
            extra_args=self.correct_args + [f"-feeasset={other_asset}"],
            expected_msg="ECX consensus configuration does not match this data directory",
            match=ErrorMatch.PARTIAL_REGEX,
        )
        node.assert_start_raises_init_error(
            extra_args=[
                "-reindex",
                "-ecxprivatebmmcheckpoint=1",
                "-ecxprivatebmmactivationheight=4",
                "-drivechainl1blocksync=0",
            ],
            expected_msg="ECX consensus configuration does not match this data directory",
            match=ErrorMatch.PARTIAL_REGEX,
        )

        with open(identity_path, "rb") as identity_file:
            original_identity = identity_file.read()
        with open(identity_path, "wb") as identity_file:
            identity_file.write(original_identity[:-1] + b"!")
        node.assert_start_raises_init_error(
            extra_args=self.correct_args,
            expected_msg="ECX consensus configuration does not match this data directory",
            match=ErrorMatch.PARTIAL_REGEX,
        )
        with open(identity_path, "wb") as identity_file:
            identity_file.write(original_identity)

        self.start_node(0, extra_args=self.correct_args)
        assert node.verifychain(4, 0)

        # The private proof producer must cross activation and extend its own
        # authenticated successor, unlike the direct mining RPCs rejected above.
        previous_hash = node.getbestblockhash()
        private_blocks = []
        for height in (3, 4):
            block_hash = node.generateprivatebmmblock()
            private_blocks.append(block_hash)
            assert_equal(node.getblockcount(), height)
            assert_equal(node.getbestblockhash(), block_hash)
            block = node.getblock(block_hash)
            assert_equal(block["previousblockhash"], previous_hash)
            assert_equal(block["height"], height)
            assert len(block["bmmproofhash"]) == 64
            assert block["bmmproofhash"] != "0" * 64
            assert node.verifychain(4, 0)
            previous_hash = block_hash
        header_before_restart = node.getblockheader(previous_hash, False)
        proof_before_restart = node.getblockheader(previous_hash)["bmmproofhash"]
        self.restart_node(0, extra_args=self.correct_args)
        assert_equal(node.getblockcount(), 4)
        assert_equal(node.getbestblockhash(), previous_hash)
        assert_equal(node.getblockheader(previous_hash, False), header_before_restart)
        assert_equal(node.getblockheader(previous_hash)["bmmproofhash"], proof_before_restart)
        assert node.verifychain(4, 0)

        # Replay both directions across the private BMM activation boundary,
        # using only persisted proof data and this test's isolated chain.
        node.invalidateblock(private_blocks[0])
        assert_equal(node.getblockcount(), 2)
        assert_equal(node.getbestblockhash(), best_before)
        assert node.verifychain(4, 0)
        node.reconsiderblock(private_blocks[0])
        assert_equal(node.getblockcount(), 4)
        assert_equal(node.getbestblockhash(), previous_hash)
        assert_equal(node.getblockheader(previous_hash, False), header_before_restart)
        assert_equal(node.getblockheader(previous_hash)["bmmproofhash"], proof_before_restart)
        assert node.verifychain(4, 0)
        self.restart_node(0, extra_args=self.correct_args)
        assert_equal(node.getbestblockhash(), previous_hash)
        assert_equal(node.getblockheader(previous_hash, False), header_before_restart)
        assert node.verifychain(4, 0)

        # Both rebuild paths must recover the valid private proof history,
        # not merely reject the incompatible legacy history tested above.
        persisted_blocks = {
            block_hash: (node.getblockheader(block_hash, False),
                         node.getblockheader(block_hash)["bmmproofhash"],
                         node.getblock(block_hash, 0))
            for block_hash in private_blocks
        }
        for rebuild in ("-reindex-chainstate", "-reindex"):
            self.restart_node(0, extra_args=self.correct_args + [rebuild])
            self.wait_until(lambda: node.getblockcount() == 4)
            assert_equal(node.getbestblockhash(), previous_hash)
            for block_hash, (header, proof_hash, block_bytes) in persisted_blocks.items():
                assert_equal(node.getblockheader(block_hash, False), header)
                assert_equal(node.getblockheader(block_hash)["bmmproofhash"], proof_hash)
                assert_equal(node.getblock(block_hash, 0), block_bytes)
            assert node.verifychain(4, 0)
            with open(identity_path, "rb") as identity_file:
                assert_equal(identity_file.read(), original_identity)
            self.restart_node(0, extra_args=self.correct_args)
            assert_equal(node.getbestblockhash(), previous_hash)
            for block_hash, (_, _, block_bytes) in persisted_blocks.items():
                assert_equal(node.getblock(block_hash, 0), block_bytes)
            assert node.verifychain(4, 0)


if __name__ == "__main__":
    EcxConsensusIdentityTest(__file__).main()
