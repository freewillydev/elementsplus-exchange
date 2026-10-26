#!/usr/bin/env python3
# Copyright (c) 2026 The Elements Core developers
# Distributed under the MIT software license.
"""Reject the retired burn-and-submit RPC even with an activated ECX checkpoint.

Requires grpcio, protobuf, protoc, bash, and openssl. The local mTLS server uses
the pinned enforcer schema but mocks L1 acceptance, not real miner votes or payout.
"""

import base64
import hashlib
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import shutil
import subprocess
import threading

from feature_fedpeg import FedPegTest, get_new_unconfidential_address
from test_framework.test_framework import SkipTest
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.enforcer_protocol import load_protocol


STATE_ADDRESS = "ert1p2zffkaxp5py4fdutfdsrt6t6tcrc5ks09rkfd428hlhf4n5q8tqq9w2238"


def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def tagged_hash(tag, data):
    tag_hash = hashlib.sha256(tag.encode("ascii")).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()


def read_compact_size(data, offset):
    first = data[offset]
    offset += 1
    if first < 253:
        return first, offset
    size = {253: 2, 254: 4, 255: 8}[first]
    return int.from_bytes(data[offset:offset + size], "little"), offset + size


def parse_bundle_outputs(wire):
    assert_equal(wire[:6], bytes.fromhex("020000000001"))
    offset = 6
    vin_count, offset = read_compact_size(wire, offset)
    assert_equal(vin_count, 0)
    vout_count, offset = read_compact_size(wire, offset)
    assert_equal(vout_count, 4)
    outputs = []
    for _ in range(vout_count):
        amount = int.from_bytes(wire[offset:offset + 8], "little")
        offset += 8
        script_size, offset = read_compact_size(wire, offset)
        script = wire[offset:offset + script_size]
        offset += script_size
        outputs.append((amount, script))
    assert_equal(wire[offset:offset + 4], b"\x00" * 4)
    assert_equal(offset + 4, len(wire))
    return outputs


class EcxWithdrawalPositiveTest(FedPegTest):
    def set_test_params(self):
        super().set_test_params()

    def skip_test_if_missing_module(self):
        super().skip_test_if_missing_module()
        if not all(shutil.which(tool) for tool in ("bash", "openssl", "protoc")):
            raise SkipTest("Mutual-TLS fixture requires bash, openssl, and protoc")
        # Children exec node binaries; none may use the parent's gRPC runtime.
        os.environ["GRPC_ENABLE_FORK_SUPPORT"] = "0"
        try:
            import grpc
            import google.protobuf
        except ImportError as error:
            raise SkipTest("Mutual-TLS fixture requires grpcio and protobuf") from error

    def setup_network(self, split=False):
        import grpc
        from google.protobuf import json_format

        self.tls_dir = Path(self.options.tmpdir) / "enforcer-tls"
        generator = Path(__file__).resolve().parents[2] / "contrib/drivechain-mtls/generate-certs.sh"
        subprocess.run(["bash", str(generator), str(self.tls_dir)], check=True, capture_output=True)
        messages = load_protocol(self.tls_dir)
        self.mock_state_path = os.path.join(self.options.tmpdir, "mock-enforcer-state.json")
        state_path = self.mock_state_path
        state_lock = threading.Lock()

        def handler(method, request_type, response_type):
            def invoke(request, context):
                assert_equal(context.auth_context()["x509_common_name"], [b"elements-client"])
                payload = json_format.MessageToDict(request)
                with state_lock:
                    state = {"calls": []}
                    if os.path.exists(state_path):
                        with open(state_path, encoding="utf-8") as state_file:
                            state = json.load(state_file)
                    state["calls"].append(method)

                    if method.endswith("/ProposeWithdrawalBundle"):
                        wire = base64.b64decode(payload["transaction"], validate=True)
                        assert_equal(wire[4:6], b"\x00\x01")
                        no_witness = wire[:4] + wire[6:]
                        state["m6_consensus_hex"] = sha256d(no_witness).hex()
                        response = {}
                    elif method.endswith("/GetTwoWayPegData"):
                        if "m6_consensus_hex" not in state:
                            context.abort(grpc.StatusCode.FAILED_PRECONDITION, "No submitted bundle")
                        response = {
                            "blocks": [{
                                "blockInfo": {
                                    "events": [{
                                        "withdrawalBundle": {
                                            "m6id": {"hex": state["m6_consensus_hex"]},
                                            "event": {"submitted": {}},
                                        }
                                    }]
                                }
                            }]
                        }
                    else:
                        context.abort(grpc.StatusCode.UNIMPLEMENTED, method)

                    with open(state_path, "w", encoding="utf-8") as state_file:
                        json.dump(state, state_file, sort_keys=True)

                return json_format.ParseDict(response, response_type())
            return grpc.unary_unary_rpc_method_handler(
                invoke, request_deserializer=request_type.FromString,
                response_serializer=response_type.SerializeToString)

        self.mock_executor = ThreadPoolExecutor(max_workers=2)
        self.mock_enforcer = grpc.server(self.mock_executor, options=[
            ("grpc.max_receive_message_length", 1024 * 1024)])
        for service, method in (("BlockProducerService", "ProposeWithdrawalBundle"),
                                ("ValidatorService", "GetTwoWayPegData")):
            full_name = "cusf.mainchain.v1." + service
            self.mock_enforcer.add_generic_rpc_handlers((grpc.method_handlers_generic_handler(
                full_name, {method: handler(full_name + "/" + method, *messages(service, method))}),))
        credentials = grpc.ssl_server_credentials(
            [((self.tls_dir / "server-key.pem").read_bytes(), (self.tls_dir / "server.pem").read_bytes())],
            root_certificates=(self.tls_dir / "ca.pem").read_bytes(), require_client_auth=True)
        port = self.mock_enforcer.add_secure_port("127.0.0.1:0", credentials)
        assert port > 0
        self.mock_enforcer_address = f"127.0.0.1:{port}"
        self.mock_enforcer.start()
        with grpc.secure_channel(self.mock_enforcer_address, grpc.ssl_channel_credentials(
                root_certificates=(self.tls_dir / "ca.pem").read_bytes())) as channel:
            try:
                channel.unary_unary("/cusf.mainchain.v1.ValidatorService/GetTwoWayPegData")(b"", timeout=1)
            except grpc.RpcError:
                pass
            else:
                raise AssertionError("enforcer accepted a client without an mTLS certificate")
        super().setup_network(split)

    def shutdown(self):
        try:
            return super().shutdown()
        finally:
            if hasattr(self, "mock_enforcer"):
                self.mock_enforcer.stop(0).wait()
            if hasattr(self, "mock_executor"):
                self.mock_executor.shutdown(wait=True)

    def sidechain_extra_args(self, node_index):
        return [
            "-anyonecanspendaremine=1",
            "-ecxactivationheight=2147483646",
            "-ecxgenesisstateoutpoint=" + "11" * 32 + ":0",
            "-ecxgenesisstateroot=" + "12" * 32,
            "-ecxchainid=" + "19" * 32,
            "-ecxforcedactiondomain=" + "45" * 32,
            "-ecxdepositinboxdomain=" + "46" * 32,
            "-ecxcollateralvaultscript=5120" + "a1" * 32,
            "-ecxcollateralvaultscripthash=fe71d55db3b84e12e09fec4a925b73bd98465de02a2ecc58bc4c6596f36ac126",
            "-drivechainl1blocksync=0",
            f"-drivechainbmmgrpcaddr={self.mock_enforcer_address}",
            f"-drivechainbmmgrpcca={self.tls_dir / 'ca.pem'}",
            f"-drivechainbmmgrpccert={self.tls_dir / 'elements-client.pem'}",
            f"-drivechainbmmgrpckey={self.tls_dir / 'elements-client-key.pem'}",
        ]

    def sidechain_initial_free_coins(self, node_index):
        return 21000000

    def sidechain_connect_genesis_outputs(self, node_index):
        return True

    def run_test(self):
        self.import_deterministic_coinbase_privkeys()
        parent = self.nodes[0]
        sidechain = self.nodes[2]
        for node in self.nodes:
            node.importprivkey(
                privkey=node.get_deterministic_priv_key().key,
                label="mining",
            )
        state_txid = sidechain.sendtoaddress(
            STATE_ADDRESS, 0.01, "", "", False, False, 1, "UNSET", False)
        state_tx = sidechain.getrawtransaction(state_txid, True)
        state_vout = next(
            output["n"] for output in state_tx["vout"]
            if output["scriptPubKey"]["hex"] ==
            "512050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
        )
        self.generatetoaddress(
            sidechain, 1, sidechain.getnewaddress(), sync_fun=self.no_op)
        state_root = sidechain.getecxstateutxoroot(state_txid, state_vout)["root"]
        state_tx_hex = sidechain.gettransaction(state_txid)["hex"]
        sidechain.invalidateblock(sidechain.getbestblockhash())
        assert_equal(sidechain.getblockcount(), 0)
        assert_equal(sidechain.getrawmempool(), [state_txid])
        assert_equal(sidechain.getblockcount(), 0)
        self.stop_node(2)
        (sidechain.chain_path / "ecx_consensus.dat").unlink()
        replacement_args = []
        for argument in self.nodes[2].extra_args:
            if argument.startswith((
                "-ecxactivationheight=",
                "-ecxgenesisstateoutpoint=",
                "-ecxgenesisstateroot=",
            )):
                continue
            replacement_args.append(argument)
        replacement_args.extend([
            "-ecxactivationheight=2",
            f"-ecxgenesisstateoutpoint={state_txid}:{state_vout}",
            f"-ecxgenesisstateroot={state_root}",
        ])
        self.start_node(2, extra_args=replacement_args)
        sidechain = self.nodes[2]
        sidechain.importprivkey(
            self.nodes[2].get_deterministic_priv_key().key,
            label="mining",
        )
        assert_equal(sidechain.getrawmempool(), [state_txid])
        self.generatetoaddress(
            sidechain, 1, sidechain.getnewaddress(), sync_fun=self.no_op)
        assert_equal(sidechain.getblockcount(), 1)
        assert_equal(
            sidechain.getblock(sidechain.getbestblockhash())["exchangestateroot"],
            "0" * 64,
        )

        self.generatetoaddress(
            sidechain, 1, sidechain.getnewaddress(), sync_fun=self.no_op)
        checkpoint_height = sidechain.getblockcount()
        checkpoint_hash = sidechain.getbestblockhash()
        checkpoint = sidechain.getblock(checkpoint_hash)
        assert_equal(checkpoint_height, 2)
        assert_equal(checkpoint["exchangestateroot"], state_root)
        assert_equal(checkpoint["withdrawalbundlehash"], "0" * 64)

        destination = get_new_unconfidential_address(parent, "legacy")
        before = sidechain.getwalletinfo()
        mempool = sidechain.getrawmempool()
        for subtract in (False, True):
            for verbose in (False, True):
                assert_raises_rpc_error(
                    -32601, "no funds were burned",
                    sidechain.sendtomainchain, destination, 0.1, subtract, verbose)
        assert_equal(sidechain.getwalletinfo(), before)
        assert_equal(sidechain.getrawmempool(), mempool)
        assert_equal(sidechain.getbestblockhash(), checkpoint_hash)
        # Even a configured, reachable enforcer must not receive a proposal.
        if os.path.exists(self.mock_state_path):
            with open(self.mock_state_path, encoding="utf-8") as state_file:
                assert_equal(json.load(state_file).get("calls", []), [])


if __name__ == "__main__":
    EcxWithdrawalPositiveTest(__file__).main()
