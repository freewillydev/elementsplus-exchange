# Copyright (c) 2026 The Elements Core developers
# Distributed under the MIT software license.
"""Load the pinned, official CUSF wire schema for isolated enforcer fixtures."""
from pathlib import Path
import subprocess


def load_protocol(directory):
    from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
    root = Path(__file__).resolve().parents[3] / "src/haskell/enforcer-proto"
    output = Path(directory) / "enforcer-descriptor.pb"
    subprocess.run(["protoc", f"--proto_path={root}", "--include_imports",
                    f"--descriptor_set_out={output}",
                    "cusf/mainchain/v1/validator.proto", "cusf/mainchain/v1/wallet.proto"],
                   check=True, capture_output=True)
    descriptor = descriptor_pb2.FileDescriptorSet.FromString(output.read_bytes())
    pool = descriptor_pool.DescriptorPool()
    for file in descriptor.file:
        pool.Add(file)

    def messages(service, method):
        rpc = pool.FindServiceByName("cusf.mainchain.v1." + service).methods_by_name[method]
        return (message_factory.GetMessageClass(rpc.input_type),
                message_factory.GetMessageClass(rpc.output_type))
    return messages
