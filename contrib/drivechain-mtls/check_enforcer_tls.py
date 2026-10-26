#!/usr/bin/env python3
"""Read-only mTLS/gRPC preflight for withdrawal-service startup and monitoring.

Requires Python grpcio and openssl. Never signs, proposes a bundle or bids.
Exit 0 means reachable now; exit 1 is failure; exit 2 means rotation is due.
This is transport health, not consensus evidence or permission to release funds.
"""

import argparse
import ipaddress
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

import grpc


def credential(path, private=False):
    directory = path.parent.stat()
    if directory.st_uid != os.getuid() or directory.st_mode & 0o022:
        raise ValueError("credential directory must be owned and not group/other writable")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & (0o077 if private else 0o022) or info.st_size > 1048576):
            raise ValueError(f"unsafe credential file: {path.name}")
        data = stream.read(1048577)
        if not data or len(data) > 1048576:
            raise ValueError(f"empty or oversized credential: {path.name}")
        return data


def probe(directory, endpoint, authority, *, remote=False, warning_days=14, timeout=10):
    if not 0 <= warning_days <= 365 or not 0 < timeout <= 30:
        raise ValueError("warning days must be 0..365 and timeout must be 1..30 seconds")
    match = re.fullmatch(r"(\[[0-9a-fA-F:]+\]|[a-zA-Z0-9.-]+):([0-9]{1,5})", endpoint)
    if not match or not 1 <= int(match[2]) <= 65535:
        raise ValueError("endpoint must be host:port, with brackets for IPv6")
    host = match[1].strip("[]")
    if not remote:
        try:
            if not ipaddress.ip_address(host).is_loopback:
                raise ValueError("not loopback")
        except ValueError as error:
            raise ValueError("non-loopback endpoints require explicit --remote") from error
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}", authority):
        raise ValueError("an explicit certificate DNS authority is required")
    directory = Path(directory)
    ca = credential(directory / "ca.pem")
    client = credential(directory / "elements-client.pem")
    key = credential(directory / "elements-client-key.pem", private=True)
    warnings = []
    certificates = {"ca.pem": ca, "elements-client.pem": client}
    if (directory / "server.pem").exists():
        certificates["server.pem"] = credential(directory / "server.pem")
    for name, data in certificates.items():
        for seconds in (0, warning_days * 86400):
            result = subprocess.run(["openssl", "x509", "-noout", "-checkend", str(seconds)],
                                    input=data, capture_output=True, timeout=5)
            if result.returncode:
                if not seconds:
                    raise ValueError(f"expired or unreadable certificate: {name}")
                warnings.append(f"{name} expires within {warning_days} days")
    credentials = grpc.ssl_channel_credentials(ca, key, client)
    options = (("grpc.ssl_target_name_override", authority),
               ("grpc.default_authority", authority), ("grpc.enable_retries", 0),
               ("grpc.max_receive_message_length", 65536),
               ("grpc.max_send_message_length", 1024))
    with grpc.secure_channel(endpoint, credentials, options=options) as channel:
        # GetChainInfo has an empty protobuf request; its response is not used as
        # a trusted chain identity. No schema, reflection or write method needed.
        channel.unary_unary("/cusf.mainchain.v1.ValidatorService/GetChainInfo")(
            b"", timeout=timeout, wait_for_ready=False)
    return warnings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("endpoint")
    parser.add_argument("authority")
    parser.add_argument("--remote", action="store_true")
    parser.add_argument("--warning-days", type=int, default=14)
    parser.add_argument("--timeout", type=int, default=10)
    args = parser.parse_args()
    try:
        warnings = probe(args.directory, args.endpoint, args.authority, remote=args.remote,
                         warning_days=args.warning_days, timeout=args.timeout)
    except grpc.RpcError as error:
        print(f"Enforcer preflight failed: {error.code().name}", file=sys.stderr)
        return 1
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"Enforcer preflight failed: {error}", file=sys.stderr)
        return 1
    for warning in warnings:
        print("ROTATE: " + warning, file=sys.stderr)
    print("Authenticated read-only enforcer RPC reachable; not withdrawal approval")
    return 2 if warnings else 0


if __name__ == "__main__":
    sys.exit(main())
