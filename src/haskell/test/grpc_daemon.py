"""Daemon lifecycle regression using only isolated parent/enforcer fixtures."""
import base64
import http.server
import json
import os
import pathlib
import signal
import socket
import subprocess
import threading
import time
import urllib.request
import urllib.error


def unused_port():
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        return reservation.getsockname()[1]


def check_daemon(binary, directory, certs, enforcer_port, calls):
    invalid = subprocess.run([str(binary), "-version"],
        env=dict(os.environ, ELEMENTS_DAEMON_PIPE="-1"), capture_output=True, timeout=5)
    assert invalid.returncode != 0 and b"Invalid daemon initialization pipe" in invalid.stderr
    class Parent(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            assert self.headers["Authorization"] == "Basic " + base64.b64encode(b"fixture:fixture").decode()
            result = "33" * 32 if request["method"] == "getbestblockhash" else None
            body = json.dumps({"result": result, "error": None, "id": request["id"]}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    parent = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Parent)
    worker = threading.Thread(target=parent.serve_forever)
    worker.start()
    try:
        for mode in ("-daemonwait", "-daemon"):
            data = pathlib.Path(directory) / mode[1:]
            data.mkdir()
            pidfile = data / "node.pid"
            port = unused_port()
            args = [str(binary), f"-datadir={data}", "-chain=elementsregtest", mode,
                f"-pid={pidfile}", "-listen=0", "-dnsseed=0", "-fixedseeds=0",
                "-disablewallet=1", "-drivechainl1blocksync=0", "-validatepegin=0", "-dbcache=16", "-par=1",
                f"-rpcport={port}", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1",
                "-mainchainrpchost=127.0.0.1", f"-mainchainrpcport={parent.server_port}",
                "-mainchainrpcuser=fixture", "-mainchainrpcpassword=fixture",
                f"-drivechainbmmgrpcaddr=127.0.0.1:{enforcer_port}",
                "-drivechainbmmgrpcauthority=enforcer.local",
                f"-drivechainbmmgrpcca={certs / 'ca.pem'}",
                f"-drivechainbmmgrpccert={certs / 'elements-client.pem'}",
                f"-drivechainbmmgrpckey={certs / 'elements-client-key.pem'}"]

            def rpc(method, params=None):
                cookie = (data / "elementsregtest/.cookie").read_bytes().strip()
                request = urllib.request.Request(f"http://127.0.0.1:{port}/",
                    data=json.dumps({"id": 1, "method": method, "params": params or []}).encode(),
                    headers={"Authorization": "Basic " + base64.b64encode(cookie).decode()})
                try:
                    with urllib.request.urlopen(request, timeout=5) as response:
                        reply = json.load(response)
                except urllib.error.HTTPError as error:
                    reply = json.load(error)
                assert reply["error"] is None, reply
                return reply["result"]

            try:
                started = subprocess.run(args, capture_output=True, text=True, timeout=20)
                logs = "\n".join(path.read_text()[-6000:] for path in data.glob("*/debug.log"))
                assert started.returncode == 0, (started.stdout, started.stderr, logs)
                for _ in range(100):
                    try:
                        assert rpc("getblockcount") == 0
                        break
                    except (OSError, ValueError):
                        time.sleep(0.1)
                else:
                    raise AssertionError("daemon RPC did not become ready")
                before = len(calls)
                result = rpc("getdrivechainpegevents", [0, 1, True])
                assert result["sidechain_id"] == 24, result
                assert calls[before:] == ["GetTwoWayPegData"], calls[before:]
                rpc("stop")
                for _ in range(100):
                    if not pidfile.exists():
                        break
                    time.sleep(0.1)
                assert not pidfile.exists(), "daemon shutdown hung"
                print("PASS", mode, "nested gRPC and clean shutdown", flush=True)
                if mode == "-daemonwait":
                    # A post-fork initialization error must reach the waiting parent.
                    failed = subprocess.run(args + [f"-rpcport={parent.server_port}"],
                        capture_output=True, text=True, timeout=20)
                    assert failed.returncode != 0, "failed daemon initialization reported success"
                    for _ in range(100):
                        if not pidfile.exists():
                            break
                        time.sleep(0.1)
                    assert not pidfile.exists(), "failed daemon did not finish shutdown"
                    print("PASS daemonwait initialization failure propagation", flush=True)
            finally:
                if pidfile.exists():
                    pid = int(pidfile.read_text())
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
    finally:
        parent.shutdown()
        parent.server_close()
        worker.join()
