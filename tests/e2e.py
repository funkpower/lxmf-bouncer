# SPDX-License-Identifier: LicenseRef-Reticulum
"""End-to-end test of lxmf-bouncer on a private Reticulum network.

Starts its own rnsd (a TCPServerInterface on 127.0.0.1, port 4360-4369,
share_instance = No), the bouncer, and Python LXMF peers, all with throwaway
identities under the work directory. Nothing touches a shared instance or
any other network. Run through tests/e2e.sh, which builds the bouncer and
picks the Python environment.

  U  the user's identity, held by the bouncer
  S  a sender (Python LXMF), online throughout
  C1, C2, C3  Python LXMF clients holding U, syncing from the bouncer
  X  an identity the bouncer does not allow
  P  a Python propagation node holding a message for U (the upstream)
"""

import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PEER = os.path.join(HERE, "lxmf_peer.py")


class Failure(Exception):
    pass


def check(condition, what):
    if not condition:
        raise Failure(what)
    print(f"  ok  {what}", flush=True)


def free_port():
    for port in range(4360, 4370):
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise Failure("no free port in 4360-4369")


def rns_config(path, port, server=False):
    os.makedirs(path, exist_ok=True)
    name = os.path.basename(path)
    if server:
        interface = (f"  [[e2e hub]]\n    type = TCPServerInterface\n    enabled = Yes\n"
                     f"    listen_ip = 127.0.0.1\n    listen_port = {port}\n")
    else:
        interface = (f"  [[e2e uplink]]\n    type = TCPClientInterface\n    enabled = Yes\n"
                     f"    target_host = 127.0.0.1\n    target_port = {port}\n")
    with open(os.path.join(path, "config"), "w") as f:
        f.write(f"[reticulum]\n  enable_transport = {'Yes' if server else 'No'}\n  share_instance = No\n"
                f"  instance_name = e2e-{name}\n  panic_on_interface_error = No\n\n"
                f"[logging]\n  loglevel = {6 if server else 4}\n\n[interfaces]\n{interface}")
    return path


class Run:
    def __init__(self, work, python, binary):
        self.work, self.python, self.binary = work, python, binary
        self.procs = {}

    def path(self, *parts):
        return os.path.join(self.work, *parts)

    def start(self, name, argv, **kwargs):
        log = open(self.path(f"{name}.log"), "ab")
        env = kwargs.pop("env", dict(os.environ))
        env["PYTHONUNBUFFERED"] = "1"
        proc = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env=env, **kwargs)
        self.procs[name] = proc
        return proc

    def stop(self, name, timeout=15):
        proc = self.procs.pop(name, None)
        if proc is None or proc.poll() is not None:
            return proc.returncode if proc else None
        proc.send_signal(signal.SIGTERM)
        try:
            return proc.wait(timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            return proc.wait()

    def stop_all(self):
        for name in list(self.procs):
            self.stop(name, timeout=5)

    def peer(self, role, name, identity, *extra, stdin=None):
        rns = rns_config(self.path("rns", name), self.port)
        argv = [self.python, PEER, role, "--rnsconfig", rns, "--identity", identity,
                "--storage", self.path("storage", name), "--name", name, *extra]
        return argv, stdin

    def wait_log(self, name, text, timeout, after=0):
        end = time.time() + timeout
        while time.time() < end:
            with open(self.path(f"{name}.log"), "rb") as f:
                data = f.read()[after:].decode("utf-8", "replace")
            if text in data:
                return True
            proc = self.procs.get(name)
            if proc is not None and proc.poll() is not None:
                raise Failure(f"{name} exited ({proc.returncode}) waiting for {text!r}")
            time.sleep(0.5)
        return False

    def log_size(self, name):
        return os.path.getsize(self.path(f"{name}.log"))

    def events(self, name):
        try:
            with open(self.path(f"{name}.events")) as f:
                return [json.loads(line) for line in f if line.strip()]
        except FileNotFoundError:
            return []

    def wait_event(self, name, predicate, timeout):
        end = time.time() + timeout
        while time.time() < end:
            for event in self.events(name):
                if predicate(event):
                    return event
            time.sleep(0.5)
        return None

    def client(self, name, identity, pn, know=(), reply_to=None, reply=None, timeout=150):
        out = self.path(f"{name}.json")
        extra = ["--pn", pn, "--out", out]
        for k in know:
            extra += ["--know", k]
        if reply_to:
            extra += ["--reply-to", reply_to, "--reply", reply]
        argv, _ = self.peer("client", name, identity, *extra)
        proc = self.start(name, argv)
        try:
            proc.wait(timeout)
        except subprocess.TimeoutExpired:
            self.stop(name)
            raise Failure(f"client {name} did not finish")
        self.procs.pop(name, None)
        with open(out) as f:
            return json.load(f)

    def bouncer_config(self, upstream, reticulum=None):
        path = self.path("bouncer.toml")
        reticulum = reticulum or f'tcp = "127.0.0.1:{self.port}"'
        with open(path, "w") as f:
            f.write(f'identity = "{self.path("ids", "U")}"\nstate_dir = "{self.path("bouncer-state")}"\n'
                    f'display_name = "e2e user"\nlog_level = "debug"\n\n'
                    f'[reticulum]\n{reticulum}\n\n'
                    f'[announce]\ninterval_minutes = 30\n\n'
                    f'[node]\nname = "e2e bouncer"\n\n'
                    f'[upstream]\nnode = "{upstream}"\ninterval_minutes = 1\n')
        return path

    def start_bouncer(self):
        offset = self.log_size("bouncer") if os.path.exists(self.path("bouncer.log")) else 0
        env = dict(os.environ, RUST_LOG=os.environ.get("E2E_BOUNCER_LOG", "info,lxmf_bouncer=debug"))
        self.start("bouncer", [self.binary, "--config", self.config, "run"], env=env)
        if not self.wait_log("bouncer", "announced the LXMF address", 60, after=offset):
            raise Failure("the bouncer did not announce")


def make_identity(python, path):
    subprocess.run([python, "-c", "import RNS,sys; RNS.Identity().to_file(sys.argv[1])", path], check=True)


def hashes(python, identity):
    code = ("import RNS,sys; i=RNS.Identity.from_file(sys.argv[1]); "
            "print(i.hash.hex(), RNS.Destination.hash(i,'lxmf','delivery').hex(), "
            "RNS.Destination.hash(i,'lxmf','propagation').hex())")
    out = subprocess.run([python, "-c", code, identity], check=True, capture_output=True, text=True).stdout.split()
    return {"identity": out[0], "delivery": out[1], "propagation": out[2]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", required=True)
    parser.add_argument("--python", required=True)
    parser.add_argument("--rnsd", required=True)
    parser.add_argument("--bouncer", required=True)
    args = parser.parse_args()

    if os.path.exists(args.work):
        shutil.rmtree(args.work)
    os.makedirs(os.path.join(args.work, "ids"))
    run = Run(args.work, args.python, args.bouncer)
    run.port = free_port()
    print(f"work directory {args.work}, private network on 127.0.0.1:{run.port}", flush=True)
    try:
        ids = {}
        for name in ["U", "S", "X", "P"]:
            make_identity(args.python, run.path("ids", name))
            ids[name] = hashes(args.python, run.path("ids", name))
        U, S, P = ids["U"], ids["S"], ids["P"]

        print("starting the network, the bouncer and the sender", flush=True)
        hub = rns_config(run.path("rns", "hub"), run.port, server=True)
        run.start("hub", [args.rnsd, "--config", hub, "-v"])
        time.sleep(3)
        run.config = run.bouncer_config(P["propagation"])
        run.start_bouncer()
        hashes_out = subprocess.run([args.bouncer, "--config", run.config, "hashes"], capture_output=True, text=True, check=True).stdout
        node = hashes_out.split("propagation node")[1].split()[0]
        check(U["delivery"] in hashes_out and len(node) == 32 and node != U["propagation"],
              "`hashes` prints the user's LXMF address and the node's (under its own identity)")

        argv, _ = run.peer("sender", "S", run.path("ids", "S"), "--events", run.path("S.events"))
        sender = run.start("S", argv, stdin=subprocess.PIPE)
        check(run.wait_event("S", lambda e: e["event"] == "ready", 30) is not None, "sender S is up")

        def send(content, method, title="", pn=None, timeout=120):
            command = {"to": U["delivery"], "content": content, "title": title, "method": method, "id": content}
            if pn:
                command["pn"] = pn
            sender.stdin.write((json.dumps(command) + "\n").encode())
            sender.stdin.flush()
            event = run.wait_event("S", lambda e: e["event"] == "sent" and e.get("id") == content, timeout)
            if event is None:
                raise Failure(f"S never finished sending {content!r}")
            return event

        print("S sends U two messages with no client of U running", flush=True)
        m1 = send("first message, direct", "direct", title="hello")
        check(m1["ok"] and m1["state"] == 0x08, "direct message delivered (proved) to U's address")
        m2 = send("second message, one packet", "opportunistic")
        check(m2["ok"], "opportunistic message sent")
        check(run.wait_log("bouncer", m2["hash"], 30), "the bouncer stored the opportunistic message")

        def by_hash(result):
            return {m["hash"]: m for m in result["received"]}

        print("C1 (holding U, not announcing) syncs from the bouncer", flush=True)
        c1 = run.client("C1", run.path("ids", "U"), node, know=[S["delivery"]])
        got = by_hash(c1)
        check(c1["state"] == 0x07, "C1's sync completed")
        check(set(got) == {m1["hash"], m2["hash"]}, "C1 received both messages, same message hashes as sent")
        first = got[m1["hash"]]
        check(first["content"] == "first message, direct" and first["title"] == "hello", "content and title intact")
        check(first["source"] == S["delivery"] and first["destination"] == U["delivery"], "source is S, destination is U")
        check(all(m["signature_validated"] for m in got.values()), "signatures valid at C1")

        c1b = run.client("C1", run.path("ids", "U"), node)
        check(c1b["state"] == 0x07 and c1b["received"] == [], "C1 syncing again gets nothing new")

        print("C2 (another client holding U) syncs: gets its own copies", flush=True)
        c2 = run.client("C2", run.path("ids", "U"), node, know=[S["delivery"]])
        check(set(by_hash(c2)) == {m1["hash"], m2["hash"]}, "C2 received both messages too")
        check(all(m["signature_validated"] for m in c2["received"]), "signatures valid at C2")

        print("C1 replies to S", flush=True)
        c1r = run.client("C1", run.path("ids", "U"), node, know=[S["delivery"]],
                         reply_to=S["delivery"], reply="reply from C1")
        check(c1r["reply"]["ok"], "C1's reply delivered")
        reply = run.wait_event("S", lambda e: e["event"] == "received" and e["content"] == "reply from C1", 30)
        check(reply is not None, "S received the reply")
        check(reply["source"] == U["delivery"] and reply["signature_validated"], "the reply is from U, signature valid")

        print("X (not allowed) tries to sync from the bouncer", flush=True)
        x = run.client("X", run.path("ids", "X"), node)
        check(x["state"] == 0xF4 and x["received"] == [], "X is refused (no access)")

        print("P, an ordinary propagation node, takes a message for U from S", flush=True)
        argv, _ = run.peer("pnode", "P", run.path("ids", "P"), "--events", run.path("P.events"))
        run.start("P", argv)
        check(run.wait_event("P", lambda e: e["event"] == "ready", 30) is not None, "P is up")
        time.sleep(3)
        m3 = send("third message, via a propagation node", "propagated", pn=P["propagation"], timeout=180)
        check(m3["ok"], "S handed the message to P")

        print("restarting the bouncer", flush=True)
        check(run.stop("bouncer") == 0, "the bouncer stopped cleanly on SIGTERM")
        offset = run.log_size("bouncer")
        run.start_bouncer()
        check(run.wait_log("bouncer", f"stored message {m3['hash']}", 150, after=offset),
              "the bouncer fetched U's message from P (decrypted with its ratchets)")

        print("C3 (a fresh client holding U) syncs after the restart", flush=True)
        c3 = run.client("C3", run.path("ids", "U"), node, know=[S["delivery"]])
        check(set(by_hash(c3)) == {m1["hash"], m2["hash"], m3["hash"]},
              "C3 received the two messages stored before the restart and the one from P")
        check(by_hash(c3)[m3["hash"]]["source"] == S["delivery"], "the message from P is from S")

        c1c = run.client("C1", run.path("ids", "U"), node)
        check([m["hash"] for m in c1c["received"]] == [m3["hash"]], "C1 gets just the new message from P")

        offset = run.log_size("bouncer")
        check(run.wait_log("bouncer", "upstream fetch", 90, after=offset), "the bouncer fetched from P again")
        time.sleep(1)
        with open(run.path("bouncer.log"), "rb") as f:
            later = f.read()[offset:].decode("utf-8", "replace")
        check(f"stored message {m3['hash']}" not in later and "upstream fetch from" not in later,
              "nothing fetched twice (P dropped the message once the bouncer held it)")

        run.stop("bouncer")
        status = subprocess.run([args.bouncer, "--config", run.config, "status", "--json"], capture_output=True, text=True, check=True).stdout
        status = json.loads(status)
        check(status["store"]["messages"] == 3 and status["store"]["by_sender"] == {S["delivery"]: 3},
              "`status` shows 3 messages from S")

        print("the bouncer as a client of a local shared instance (a Python rnsd)", flush=True)
        instance = f"lxmfb-e2e-{run.port}"
        run.config = run.bouncer_config(P["propagation"], f'shared_instance = true\ninstance_name = "{instance}"')
        refused = subprocess.run([args.bouncer, "--config", run.config, "run"], capture_output=True, text=True, timeout=30)
        check(refused.returncode != 0 and "no Reticulum shared instance" in refused.stderr,
              "with no shared instance running, the bouncer refuses to start (rather than become one)")
        shared = run.path("rns", "shared")
        os.makedirs(shared, exist_ok=True)
        with open(os.path.join(shared, "config"), "w") as f:
            f.write(f"[reticulum]\n  enable_transport = No\n  share_instance = Yes\n  instance_name = {instance}\n\n"
                    f"[logging]\n  loglevel = 4\n\n[interfaces]\n  [[e2e uplink]]\n    type = TCPClientInterface\n"
                    f"    enabled = Yes\n    target_host = 127.0.0.1\n    target_port = {run.port}\n")
        run.start("shared", [args.rnsd, "--config", shared])
        time.sleep(4)
        run.start_bouncer()
        m4 = send("fourth message, bouncer on a shared instance", "direct")
        check(m4["ok"], "direct message delivered through the shared instance")
        c1d = run.client("C1", run.path("ids", "U"), node)
        check([m["hash"] for m in c1d["received"]] == [m4["hash"]], "C1 gets it from the bouncer")
        offset = run.log_size("bouncer")
        m5 = send("fifth message, via P while the bouncer is on a shared instance", "propagated", pn=P["propagation"], timeout=180)
        check(m5["ok"], "S handed another message to P")
        check(run.wait_log("bouncer", f"stored message {m5['hash']}", 150, after=offset),
              "the bouncer fetched it from P through the shared instance")
        print("PASS", flush=True)
        return 0
    except Failure as e:
        print(f"FAIL: {e}", flush=True)
        print(f"logs are in {args.work}", flush=True)
        return 1
    finally:
        # Only the processes this run started, by their handles.
        run.stop_all()


if __name__ == "__main__":
    sys.exit(main())
