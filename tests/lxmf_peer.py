# SPDX-License-Identifier: LicenseRef-Reticulum
"""Python LXMF peers for the end-to-end test, on the reference LXMF.

Roles:
  sender   long-running: announces itself, sends what it is told on stdin
           (one JSON object per line; {"sync": node} syncs from a
           propagation node instead), records sends and receipts as JSON
           lines in --events.
  client   one-shot: syncs from a propagation node holding an identity
           (without announcing it), writes what arrived to --out, and can
           then send a reply directly, or a message through that node.
  pnode    long-running: an ordinary Python propagation node.

Each process runs its own Reticulum instance from --rnsconfig.
"""

import argparse
import json
import os
import sys
import threading
import time

import RNS
import LXMF


def log_to_file(configdir):
    # Never let Reticulum create a default config (which would attach to the
    # host's shared instance): the test writes every config itself.
    config = os.path.join(configdir, "config")
    with open(config) as f:
        text = f.read().replace(" ", "").lower()
    if "share_instance=no" not in text:
        sys.exit(f"{config}: refusing to run without share_instance = No")
    return dict(configdir=configdir, loglevel=RNS.LOG_DEBUG, logdest=RNS.LOG_FILE)


def wait_for(predicate, timeout, step=0.2):
    end = time.time() + timeout
    while time.time() < end:
        if predicate():
            return True
        time.sleep(step)
    return predicate()


def ensure_identity_known(dest_hash, timeout=30):
    """Request a path until the destination's identity is known."""
    end = time.time() + timeout
    while time.time() < end:
        if RNS.Identity.recall(dest_hash) is not None and RNS.Transport.has_path(dest_hash):
            return True
        if not RNS.Transport.has_path(dest_hash):
            RNS.Transport.request_path(dest_hash)
        wait_for(lambda: RNS.Transport.has_path(dest_hash), 5)
    return RNS.Identity.recall(dest_hash) is not None


def describe(message):
    return {
        "hash": message.hash.hex(),
        "source": message.source_hash.hex(),
        "destination": message.destination_hash.hex(),
        "title": message.title_as_string(),
        "content": message.content_as_string(),
        "signature_validated": bool(message.signature_validated),
        "unverified_reason": message.unverified_reason,
        "method": message.method,
        "transient_id": message.transient_id.hex() if getattr(message, "transient_id", None) else None,
    }


METHODS = {
    "direct": LXMF.LXMessage.DIRECT,
    "opportunistic": LXMF.LXMessage.OPPORTUNISTIC,
    "propagated": LXMF.LXMessage.PROPAGATED,
}


def send_message(router, source, to_hex, title, content, method, pn_hex=None, timeout=90):
    to = bytes.fromhex(to_hex)
    if not ensure_identity_known(to):
        return {"ok": False, "error": "recipient identity unknown"}
    if pn_hex:
        pn = bytes.fromhex(pn_hex)
        router.set_outbound_propagation_node(pn)
        ensure_identity_known(pn)
    identity = RNS.Identity.recall(to)
    destination = RNS.Destination(identity, RNS.Destination.OUT, RNS.Destination.SINGLE, "lxmf", "delivery")
    message = LXMF.LXMessage(destination, source, content, title=title, desired_method=METHODS[method])
    message.try_propagation_on_fail = False
    router.handle_outbound(message)
    done = {LXMF.LXMessage.DELIVERED, LXMF.LXMessage.FAILED, LXMF.LXMessage.REJECTED, LXMF.LXMessage.CANCELLED}
    if method == "propagated":
        done.add(LXMF.LXMessage.SENT)
    if method == "opportunistic":
        done.add(LXMF.LXMessage.SENT)
    wait_for(lambda: message.state in done, timeout)
    ok = message.state in done and message.state not in {LXMF.LXMessage.FAILED, LXMF.LXMessage.REJECTED, LXMF.LXMessage.CANCELLED}
    return {"ok": ok, "state": message.state, "hash": message.hash.hex() if message.hash else None,
            "method": method, "content": content, "title": title}


def emit(path, event):
    with open(path, "a") as f:
        f.write(json.dumps(event) + "\n")


def run_sender(args):
    RNS.Reticulum(**log_to_file(args.rnsconfig))
    identity = RNS.Identity.from_file(args.identity)
    router = LXMF.LXMRouter(identity=identity, storagepath=args.storage)
    source = router.register_delivery_identity(identity, display_name=args.name)

    def delivered(message):
        emit(args.events, {"event": "received", **describe(message)})

    router.register_delivery_callback(delivered)
    router.announce(source.hash)
    emit(args.events, {"event": "ready", "address": source.hash.hex()})

    def announcer():
        while True:
            time.sleep(15)
            router.announce(source.hash)

    threading.Thread(target=announcer, daemon=True).start()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        command = json.loads(line)
        if "sync" in command:
            node = bytes.fromhex(command["sync"])
            ensure_identity_known(node)
            router.set_outbound_propagation_node(node)
            router.request_messages_from_propagation_node(identity)
            final = {LXMF.LXMRouter.PR_COMPLETE, LXMF.LXMRouter.PR_NO_PATH, LXMF.LXMRouter.PR_LINK_FAILED,
                     LXMF.LXMRouter.PR_TRANSFER_FAILED, LXMF.LXMRouter.PR_NO_IDENTITY_RCVD,
                     LXMF.LXMRouter.PR_NO_ACCESS, LXMF.LXMRouter.PR_FAILED}
            wait_for(lambda: router.propagation_transfer_state in final, 60)
            time.sleep(2)
            emit(args.events, {"event": "synced", "id": command.get("id"),
                               "state": router.propagation_transfer_state})
            router.acknowledge_sync_completion(reset_state=True)
            continue
        result = send_message(router, source, command["to"], command.get("title", ""), command["content"],
                              command.get("method", "direct"), command.get("pn"))
        emit(args.events, {"event": "sent", "id": command.get("id"), **result})
    # stdin closed: keep receiving until killed.
    while True:
        time.sleep(1)


def run_client(args):
    RNS.Reticulum(**log_to_file(args.rnsconfig))
    identity = RNS.Identity.from_file(args.identity)
    router = LXMF.LXMRouter(identity=identity, storagepath=args.storage)
    # The identity is registered (so propagated messages can be decrypted)
    # but never announced: the bouncer is the only announcer.
    router.register_delivery_identity(identity, display_name=args.name)
    received = []
    router.register_delivery_callback(lambda m: received.append(describe(m)))
    for known in args.know:
        ensure_identity_known(bytes.fromhex(known))
    pn = bytes.fromhex(args.pn)
    router.set_outbound_propagation_node(pn)
    result = {"received": [], "state": None}
    for attempt in range(3):
        router.request_messages_from_propagation_node(identity)
        final = {LXMF.LXMRouter.PR_COMPLETE, LXMF.LXMRouter.PR_NO_PATH, LXMF.LXMRouter.PR_LINK_FAILED,
                 LXMF.LXMRouter.PR_TRANSFER_FAILED, LXMF.LXMRouter.PR_NO_IDENTITY_RCVD,
                 LXMF.LXMRouter.PR_NO_ACCESS, LXMF.LXMRouter.PR_FAILED}
        wait_for(lambda: router.propagation_transfer_state in final, 60)
        result["state"] = router.propagation_transfer_state
        if router.propagation_transfer_state not in (LXMF.LXMRouter.PR_NO_PATH, LXMF.LXMRouter.PR_LINK_FAILED):
            break
        router.acknowledge_sync_completion(reset_state=True)
        time.sleep(3)
    # Delivery callbacks run on the router's threads.
    wait_for(lambda: len(received) >= router.propagation_transfer_last_result if isinstance(router.propagation_transfer_last_result, int) else True, 10)
    time.sleep(1)
    result["received"] = list(received)
    result["last_result"] = router.propagation_transfer_last_result
    if args.reply_to:
        source = router.delivery_destinations[RNS.Destination.hash(identity, "lxmf", "delivery")]
        result["reply"] = send_message(router, source, args.reply_to, "re", args.reply, "direct")
    if args.send_to:
        source = router.delivery_destinations[RNS.Destination.hash(identity, "lxmf", "delivery")]
        result["sent"] = send_message(router, source, args.send_to, "", args.send, "propagated", pn_hex=args.pn,
                                      timeout=120)
    with open(args.out, "w") as f:
        json.dump(result, f)
    # Let the purge request (and the reply's proof) go out before exiting.
    time.sleep(2)
    os._exit(0)


def run_pnode(args):
    RNS.Reticulum(**log_to_file(args.rnsconfig))
    identity = RNS.Identity.from_file(args.identity)
    router = LXMF.LXMRouter(identity=identity, storagepath=args.storage, name=args.name,
                            propagation_cost=LXMF.LXMRouter.PROPAGATION_COST_MIN)
    router.enable_propagation()
    router.announce_propagation_node()
    emit(args.events, {"event": "ready", "node": router.propagation_destination.hash.hex()})
    while True:
        time.sleep(20)
        router.announce_propagation_node()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("role", choices=["sender", "client", "pnode"])
    parser.add_argument("--rnsconfig", required=True)
    parser.add_argument("--identity", required=True)
    parser.add_argument("--storage", required=True)
    parser.add_argument("--name", default="test peer")
    parser.add_argument("--events")
    parser.add_argument("--out")
    parser.add_argument("--pn")
    parser.add_argument("--know", action="append", default=[])
    parser.add_argument("--reply-to")
    parser.add_argument("--reply")
    parser.add_argument("--send-to")
    parser.add_argument("--send")
    args = parser.parse_args()
    {"sender": run_sender, "client": run_client, "pnode": run_pnode}[args.role](args)


if __name__ == "__main__":
    main()
