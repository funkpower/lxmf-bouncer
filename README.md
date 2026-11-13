# lxmf-bouncer

One LXMF identity, several LXMF apps, no lost messages. Like an IRC bouncer,
but for [LXMF](https://github.com/markqvist/LXMF) on
[Reticulum](https://reticulum.network).

## Why

Every LXMF app (NomadNet, MeshChat, Sideband) makes its own identity, and
the usual advice is one identity per device: if two apps hold the same
identity and both announce it, which one a message reaches depends on which
announce a sender heard last. With an identity per app, people have to
know which address to write to, and messages pile up in whichever app was
not running.

lxmf-bouncer is a small always-on daemon that holds your identity and is
the only thing that announces your LXMF address. Every message sent to you
reaches it, at any hour. It keeps each one in a private propagation node,
encrypted for you exactly as a propagated LXMF message is, and each of your
apps downloads its own copy from that node with an ordinary propagation
node sync. The apps hold the same identity but never announce it.

```
  sender ──direct/opportunistic──▶ lxmf-bouncer ──(your LXMF address, announced every 30 min)
  upstream propagation node ──fetch as you──▶ │
                                              ▼
                               private propagation node (messages kept 30 days)
                                ▲            ▲             ▲
                           NomadNet      MeshChat       Sideband   (each syncs its own copy)
```

What it does:

- **Receives everything for you.** It announces your `lxmf.delivery`
  address (with your display name, and ratchets as Python LXMF does) at
  start and every `interval_minutes`, and takes direct (Link) and
  opportunistic deliveries. Signatures are checked when the sender's key is
  known (a sender it hasn't heard of is looked up on the network first);
  forged messages are dropped. Apps that announced your address before
  can be listed, and messages encrypted to their ratchets are read too.
- **Serves every app its own copy.** Its propagation node answers `/get`
  only for identities you allow (your own, plus any you list). A
  propagation node normally deletes a message once a client says it has it;
  this one ignores that and keeps every message until it expires, so each
  app gets one. Apps remember which messages they already have, so a sync
  downloads only new ones. Messages keep their original source and
  signature, so replies go to the sender.
- **Fetches from other propagation nodes too (optional).** A sender whose
  direct delivery failed may have left a message for you on their
  propagation node. The bouncer syncs from the ones you name, as you, and
  keeps what it finds the same way.
- **Passes on what you send (with an upstream node).** An app that can't
  reach someone directly hands the message to its propagation node, which
  is the bouncer's. The bouncer checks its stamp, keeps it on disk, and
  passes it to each upstream node, retrying every 5 minutes until each
  takes it (or `expiry_days` pass). The recipient collects it there when
  they come online. The message is encrypted for the recipient; the bouncer
  can't read it. Without an upstream node the bouncer takes nothing in.
- **Keeps your old addresses working (optional).** If you used another
  identity before, people may still write to its address. List it as an
  `[[old_identity]]` and the bouncer announces that address too, takes its
  messages (directly and from the upstream node), checks their signatures,
  and moves them to your address so your apps can open them. They show in
  the sender's conversation, and your reply goes to the sender from your
  current address. Because the sender signed the old address, apps mark
  these messages' signatures as invalid (NomadNet: "Invalid Signature");
  the bouncer checks them against the old address before moving them.
  With `notify_senders` it also sends each such sender, once, a message
  from the old address giving your current one.
- **Asks senders for proof of work (optional).** With a `[stamps]` cost,
  your address announces it, as Python LXMF does, and with `enforce`
  messages without a good enough stamp are dropped.
- **Doesn't peer.** The node announces itself as inactive, so other
  propagation nodes don't peer with it, and it never peers with them.
- **Survives restarts.** The store is rsLXMF's on-disk propagation store
  plus a ledger of message IDs (so a message that arrives twice, directly
  and from upstream, is kept once).

## Build

Needs Rust 1.89 or newer. rsReticulum and rsLXMF are git submodules pinned
to their v1.4.0 release commits.

```
git clone --recursive <this repository> lxmf-bouncer
cd lxmf-bouncer
cargo build --release      # target/release/lxmf-bouncer
```

The release binary links only glibc (2.39 or newer when built on a current
Arch system) and libgcc_s.

## Setting up

1. **Pick the identity.** Use the one your main app already has, so people
   keep writing to the same address. NomadNet keeps it at
   `~/.nomadnetwork/storage/identity`; MeshChat's is under its storage
   directory (or the file given to `--identity-file`); Sideband shows its
   key as base32 under Encryption Keys. Copy it for the bouncer and keep it private:

   ```
   install -m 600 ~/.nomadnetwork/storage/identity ~/.local/share/lxmf-bouncer/identity
   ```

2. **Configure** `~/.config/lxmf-bouncer/config.toml` from
   [`contrib/config.example.toml`](contrib/config.example.toml).

3. **Get the addresses** to give the apps:

   ```
   lxmf-bouncer --config ~/.config/lxmf-bouncer/config.toml hashes
   identity           …
   LXMF address       …   (your address, unchanged)
   propagation node   …   (set this as the propagation node in every app)
   ```

   The propagation node has an identity of its own (made on first use, in
   the state directory). It can't use yours: every LXMF app registers the
   `lxmf.propagation` address of its own identity, so an app holding your
   identity would take a node under that identity for a local one and never
   reach it.

4. **Run it** (see [systemd](#running-under-systemd)), then set up each app
   as below. Stop your apps from announcing *before* the bouncer's first
   announce, so senders' newest path and ratchet for you are the bouncer's.

## Configuration

TOML. Relative paths are relative to the config file; `~/` is the home
directory.

| Key | Default | Meaning |
|---|---|---|
| `identity` | required | Your Reticulum identity file (64 bytes). |
| `state_dir` | required | Message store, ledger, ratchets, node identity, generated Reticulum config, `status.json`. |
| `display_name` | none | Name announced with your LXMF address. |
| `log_level` | `info` | `error`, `warn`, `info`, `debug`, `trace`, or a tracing filter. `RUST_LOG` overrides it. Logs go to stderr (journald). |
| `[reticulum] shared_instance` | `false` | Attach to this host's Reticulum shared instance (`rnsd`). |
| `[reticulum] instance_name` | `default` | That instance's `instance_name`. |
| `[reticulum] tcp` | none | Instead: connect to an rnsd `TCPServerInterface`, `host:port`. |
| `[reticulum] config_dir` | none | Instead: a complete Reticulum config directory, used as is. |
| `[announce] interval_minutes` | `30` | Time between announces of your address and the node. |
| `[store] max_size_mb` | `500` | Store size; past it, the oldest messages go first. |
| `[store] expiry_days` | `30` | How long each message is kept for your apps. |
| `[node] name` | none | Name the node announces. |
| `[node] identity` | `state_dir/node_identity` | The node's identity file, created if missing. |
| `[node] allowed_identities` | `[]` | Identity hashes (not addresses) allowed to sync besides yours. |
| `[upstream] node` | none | A propagation node (`lxmf.propagation` hash), or a list, to fetch your messages from and to pass on what your apps send through the bouncer. |
| `[upstream] interval_minutes` | `15` | Time between fetches. |
| `[upstream] extra_ratchets` | `[]` | Ratchet files of apps that announced your address before the bouncer (Python LXMF keeps them at `<storage>/lxmf/ratchets/<your LXMF address>.ratchets`). Added to the bouncer's own ratchets at start. |
| `[stamps] cost` | none | Stamp cost announced with your address (1 to 254). |
| `[stamps] enforce` | `false` | Drop messages to you without a stamp of that cost. |
| `[[old_identity]] identity` | none | An identity you used before; repeat the table for more. |
| `[[old_identity]] extra_ratchets` | `[]` | Ratchet files of apps that announced that old address. |
| `[[old_identity]] notify_senders` | `false` | Tell each person who writes to the old address, once, your current one. |

Set exactly one of `shared_instance`, `tcp` or `config_dir`. With
`shared_instance` or `tcp` the bouncer writes its own Reticulum config to
`state_dir/reticulum/config` on each start (no interfaces of its own, or one
`TCPClientInterface`). With `shared_instance` it refuses to start while no
shared instance is running, rather than become one; under systemd it is
restarted until rnsd is up, and it reconnects if rnsd restarts.

## The apps

Each app holds your identity, uses the bouncer's propagation node, syncs
from it often, and never announces. With an `[upstream] node` set, turn on
"send via the propagation node when direct delivery fails": the bouncer
passes such messages on. Without one, turn it off, since the bouncer's node
then takes nothing in and the send fails.

### NomadNet

Put your identity at `~/.nomadnetwork/storage/identity` (NomadNet not
running). In `~/.nomadnetwork/config`, section `[client]`:

```
announce_at_start = no
# NomadNet has no "never": announce once every ten years.
announce_interval = 5256000
# yes with an [upstream] node in the bouncer, no without.
try_propagation_on_send_fail = yes
periodic_lxmf_sync = yes
# Minutes (1 at least).
lxmf_sync_interval = 5
# 0 downloads everything waiting at each sync.
lxmf_sync_limit = 0
```

Set the propagation node: Conversations, `Ctrl-R` (LXMF synchronisation),
set the node to the bouncer's propagation node hash and save. If the node
announced recently, it also shows in Network, Known Nodes, where its Info
dialog can make it the default.

If you host a NomadNet node (`[node] enable_node = yes`), keep
`disable_propagation = yes` there.

A NomadNet profile that has never announced has no time of last announce,
and with `announce_at_start = no` its job thread stops with an error on its
first round (which also stops periodic sync). Give it one, with NomadNet
stopped, using the Python NomadNet runs on:

```
python3 -c 'import os,time; from RNS.vendor import umsgpack as m; p=os.path.expanduser("~/.nomadnetwork/storage/peersettings"); s=m.unpackb(open(p,"rb").read()); s["last_announce"]=time.time(); open(p,"wb").write(m.packb(s))'
```

### MeshChat (reticulum-meshchat)

Start it with your identity: `meshchat.py --identity-file <path>` (MeshChat
keeps its history per identity, under `storage/identities/<identity hash>`).
Then, in the web UI:

- sidebar, **Announce**: *Disabled*; don't press *Announce Now*;
- Settings, **Auto send to propagation node**: on with an `[upstream] node`, off without;
- Settings, Propagation Nodes, **Local Propagation Node**: off;
- **Preferred Propagation Node**: the bouncer's propagation node hash;
- **Auto Sync Interval**: *Every 15 Minutes* (the shortest the UI offers).

The same through its API, with a shorter sync interval:

```
curl -X PATCH http://127.0.0.1:8000/api/v1/config -H 'Content-Type: application/json' -d '{
  "auto_announce_interval_seconds": 0,
  "auto_send_failed_messages_to_propagation_node": true,
  "lxmf_preferred_propagation_node_destination_hash": "<bouncer propagation node hash>",
  "lxmf_preferred_propagation_node_auto_sync_interval_seconds": 300
}'
```

### Sideband

Import your identity in the Encryption Keys screen ("Restore Identity From
Key" takes the key as base32: `python3 -c 'import base64,sys;
print(base64.b32encode(open(sys.argv[1],"rb").read()).decode())' <identity file>`),
then in Preferences:

- **Announce automatically**: off;
- **Try propagation automatically**: on with an `[upstream] node`, off without;
- **Send via Propagation Node by default**: off;
- **LXMF Propagation Node**: the bouncer's propagation node hash;
- **Sync with Propagation Node periodically**: on, with the shortest
  interval you can live with;
- **Limit each sync to 3 messages**: off.

Don't use the announce button in the conversation list.

## Running under systemd

[`contrib/lxmf-bouncer.service`](contrib/lxmf-bouncer.service) is a user
unit:

```
install -Dm755 target/release/lxmf-bouncer ~/.local/bin/lxmf-bouncer
install -Dm644 contrib/lxmf-bouncer.service ~/.config/systemd/user/lxmf-bouncer.service
systemctl --user daemon-reload
systemctl --user enable --now lxmf-bouncer
loginctl enable-linger "$USER"
journalctl --user -u lxmf-bouncer -f
```

It logs each stored message (ID, sender, how it came, whether its signature
was checked), each sync it serves or refuses, and a store summary every
hour. `lxmf-bouncer status` reads `state_dir/status.json` (written every
minute):

```
lxmf-bouncer status (updated 12 s ago)
  identity           …
  LXMF address       …
  propagation node   …
  last announce      14 min ago
  store              3 message(s), 1914 bytes, oldest 2 h ago, newest 3 min ago
    <sender address>  3
  since start        2 direct, 1 from upstream, 0 duplicate(s), 0 dropped
  clients            6 message(s) served in 3 sync(s), 1 refused
  outgoing           0 waiting; since start 2 queued, 2 passed upstream, 0 refused
  upstream           <node>, last fetch 4 min ago: ok, 0 new
```

`status --json` prints the file itself.

## Limits

- **Your own sent messages stay in the app you sent them from.** The other
  apps never see them; their history shows only what you received. A sent
  message is encrypted for its recipient, so the bouncer can't read it.
- **Read state isn't shared**, and a new app (or one reset) downloads every
  message still held, up to `expiry_days` back. Every app syncs as the
  same identity, so the node can't tell them apart.
- **Messages arrive at the speed of each app's sync**, not the instant
  they're sent: a propagation node can't push. Senders see "delivered" when
  the bouncer has the message, before any of your apps show it.
- **A message sent through the bouncer reaches people who collect from an
  upstream node's network.** A recipient whose app syncs from a node that
  peers with none of the upstream nodes won't find it. The app shows such a
  message as sent (to a node), not delivered.
- **Without an upstream node, sending through a propagation node doesn't
  work.** Apps have one propagation node setting, used both to collect and
  to send, and the bouncer's node then takes nothing in.
- **An app that is online still answers path requests for your address.**
  Reticulum answers a path request for any destination registered locally,
  announce or no announce. A sender asking for a path at that moment may
  get one to the app instead of to the bouncer, and deliver straight to it:
  the other apps never see that message. That path response also carries
  the app's own ratchet, which the sender then uses until it hears the
  bouncer's next announce. Path requests are usually answered by transport
  nodes that already know the bouncer's path, so this is rare when the apps
  sit behind the same transport node as the bouncer.
- **Old ratchets.** Senders encrypt opportunistic and propagated messages
  to the newest ratchet they heard for you. Until they hear the bouncer's
  announce, that may be one of an app that announced your address before.
  Only the ratchet files listed in `extra_ratchets` are known to the
  bouncer; a message encrypted to any other app's ratchet can't be read.
  An opportunistic one is lost; a propagated one stays on the upstream node
  and is tried again every 6 hours, so adding the file later still gets it.
- **Anyone can send through the node.** Like any propagation node it can't
  tell who hands it a message (apps don't identify to send), so it takes
  one from anyone who knows its hash and pays its stamp cost (16, as Python
  LXMF's default). At most 50 MB waits for each upstream node.
- **Stamps and tickets.** Apps can give contacts tickets that stand in for
  a stamp. The bouncer doesn't see them, so with `enforce` a contact's
  ticket-stamped message is dropped, as is one from a sender who hasn't
  heard your announce since the cost was set.
- **Messages to an old address stay unverified in your apps.** Their
  signatures cover the old address, which only the sender can change; the
  notice asks them to.
- **A sender the network doesn't know is kept unverified.** If no transport
  node has heard the sender announce, the bouncer can't find their key; it
  keeps the message and your apps check it once they know the sender.

## Tests

`cargo test` covers the config, the store (one copy per message, every
client served, nothing deleted by a client's sync, survival across
restarts), ratchet decryption and merging (including ratchet files written
by Python RNS).

`tests/e2e.sh` runs the whole thing against the reference Python RNS and
LXMF on a private network it starts itself (an `rnsd` with a
`TCPServerInterface` on 127.0.0.1, port 4360–4369, `share_instance = No`),
with throwaway identities:

```
python -m venv /path/to/venv && /path/to/venv/bin/pip install rns lxmf
LXMF_TEST_VENV=/path/to/venv tests/e2e.sh
```

It checks: a direct and an opportunistic message to the user, sent while no
app of the user's runs, reach two Python LXMF clients holding the identity
(each its own copy, content, title, source and signature intact, nothing
twice); a client's reply reaches the sender; an identity not allowed is
refused; after a restart the stored messages are still there; a message
left on an ordinary Python propagation node is fetched (decrypted with the
bouncer's ratchets), served, and purged upstream; a client's send through
the bouncer reaches both upstream nodes; a sender writing to an old address
is told the current one, once; the bouncer works as a client of a Python
`rnsd` shared instance (receiving, serving and fetching upstream) and
refuses to start without one; with the stamp cost enforced, a message
without a stamp is dropped while every stamped one gets through; a packet
encrypted to an app's old ratchet is read; a message held on the second
upstream node is fetched; a sender the bouncer never heard announce is
looked up and verified.

## License

lxmf-bouncer is under the Reticulum License (see [LICENSE](LICENSE)): the MIT
terms with two use restrictions, the same license as Reticulum itself and as
the [rsReticulum](https://github.com/ratspeak/rsReticulum) and
[rsLXMF](https://github.com/ratspeak/rsLXMF) libraries it is built on.
