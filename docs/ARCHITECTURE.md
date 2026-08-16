# MeshMorphic Architecture

## The problem in one sentence

Somebody wants a website on a computer in their house, and does not want
anything on the internet to be able to knock on their front door.

## The shape of the solution

The home server never accepts an inbound connection. It makes one outbound
connection — the same shape a browser makes when it visits a website — and
everything the website does travels back down that connection.

```
                     ordinary DNS
  visitor's         *.awwe.uk ──> an edge's IP
  browser                              │
     │                                 │
     │ 1. TLS to qz3k9rf7dnxb2wp8sq4t.awwe.uk:443
     ▼                                 ▼
  ┌──────────────────────────────────────────────────┐
  │  EDGE  (public VPS, static IP)                   │
  │  · reads ONLY the hostname from the unencrypted  │
  │    ClientHello, then stops looking               │
  │  · holds no certificate and no certificate key   │
  │  · cannot decrypt: it forwards ciphertext        │
  └──────────────────────────────────────────────────┘
     ▲                                 │
     │ 2. the agent's outbound tunnel  │ 3. new stream, raw bytes
     │    (opened earlier, kept alive) ▼
  ┌──────────────────────────────────────────────────┐
  │  AGENT  (home server, every inbound port closed) │
  │  · TLS terminates HERE. The certificate's        │
  │    private key never leaves this machine.        │
  │  · reverse-proxies to the site container         │
  └──────────────────────────────────────────────────┘
                        │
                        │ 4. plain HTTP over a container network
                        │    with no route to anywhere
                        ▼
  ┌──────────────────────────────────────────────────┐
  │  SITE CONTAINER  (nginx, read-only, non-root,    │
  │  all capabilities dropped, no internet access)   │
  └──────────────────────────────────────────────────┘

  and, entirely off the traffic path:

  ┌──────────────────────────────────────────────────┐
  │  GATEWAY  (any cheap VPS, run by anyone)         │
  │  · answers one question: "who else is out there" │
  │  · stores nothing. No peer list, no names, no    │
  │    credentials, no database, no logs of who.     │
  │  · carries no traffic and grants no permission   │
  └──────────────────────────────────────────────────┘
```

## The central design decision: nothing is granted, everything is derived

Most systems of this shape have a server that decides things — which name you
get, whether you may use it, whether you are still a customer. That server
becomes the thing worth attacking, the thing that must be backed up, and the
thing that must keep existing for the network to work.

MeshMorphic has no such server, because **a site's address is a fingerprint of
its own public key**:

```
hostname = z-base32( sha256("meshmorphic-host-v1" || 0x00 || pubkey)[:12] ) + "." + domain
```

That one decision removes a great deal:

- **No name register.** There is nothing to look up, so nothing to store.
- **No credential.** An edge decides whether a peer may serve a hostname by
  recomputing the hash and comparing. Authorisation is arithmetic.
- **No authority.** No component can grant a hostname, so no component can be
  compromised into granting the wrong one. Forging a claim means finding a
  96-bit second preimage of somebody else's key.
- **No synchronisation.** Fifty gateways agree without ever talking, because
  they are all computing the same function rather than sharing a database.

The cost is an ugly default address. That is the honest trade, and it is why
"use your own domain" is a first-class feature rather than an upsell.

## Gateways: what "knows nothing" actually means

A gateway is not a lightweight version of a central server. It is a different
kind of thing.

**It holds:** its own keypair, and a list of the edges currently connected to
it, in memory only.

**It does not hold:** any record of any agent, ever. Not an ID, not a key, not
a hostname, not a first-seen date. It writes nothing to disk except its own
identity file. It has no database, no user table, and no log of who connected.

**It cannot:** read any traffic, issue any credential, authorise any hostname,
or reach into any home server.

So the consequences of a gateway being fully compromised are:

| An attacker with total control of a gateway can | can they? |
|---|---|
| Read anyone's website traffic | No — no traffic passes through it |
| Read stored user data | No — there is none |
| Take over somebody's address | No — addresses derive from keys it does not have |
| Issue a false permission | No — there are no permissions in this protocol |
| Serve a site in someone's place | No — that needs a certificate key held at home |
| Lie about which edges exist | Yes |
| Refuse to answer | Yes |

Both of the "yes" answers are handled the same way: the agent tries another
gateway. Which is why running fifty of them is the point.

### Gateway discovery is deliberately unauthenticated

Gateways gossip each other's addresses to agents, and an agent adds any it has
not seen to the list it will try.

This looks reckless and is not. **Because a gateway cannot do anything, you do
not need to trust where its address came from.** A hostile gateway address is
merely a useless one: the agent dials it, gets nothing useful, and moves on.
Entries are only ever added, never removed, so a hostile gateway cannot narrow
an agent's options down to one it controls.

This is the property that makes volunteer redundancy work without anybody
maintaining an official list.

### If every gateway went down at once

Existing tunnels are agent-to-edge and do not pass through a gateway, so:

- Every site already running stays up.
- Agents that need to reconnect cannot find edges, and go dark until a gateway
  returns.

Which is why a gateway is worth running on any spare box: the cost is
negligible and the failure mode is shared.

## Edges: the only thing on the traffic path

Something with a public address has to accept a visitor's connection, because
a browser cannot join a mesh. The edge is that something, and it is built to
be useless to whoever takes it.

It accepts a TCP connection on port 443, reads the ClientHello far enough to
find the SNI hostname, and stops. It has no certificate. It cannot complete a
TLS handshake with the visitor even if it wanted to. It looks up which tunnel
serves that hostname and copies bytes.

The TLS session is end to end between the **visitor's browser** and the **home
server**. A compromised edge sees hostnames, visitor IP addresses, timestamps,
and ciphertext.

**An edge cannot silently impersonate a site.** Serving the site would need the
certificate private key, which exists only on the home machine. The worst a
hostile edge can do is refuse traffic, or present a certificate it has no key
for — which every browser rejects loudly. Failure is visible, not silent.

Agents connect to **every** edge they are told about, so an edge disappearing
costs only the requests in flight on it.

## Why QUIC

The tunnel is QUIC for three reasons that all matter here:

1. **Connection migration.** A QUIC connection is identified by a connection
   ID, not an IP/port pair, so when a home broadband connection changes address
   the tunnel survives. The dynamic-IP problem is solved in the transport,
   where it belongs, rather than by polling DNS.
2. **Native stream multiplexing.** Every visitor becomes a stream on the one
   tunnel already open. The home machine never dials again and never listens.
3. **UDP.** Direct peer-to-peer paths in a later phase need hole punching.
   Building on TCP now would mean replacing the transport later.

## Identity

Every peer — agent, edge, gateway — has an Ed25519 keypair generated on first
run and never transmitted.

```
peer_id = "mm1" + z-base32( sha256(pubkey)[:20] )
```

The ID derives from the key, so given both you can check they belong together
with no authority to ask. Every server checks this before anything else,
which removes a whole class of confusion bugs.

TLS certificates on the wire carry the Ed25519 identity key itself, so
"verify the certificate" and "check this is the peer I expected" are the same
operation. There is no certificate authority anywhere in the mesh.

## The chain of trust, end to end

1. The install command carries one gateway address and its public key. The
   user pastes it once without needing to know it exists.
2. The agent pins that key. A hostile network cannot substitute a gateway.
3. The gateway names the edges and their public keys inside that authenticated
   session; the agent pins those in turn, and independently checks each edge ID
   derives from its key.
4. The agent **recomputes its own hostname** from its own key and refuses any
   hostname the gateway offers that does not match. A hostile gateway cannot
   talk it into serving, or requesting a certificate for, somebody else's name.
5. The agent claims its hostname at an edge. The edge recomputes the same
   function. No credential is presented because none exists.
6. The visitor's browser validates a Let's Encrypt certificate presented by the
   home server, through an edge that cannot tamper with it undetectably.

No step requires trusting the edge, and no step requires trusting the gateway.

## Sandboxing

Two containers that cannot reach each other except on one port, one way.

- **Agent container** — on two networks: an internal-only one shared with the
  site, and a normal bridge for its single outbound tunnel.
- **Site container** — on *only* the internal network, declared
  `internal: true`, so Docker installs no route out of it. No internet, no LAN,
  no host. Read-only root filesystem, non-root, `no-new-privileges`, all
  capabilities dropped.

A compromised website finds itself on a network with one other host, no route
anywhere, and a filesystem it cannot write to.

## The settings panel

Local network only, never reachable from the internet, and defended as though
that were not enough:

- **Host pinning** against DNS rebinding, which is the one way a public web
  page could otherwise reach a service bound to a private address.
- **Origin and Sec-Fetch-Site checks** on everything that changes state, with
  the absence of both treated as a refusal rather than a pass.
- **Device pairing.** The first browser becomes the owner; every later device
  must be approved from an enrolled browser or from the machine's command line.
  A home network contains guests, a smart television and a printer from 2019,
  and being on the wi-fi should not be enough to replace somebody's website.
- **A content security policy that permits nothing external**, which is easy to
  promise because the panel loads nothing external. No CDN, no font service,
  no analytics.

## What still needs trust, stated plainly

The target user cannot evaluate these and deserves not to be misled:

- **The agent's own code.** It runs on their machine and holds the tunnel.
  Mitigation: keep it small enough to actually read, and source-available.
- **The install path.** `curl | sh` is a trust decision. Mitigation: pinned
  checksums and signed, reproducible release builds.
- **Let's Encrypt.** A CA compromise is a CA compromise, the same as for every
  website on the internet.
- **The user's own recovery key.** Anyone who reads it becomes that site. There
  is no reset, because there is no account — which is the same property that
  makes the site impossible to take administratively.

Note what is *not* on this list: the gateway operator and the edge operator.
Neither has to be trusted, which is the whole point of the design.

## Reading the source gives an attacker nothing

There is no shared secret anywhere in this system. No API key, no signing key
held in common, no server-side pepper, no bootstrap credential. Every value
that matters is a keypair generated locally on the machine that uses it.

So publishing the source discloses the mechanism and nothing else — which is
the only honest basis for asking a nervous person to run something.

## Roadmap position

**Phase 1 (implemented):** static sites, outbound-only tunnels, key-derived
hostnames, multiple gateways and edges, automatic certificates, custom domains,
two-container sandbox, local settings panel, paper recovery keys.

**Phase 2:** application presets — WordPress and similar — as more containers
behind the same sandbox model.

**Phase 3:** direct peer-to-peer paths between agents via hole punching, and
Shamir-split recovery material distributed across agents. The protocol carries
endpoint announcements from day one so that this is an addition rather than a
rewrite.
