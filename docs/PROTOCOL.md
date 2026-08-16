# MeshMorphic Wire Protocol v1

Deliberately boring and readable. The control plane is length-prefixed JSON
because this code needs to be auditable by people who are nervous, and saving
bytes on a message sent twice an hour is not worth costing anyone that.

## Framing

Every control message:

```
+--------+--------------------+
| uint32 |   JSON payload     |
|  BE    |                    |
+--------+--------------------+
```

Maximum payload 1 MiB, checked before allocating. Every message has a `type`.

## Transport

QUIC, ALPN `meshmorphic/1`. Each peer presents a TLS certificate whose public
key *is* its Ed25519 identity, so certificate verification and key pinning are
the same check. There is no certificate authority in the mesh and the Web PKI
is not consulted.

Stream 0 — the first bidirectional stream the client opens — is the control
stream and lives as long as the connection. Every later stream is a data
tunnel.

## Authentication handshake

Identical for agent→gateway and agent→edge.

```
client                                              server
  │──── hello {peer_id, pubkey, role, version} ──────>│
  │<─── challenge {nonce, server_pubkey} ─────────────│
  │──── auth {sig} ──────────────────────────────────>│
  │<─── welcome {...}  or  error {code, message} ─────│
```

The signature binds the response to this specific server, so an auth captured
by one server cannot be replayed to another:

```
sig = Ed25519_sign(client_priv,
        "meshmorphic-auth-v1" || 0x00 || nonce || 0x00 || server_identity_pubkey)
```

Before anything else, the server checks that `peer_id` genuinely derives from
`pubkey`. Identity is self-certifying, and nothing downstream reasons about a
mismatched pair.

## Hostnames are derived, not granted

There is no token in this protocol, and no message that grants anything. A
peer's mesh hostname is a function of its public key:

```
label = z-base32( sha256("meshmorphic-host-v1" || 0x00 || pubkey)[:12] )
host  = label + "." + <mesh domain>
```

Every party computes this independently:

- The **gateway** computes it to tell the agent what its address is.
- The **agent** recomputes it and refuses any hostname the gateway offers that
  does not match, so a hostile gateway cannot redirect it.
- The **edge** recomputes it to decide whether a claim is legitimate.

Nobody stores it and nobody issues it.

## Agent ↔ Gateway

After `welcome` the agent may send:

- `announce` — locally observed endpoints. Accepted and discarded in Phase 1;
  part of the wire format from the start so that direct peer-to-peer paths
  later are an addition rather than a break. The gateway records nothing.
- `ping` — keepalive every 20 s, answered with `pong`.

The gateway may send at any time:

- `welcome {peer_id, host_label, nickname, hostnames[], edges[], gateways[], server_id}`
- `edges {edges[]}` — the edge set changed, sent the moment an edge appears or
  disappears.
- `gateways {gateways[]}` — other gateways worth knowing about.
- `error {code, message}`

`edge` entries are `{edge_id, pubkey, addr}`; `gateway` entries are
`{gateway_id, pubkey, addr}`. Public keys are learned only inside an
authenticated session, which is what makes pinning them meaningful.

### Gateway gossip is not authenticated, on purpose

An agent adds any gateway it is told about, and never removes one. This is
sound because a gateway holds no state and grants no permission: a fabricated
entry costs one wasted dial. Add-only means a hostile gateway cannot shrink an
agent's list down to gateways it controls.

## Agent ↔ Edge

The agent authenticates as above, then sends:

```json
{"type":"claim","hostnames":["qz3k9rf7dnxb2wp8sq4t.awwe.uk","example.com"]}
```

No credential accompanies it, because there is no issuer. The edge decides per
hostname:

- **Under a mesh domain** — the label must equal the one this peer's key
  derives. Pure computation, no lookup, unforgeable without a 96-bit second
  preimage.
- **Any other domain** — first claimant wins. The edge cannot know who owns
  `example.com` and does not pretend to. This is safe because a claim is worth
  nothing unless DNS for that name already points at this edge, which only the
  domain's owner controls, and because a squatter has no certificate for it, so
  browsers refuse rather than being deceived.

Replies `claimed {hostnames[]}` with what was accepted, or `error` if none
were. Re-claiming over the same connection is normal and simply replaces the
set; the agent does it immediately whenever the user adds or removes a domain.

## Data tunnels

When a visitor connects, the edge opens a new stream to the agent, writes one
control frame, and then stops interpreting anything:

```json
{"type":"open","proto":"tls","host":"qz3k9rf7dnxb2wp8sq4t.awwe.uk",
 "remote":"198.51.100.7:51234"}
```

`proto` is `tls` (port 443; the bytes are a TLS record stream the edge cannot
read) or `http` (port 80; cleartext, carrying ACME challenges and the redirect
to HTTPS, both answered by the home server).

After that frame the stream is an opaque byte pipe.

For `proto: tls` the edge has already consumed the ClientHello in order to read
the SNI, so it replays those exact bytes as the first thing it writes. The home
server sees precisely what the browser sent, in order.

The agent checks the hostname against what it actually claims before serving,
so an edge forwarding something else — through a bug or through malice — gets
nothing.

## Certificates

The agent obtains a Let's Encrypt certificate for each hostname it serves. The
challenge arrives from outside on port 80, crosses the edge as a `proto: http`
stream, and is answered at home. The private key is generated on the home
machine and never leaves it.

## Error codes

Stable strings, so operators can grep logs: `unsupported_version`,
`bad_identity`, `bad_signature`, `host_not_allowed`, `no_route`, `internal`,
`protocol`.

## Version negotiation

`hello.version` is currently `1`. A server that does not speak it replies
`error {code:"unsupported_version"}` and closes. Later versions add message
types rather than changing existing ones, and **unknown message types must be
ignored rather than treated as fatal**, so a newer peer can talk to an older
one without either breaking.
