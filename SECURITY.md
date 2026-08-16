# Security

## Reporting a vulnerability

Email **security@lightmorphic.co.uk**. Please do not open a public issue for
anything exploitable.

Include what you did, what happened, and what you expected. A proof of concept
helps enormously. You will get an acknowledgement within a few days, and credit
in the release notes unless you would rather not have it.

Please do not test against other people's servers or sites. Run a gateway, an
edge and an agent locally — `make test` starts a complete network in one
process — or test against your own installation.

## Threat model

The intended user is somebody who is frightened of the internet and cannot
evaluate any of this for themselves. Where a trade-off exists between "safe by
default" and "convenient", this project chooses safe, and where something still
has to be trusted it is written down plainly rather than glossed over.

### What an attacker cannot do

**Reach the home computer.** It accepts no inbound connections. There is no
listening port on the internet side, so there is nothing to scan, nothing to
brute-force, and nothing to exploit remotely. This is a property of the
architecture rather than a firewall rule that could be misconfigured.

**Read website traffic in transit.** TLS terminates on the home machine. The
edge in the middle forwards ciphertext and holds no key to it.

**Take somebody's address.** Mesh hostnames are derived from the peer's public
key. There is no register to compromise, no authority to impersonate, and no
credential to steal. Claiming another peer's hostname requires a 96-bit second
preimage.

**Impersonate a site.** That requires the certificate's private key, which
exists only on the home machine. A hostile edge presenting its own certificate
is rejected by every browser, visibly.

**Get anything useful from a gateway.** It stores nothing about anyone.

**Get anything useful from the source code.** There is no shared secret in this
project — no API key, no common signing key, no bootstrap credential. Every
value that matters is generated locally by the machine that uses it.

### What an attacker can do

Being honest about this is the point of the section.

| Position | What it gets them |
|---|---|
| Compromised **gateway** | Hand out bad introductions, or refuse to answer. Agents fail over to another gateway. Nothing is stored to read. |
| Compromised **edge** | See hostnames, visitor IP addresses and timestamps. Refuse traffic. Cannot decrypt, cannot impersonate. |
| On the user's **home network** | Reach the settings panel, and must then get past device pairing. |
| Holding the **recovery key** | Full control of that site. The key is equivalent to the private key. |
| Compromised **release pipeline** | Everything, on every machine that updates. This is the most serious risk in the project. |

### Residual risks, stated plainly

- **The agent's own code.** It runs on the user's machine and holds the tunnel.
  Mitigation: keep it small enough that reading it is realistic, and
  source-available so that reading it is possible.
- **The install path.** `curl | sh` is a trust decision, and this project asks
  for it. Mitigation: reproducible builds and signed releases, so a published
  binary can be checked against the published source.
- **Let's Encrypt.** A certificate authority compromise affects this the same
  way it affects every website on the internet.
- **Loss of the recovery key.** Unrecoverable by design. The panel says so in
  those words rather than softer ones.

## Design decisions that carry security weight

**Nothing is granted; everything is derived.** There is no permission in this
protocol, so there is no permission to forge. Hostname authorisation is
arithmetic performed independently by every party, and each recomputes rather
than trusting what it was told — including the agent, which refuses a hostname
its own key does not produce even when a gateway offers it.

**Identity is self-certifying.** A peer ID derives from its public key, and
every server verifies the pairing before anything else.

**Signatures are domain-separated.** Handshake signatures cover
`"meshmorphic-auth-v1"` and bind to the specific server's public key, so an
auth response captured by one server cannot be replayed to another.

**Key pinning replaces the Web PKI.** In-mesh TLS certificates carry the Ed25519
identity key, so verifying a certificate and confirming a peer's identity are
one operation. `InsecureSkipVerify` appears in the transport with a stricter
check replacing it, not with nothing.

**Untrusted parsing is bounded.** The ClientHello parser is the only code that
reads attacker-controlled bytes before authentication. Every read is explicitly
bounds-checked and returns an error rather than panicking, because a panic
there would take down every site behind that edge.

**The panel assumes the local network is hostile.** Host pinning against DNS
rebinding, Origin and Sec-Fetch-Site checks on every write with absence treated
as refusal, device pairing so wi-fi access alone is insufficient, tokens stored
hashed, and a content security policy permitting nothing external.

**Uploads are treated as hostile.** Archive entries that escape their directory
are refused, symbolic links are refused, and both the compressed and
decompressed sizes are capped. Replacement is atomic, so a failed upload leaves
the running site untouched.

**Services are confined.** The systemd units drop every capability except the
one the edge needs to bind ports 80 and 443, and set `ProtectSystem=strict`,
`PrivateDevices`, `MemoryDenyWriteExecute`, and a system call filter. Containers
run read-only, non-root, with all capabilities dropped.

## Supported versions

Phase 1 is pre-1.0. Security fixes land on `main` and in the current release.

## Scope

In scope: the agent, gateway, edge, settings panel, protocol, install scripts,
and deployment configuration in this repository.

Out of scope: vulnerabilities in Docker, nginx, Go, or Let's Encrypt
themselves — report those upstream, though do please tell us if this project
uses them in a way that makes something worse.
