# MeshMorphic

**A website on your own computer, with nothing open to the internet.**

Self-hosting a website at home normally means opening a door in your home
network and hoping nobody unpleasant walks through it. MeshMorphic doesn't do
that. Your computer opens **no ports at all**. It makes one connection
outward — the same shape as a browser visiting a website — and your site
travels back down it.

There is no account, no password, and no company you depend on. If everyone
involved in building this disappeared tomorrow, the network would keep working
and anyone could fork it and carry on.

---

## Install

```bash
curl -fsSL https://get.awwe.uk | sudo sh
```

It asks you nothing. A minute later it prints your web address and a link to
your settings page. That's the whole setup.

---

## How it stays safe

**Your computer has no open ports.** Nothing on the internet can start a
connection to it. There is no door to find, so there is nothing to knock on,
scan, or brute-force.

**Your address is your key.** A site's web address is a fingerprint of a secret
key that only your computer holds:

```
qz3k9rf7dnxb2wp8sq4t.awwe.uk
└──────────────────┘
   derived from your public key
```

Nobody assigns it, so nobody can reassign it. There is no register to hack and
no support desk to social-engineer. Taking your address would mean finding a
different key that hashes to the same 96 bits.

**Encryption ends on your machine.** The certificate for your site, and its
private key, are generated at home and never leave. The public servers your
traffic crosses forward sealed bytes they cannot open.

**The public servers hold nothing worth stealing.** More on this below, because
it is the part that makes the rest work.

**Your website is sealed off from your computer.** Your site runs in its own
container on a network with no route to the internet, to your home network, or
to your machine. If your website is ever compromised, the attacker lands
somewhere with nowhere to go.

---

## The two kinds of public server

| | **Gateway** | **Edge** |
|---|---|---|
| Job | Introductions only | Passes visitor traffic through |
| Stores | Nothing at all | Nothing at all |
| Can read your traffic | No traffic passes through it | No — it has no key |
| Can take your address | No — addresses derive from keys | No |
| If it's hacked | Nothing to take; agents use another | Sees hostnames and IPs; can refuse traffic |
| If it dies | Running sites are unaffected | Agents move to another edge |

### Why a gateway genuinely knows nothing

It has no database. No peer list. No names. No credentials. No log of who
connected. It writes exactly one file to disk — its own key — and answers one
question: *who else is out there?*

It can't authorise anything, because **there is nothing to authorise**. A
hostname is a calculation anyone can do, not a permission somebody grants.

That has a useful consequence: since a gateway can't do anything, you don't
have to trust where its address came from. A hostile gateway is just a useless
one, and your computer moves on to the next. Which is why anyone can run one.

### Why an edge can't read your traffic

An edge reads only the hostname from the unencrypted opening of a TLS
connection — the same field any network switch on the path can see — and then
copies bytes. It has no certificate and no private key, so it cannot decrypt
anything, and it cannot pretend to be your site either: browsers reject a
certificate nobody holds the key for, loudly.

---

## Run a server for the network

More gateways means more resilience. A gateway is nearly free to run — no
storage, negligible traffic, no responsibility for anyone's data, and nothing
on the machine worth attacking.

```bash
git clone https://github.com/FOSSCharlie/meshmorphic
cd meshmorphic/deploy/vps
sudo bash install-node.sh --role gateway --public-host gw2.example.org
```

It hardens the server first (firewall, automatic security updates, fail2ban,
SSH), builds from source so you can read what you're running, installs a
locked-down systemd service, and prints the one line to publish.

To run an edge as well, use `--role both`. Edges carry real traffic, so they
want decent bandwidth; gateways run happily on the cheapest box available.

---

## The one thing you must do

Open your settings page, go to **Recovery**, and write the key down on paper.

Nobody else has a copy. Not us, not whoever runs the gateway, not anyone. That
is exactly why nobody can take your site — and it means if your disk dies and
you haven't written it down, your address is gone permanently.

It is the same trade as a house key: nobody can let themselves in, and nobody
can let you back in either.

---

## Using your own domain

Add it in the settings page, then create one CNAME record at your domain
registrar pointing at your automatic address. A certificate is obtained
automatically, usually within a few minutes.

---

## Settings

The settings page runs on your own computer and is reachable only from your
home network. It is never exposed to the internet.

The first browser to open it becomes the owner. Any other device has to be
approved from there, or from the machine's command line — so being on the wi-fi
is not by itself enough to change your website. Home networks contain guests,
smart televisions, and a printer nobody has updated since 2019.

---

## Command line

```bash
mm-agent status                  # is my site online?
mm-agent recovery                # show the key to write down
mm-agent restore <key>           # bring a site back on a new computer
mm-agent devices approve <code>  # let another device into the settings page
mm-agent devices reset           # forget every device
```

---

## Build and test

```bash
make build     # all three binaries
make test      # unit tests plus a full network end-to-end
make check     # vet, format check, tests
```

The end-to-end test runs a real gateway, a real edge and a real agent in one
process and pushes a request through the whole path, including the checks that
stop one peer claiming another's address.

---

## Reading the source gives an attacker nothing

There is no shared secret anywhere in this system. No API key, no common
signing key, no server-side pepper, no bootstrap credential. Every value that
matters is a keypair generated locally on the machine that uses it.

Publishing the source discloses the mechanism and nothing else — which is the
only honest basis for asking a nervous person to run something on their own
computer.

---

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — how it works and why, including an
  honest account of what still has to be trusted
- [Protocol](docs/PROTOCOL.md) — the wire format, in full
- [Security](SECURITY.md) — threat model and reporting

## Status

Phase 1: static websites. Working end to end.

Phase 2 will add presets for WordPress and similar. Phase 3 adds direct
peer-to-peer paths and split recovery material. The protocol was built
mesh-shaped from the first commit so neither is a rewrite.

## Licence

[FSL-1.1-Apache-2.0](LICENSE) — source-available, free for personal and
internal use, and it becomes Apache 2.0 two years after each release. You can
read every line, run it yourself, and fork it. You can't resell it as a
competing hosted service until it converts.
