# AmneziaWG server setup

Scripts to install and run an [AmneziaWG](https://github.com/amnezia-vpn) 3.1
server on EL10 (Rocky / Alma / RHEL) or Fedora 44: kernel module via DKMS,
config and key generation, nftables firewall/NAT, sysctl tuning, per-client
provisioning and a health check.

| File | Purpose |
|---|---|
| `awg-install.sh` | Builds the pinned kernel module + tools, applies sysctls and firewall |
| `awg-bootstrap.sh` | Generates keys, the server config and the obfuscation parameters |
| `awg-peer.sh` | `add` / `remove` / `list` clients |
| `awg-doctor.sh` | Checks the host for common misconfigurations |
| `awg.nft` | nftables ruleset (filter, NAT, MSS clamp) |
| `99-awg-network.conf` | sysctl network tuning |

## Profiles

`awg-bootstrap.sh --profile balanced` (default) or `--profile stealth`.

| | balanced | stealth |
|---|---|---|
| Junk packets, S1/S2 handshake padding | yes (small) | yes |
| H1-H4 randomised message types | yes | no (HP hides them instead) |
| Header Protection | off (opt-in: `--header-protection`) | on |
| RandomTrailers / content padding / S4 | off | on |
| Cookies (handshake-flood defence) | **on** | off |
| Timers | stock WireGuard | randomised ranges |
| I1/I2 signature packets | off | on |
| Default port / MTU | 443 / 1380 | 443 / 1360 |

Balanced keeps every obfuscation feature whose cost is paid once per
handshake and drops every feature paid per data packet. Crypto is identical
in both: Noise IK, ChaCha20-Poly1305, plus a per-peer PresharedKey.

**Nothing is hardcoded.** Every numeric obfuscation value (junk count/sizes,
S1-S4, H ranges, content padding, timer ranges, I1/I2 sizes, Header Protection
key) is drawn at random each time `awg-bootstrap.sh` runs, so no two
deployments share a fingerprint. Jc/Jmin/Jmax are additionally re-drawn per
client by `awg-peer.sh`.

## Deployment order (new host)

```bash
chmod +x awg-*.sh
./awg-install.sh                                 # module, tools, sysctls, nftables
./awg-bootstrap.sh --endpoint <public-ip>        # balanced; re-applies firewall itself
./awg-peer.sh add laptop                         # prints a QR code; key is not stored
./awg-doctor.sh
```

Before installing, review `99-awg-network.conf`: the `eth0` entries must match
your WAN interface name (`ip -o route show default`). `awg.nft` and the
firewall are adjusted automatically by `awg-install.sh` from the live default
route and `deployment.env`.

Restrict SSH by adding `SSH_ALLOW="198.51.100.7,203.0.113.0/24"` to
`/etc/amnezia/amneziawg/deployment.env` and running
`./awg-install.sh --firewall-only`. The default is open to any source, so rely
on your provider's cloud firewall or set this.

### Fedora 44 (7.x kernel)

Same order, with two differences:

- **firewalld.** Fedora runs it by default and `awg.nft` replaces the whole
  ruleset, so the installer skips the firewall while firewalld is active.
  Hand the host over with `./awg-install.sh --disable-firewalld` (or
  `--firewall-only --disable-firewalld` afterwards).
- **Secure Boot.** If the DKMS key is not yet enrolled, the installer imports
  it and stops. Reboot, choose *Enroll MOK*, enter the password, and re-run
  `./awg-install.sh` to verify the module and apply the firewall. An enrolled
  key is kept across re-runs and kernel updates.

The pinned `v3.1.20260812` predates kernel 7.1. The DKMS pre-build hook patches
the 7.x breaks into each build: `setup_udp_tunnel_sock()` /
`udp_tunnel_sock_release()` take a `struct sock *` (7.1), `strncpy()` was
removed (7.2), and `WQ_PERCPU` is set so `alloc_workqueue()` doesn't WARN
(6.18+). Each shim is gated on the target kernel's headers, so kernel
updates rebuild correctly under DKMS autoinstall.

## Design notes

- **Pinned, matched versions.** Tools and kernel module are built from the same
  release tag; the UAPI moves in lockstep and mismatched builds silently drop
  parameters. The installer verifies the loaded module against the tools and
  probes that the module really accepts the 3.1 keys.
- **Stale modules.** depmod prefers `updates/` over `extra/`, so the purge
  removes copies from every module directory and `awg-doctor.sh` counts them.
- **`notrack` is scoped to the WAN interface.** An unscoped
  `udp dport 443 notrack` also matches forwarded client QUIC, which then skips
  NAT and black-holes HTTP/3.
- **MSS is clamped, not set.** `maxseg size set rt mtu` can raise a correct
  small MSS; `awg.nft` only lowers it, on the tunnel interface, from the
  configured MTU.
- **Path-MTU discovery works.** ICMP errors about the (untracked) tunnel UDP
  arrive as `INVALID`, so ICMP error types are accepted before
  `ct state invalid drop`. NDP/RA/MLD are accepted so IPv6 on the WAN works.
- **IPv6 is all-or-nothing.** Dual-stack (ULA + NAT66, the default) or
  `--no-ipv6`; clients routing `::/0` into a tunnel that cannot forward it is
  worse than either.
- **Conntrack is sized** (`nf_conntrack_max = 524288`) for a busy NAT gateway.
- **BBR with timestamps on.** BBR needs timestamped RTT samples.
- **No TTL rewriting.** Stock Linux uses 64; an unusual value is a signature.

## Things to verify by hand

**MTU.** The defaults are conservative. Run `./awg-doctor.sh --mtu-probe` from
a client toward the endpoint and raise the MTU if there is headroom. If you
change it, re-run bootstrap with `--mtu` (or edit it on both ends and in
`deployment.env`, then `./awg-install.sh --firewall-only`) so the MSS clamp
follows.

**Parameter names.** The 3.1 docs list `DisableCookies`, while the release
notes call it `DisableCookie`. `awg-bootstrap.sh` writes the documented
spelling and then verifies every key appears in `awg showconf awg0`, so a
mismatch fails loudly at bootstrap instead of running silently without it.

**I1/I2 signatures.** The stealth profile generates random-length signature
packets. A signature you design yourself is worth more than a widely
published one; treat the generated ones as a starting point.

## Security notes

- Server and client private keys, PresharedKeys and `HeaderProtectionKey` are
  generated on the host and never belong in this repository. Everything under
  `/etc/amnezia/amneziawg/` is mode 600.
- `awg-peer.sh add` prints the client config and does not store it unless
  `--keep-file` is passed.
- Addresses in this repo (`10.4.20.0/24`, `fd42:4:20::/64`, `203.0.113.x`,
  `198.51.100.x`) are private defaults or documentation ranges, not real hosts.
