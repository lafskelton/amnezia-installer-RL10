#!/usr/bin/env bash
#
# awg-bootstrap.sh — generate the AmneziaWG server config, keys and the shared
# obfuscation parameter block. Run once, after awg-install.sh.
#
#   ./awg-bootstrap.sh --endpoint 203.0.113.10 [--profile balanced|stealth]
#                      [--port N] [--mtu N] [--subnet 10.4.20] [--no-ipv6]
#                      [--header-protection] [--force]
#
# PROFILES
#
#   balanced (default) — security and latency first, light obfuscation only
#     where it costs nothing at runtime.
#       * Handshake-only disguise: junk packets (Jc), init/response padding
#         (S1/S2) and randomised message-type headers (H1-H4). Junk and
#         padding happen once per handshake (~every 2 min); the H values just
#         rewrite a field that exists anyway. Per-packet cost: zero.
#       * OFF: Header Protection, RandomTrailers, ContentPaddingAddition, S4.
#         These act on every data packet — extra bytes, an extra cipher pass,
#         and a smaller usable MTU — which is the part that buys DPI
#         resistance and costs throughput.
#       * Cookies stay ON. They are WireGuard's DoS defence: under handshake
#         flood the server answers with a cookie instead of doing the
#         expensive DH. Stealth disables them to remove a message type.
#       * Stock WireGuard timers (no randomised ranges).
#       * Default port 443/udp. Do not run an HTTP/3 (QUIC) listener on this
#         host: it would collide. Pass --port to use something else.
#       * Default MTU 1380 (standard 80-byte WG overhead, nothing added).
#
#     --header-protection (balanced only) adds Header Protection on top: the
#     message-type field is encrypted with a shared key. It needs S4 >= 12,
#     so S4 is set too, and S4 is a per-packet cost (extra bytes on every
#     data packet). Everything else stays as balanced.
#
#   stealth — maximum DPI resistance (Header Protection, RandomTrailers,
#     padding, randomised timers, I1/I2, cookies off, 443).
#
# Every numeric obfuscation value (junk counts and sizes, padding, timer ranges,
# I1/I2 sizes, H ranges, S values) is drawn at random per install, so no two
# deployments share a fingerprint and nothing here is a published signature.
#
# Constraints enforced here:
#   * Every parameter must match on both ends EXCEPT Jc, Jmin, Jmax.
#   * H1-H4 ranges must not overlap each other or the stock values 1-4.
#   * S1 + 56 != S2, so init and response are not the same size.
#   * stealth: Header Protection needs S1-S4 >= 12; RandomTrailers wants
#     S1 == S2 == S3 == S4.
#   * Jc 1..128; Jmin < Jmax <= 1280.

set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AWG_DIR="/etc/amnezia/amneziawg"
IFACE="awg0"
SERVER_CONF="${AWG_DIR}/${IFACE}.conf"
OBFS_FILE="${AWG_DIR}/obfuscation-params.conf"
META_FILE="${AWG_DIR}/deployment.env"

PROFILE="balanced"
PORT=""
MTU=""
SUBNET="10.4.20"
SUBNET6="fd42:4:20"
ENDPOINT=""
WANT_V6=1
FORCE=0
HP=0
DNS="1.1.1.2, 1.0.0.2"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --endpoint) ENDPOINT="$2"; shift 2 ;;
    --profile)  PROFILE="$2"; shift 2 ;;
    --port)     PORT="$2"; shift 2 ;;
    --mtu)      MTU="$2"; shift 2 ;;
    --subnet)   SUBNET="$2"; shift 2 ;;
    --dns)      DNS="$2"; shift 2 ;;
    --no-ipv6)  WANT_V6=0; shift ;;
    --header-protection) HP=1; shift ;;
    --force)    FORCE=1; shift ;;
    -h|--help)  sed -n '2,46p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

say()  { printf '\n\033[1;36m==>\033[0m %s\n' "$*"; }
ok()   { printf '    \033[1;32m[ok]\033[0m %s\n' "$*"; }
warn() { printf '    \033[1;33m[!!]\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31m[fatal]\033[0m %s\n' "$*" >&2; exit 1; }

rand() { shuf -i "$1"-"$2" -n 1; }

# Server-side junk parameters, drawn once per install. Peers get their own
# values from the PEER_* ranges, which awg-peer.sh re-draws per client.
case "$PROFILE" in
  balanced) : "${PORT:=443}"; : "${MTU:=1380}"
            JC="$(rand 2 5)"; JMIN="$(rand 8 24)"; JMAX="$(rand 48 128)"
            PEER_JC="2-5"; PEER_JMIN="$JMIN"
            PEER_JMAX="$(( JMAX - 16 ))-$(( JMAX + 16 ))" ;;
  stealth)  : "${PORT:=443}"; : "${MTU:=1360}"
            JC="$(rand 4 10)"; JMIN="$(rand 8 32)"; JMAX="$(rand 100 300)"
            PEER_JC="4-12"; PEER_JMIN="$JMIN"
            PEER_JMAX="$(( JMAX - 40 ))-$(( JMAX + 40 ))" ;;
  *) die "unknown profile '$PROFILE' (balanced|stealth)" ;;
esac

(( HP == 0 )) || [[ "$PROFILE" == balanced ]] || die "--header-protection only applies to the balanced profile (stealth always has it)"

[[ $EUID -eq 0 ]] || die "run as root"
command -v awg >/dev/null || die "awg not found — run awg-install.sh first"

if [[ -e "$SERVER_CONF" && $FORCE -eq 0 ]]; then
  die "$SERVER_CONF already exists. Re-running would invalidate every issued
     client config. Pass --force if that is genuinely what you want."
fi

if [[ -z "$ENDPOINT" ]]; then
  ENDPOINT="$(ip -4 -o addr show scope global | awk 'NR==1{split($4,a,"/"); print a[1]}')"
  [[ -n "$ENDPOINT" ]] || die "could not detect a public address; pass --endpoint"
  warn "endpoint auto-detected as ${ENDPOINT} — verify this is the address clients reach"
fi

WAN_IF="$(ip -4 -o route show default | awk 'NR==1{print $5}')"
[[ -n "$WAN_IF" ]] || die "no default route"

install -d -m 700 "$AWG_DIR"
umask 077

# ------------------------------------------------------------------------ keys
say "Generating server keypair"
awg genkey > "${AWG_DIR}/server_private.key"
awg pubkey < "${AWG_DIR}/server_private.key" > "${AWG_DIR}/server_public.key"
chmod 600 "${AWG_DIR}/server_private.key"
chmod 644 "${AWG_DIR}/server_public.key"
ok "keys written"

# ------------------------------------------------------------------ helpers
# Four non-overlapping H ranges, each in its own quarter of [5, 2^31), with the
# quarters shuffled so H1..H4 are not in ascending order.
gen_h_ranges() {
  local band=$(( (2147483647 - 5) / 4 )) q lo start width
  local -a order
  mapfile -t order < <(shuf -e 0 1 2 3)
  for q in "${order[@]}"; do
    lo=$(( 5 + q * band ))
    start="$(rand "$lo" $(( lo + band / 2 )))"
    width="$(rand 1000 100000)"
    printf '%s-%s\n' "$start" $(( start + width ))
  done
}

# ------------------------------------------------------ obfuscation params
say "Generating obfuscation parameters (profile: ${PROFILE})"

mapfile -t H < <(gen_h_ranges)

{
  cat <<EOF
# AmneziaWG shared obfuscation parameters — profile: ${PROFILE}
# Generated $(date -Iseconds) by awg-bootstrap.sh
#
# EVERY line must be byte-identical on the server and every client, except
# Jc / Jmin / Jmax, which awg-peer.sh re-randomises per client on purpose.
# A mismatch does not fail loudly: the handshake can complete and the tunnel
# then drops data.

EOF

  if [[ "$PROFILE" == "balanced" ]]; then
    # S1/S2 in 15..64, so S1+56 >= 71 > S2 and the two sizes always differ.
    cat <<EOF
Jc = ${JC}
Jmin = ${JMIN}
Jmax = ${JMAX}

S1 = $(rand 15 64)
S2 = $(rand 15 64)
S3 = $(rand 15 64)

H1 = ${H[0]}
H2 = ${H[1]}
H3 = ${H[2]}
H4 = ${H[3]}
EOF
    if (( HP )); then
      # Header Protection needs S1-S4 >= 12; S1-S3 are already 15..64.
      cat <<EOF

S4 = $(rand 15 64)
HeaderProtectionKey = $(openssl rand -base64 32)
EOF
    fi
    # Absent unless --header-protection (S4, HeaderProtectionKey); always
    # absent (all default off/zero): ContentPaddingAddition, RandomTrailers,
    # DisableCookies, timer ranges, I1-I5. Omitted rather than written as 0 so
    # the live-parameter check below cannot trip over showconf eliding zeros.
  else
    # One S value for all four: HP needs >= 12, RandomTrailers wants equal.
    S_VAL="$(rand 16 48)"
    # Timer ranges sit around the WireGuard stock values (rekey 120, timeout 5,
    # reject 180, keepalive 10, attempts 20) and keep rekey < reject.
    RK_LO="$(rand 100 115)";  RT_LO="$(rand 3 5)"
    RJ_LO="$(rand 165 175)";  KA_LO="$(rand 8 10)"; MA_LO="$(rand 14 18)"
    cat <<EOF
Jc = ${JC}
Jmin = ${JMIN}
Jmax = ${JMAX}

S1 = ${S_VAL}
S2 = ${S_VAL}
S3 = ${S_VAL}
S4 = ${S_VAL}

# Compatibility values: HP hides the message type instead.
H1 = 1
H2 = 2
H3 = 3
H4 = 4

HeaderProtectionKey = $(openssl rand -base64 32)
ContentPaddingAddition = 0-$(rand 48 128)

RekeyAfterTime = ${RK_LO}-$(( RK_LO + $(rand 10 25) ))
RekeyTimeout = ${RT_LO}-$(( RT_LO + $(rand 1 3) ))
RejectAfterTime = ${RJ_LO}-$(( RJ_LO + $(rand 10 20) ))
KeepaliveTimeout = ${KA_LO}-$(( KA_LO + $(rand 2 4) ))
MaxHandshakeAttempts = ${MA_LO}-$(( MA_LO + $(rand 2 4) ))

RandomTrailers = on
DisableCookies = on

I1 = <r $(rand 900 1200)>
I2 = <r $(rand 300 700)>
EOF
  fi
} > "$OBFS_FILE"
chmod 600 "$OBFS_FILE"

if (( HP )); then
  ok "handshake obfuscation + Header Protection (S4 set); cookies on"
elif [[ "$PROFILE" == "balanced" ]]; then
  ok "handshake-only obfuscation; per-packet features off; cookies on"
else
  ok "Header Protection on, RandomTrailers on, DisableCookies on"
fi

# --------------------------------------------------------------- server config
say "Writing ${SERVER_CONF}"
{
  echo "[Interface]"
  echo "Address = ${SUBNET}.1/24"
  [[ $WANT_V6 -eq 1 ]] && echo "Address = ${SUBNET6}::1/64"
  echo "ListenPort = ${PORT}"
  echo "PrivateKey = $(cat "${AWG_DIR}/server_private.key")"
  # Explicit MTU: awg-quick otherwise assumes a clean 1500-byte path (1420).
  # Verify with awg-doctor.sh --mtu-probe from the client side.
  echo "MTU = ${MTU}"
  echo ""
  sed '/^#/d;/^$/d' "$OBFS_FILE"
} > "$SERVER_CONF"
chmod 600 "$SERVER_CONF"
ok "server config written (port ${PORT}, MTU ${MTU})"

cat > "$META_FILE" <<EOF
PROFILE=${PROFILE}
HEADER_PROTECTION=${HP}
AWG_DIR=${AWG_DIR}
IFACE=${IFACE}
LISTEN_PORT=${PORT}
SERVER_ENDPOINT=${ENDPOINT}:${PORT}
VPN_SUBNET=${SUBNET}
VPN_SUBNET6=${SUBNET6}
WANT_V6=${WANT_V6}
MTU=${MTU}
DNS="${DNS}"
WAN_IF=${WAN_IF}
PEER_JC=${PEER_JC}
PEER_JMIN=${PEER_JMIN}
PEER_JMAX=${PEER_JMAX}
EOF
chmod 600 "$META_FILE"

say "Bringing the interface up"
systemctl enable --now "awg-quick@${IFACE}" 2>/dev/null \
  || { awg-quick up "$IFACE"; warn "started manually; awg-quick@${IFACE}.service not enabled"; }

# awg-quick reports success even when awg setconf silently discarded
# parameters the running module does not understand.
say "Confirming the kernel accepted every parameter"
missing=0
live="$(awg showconf "$IFACE" 2>/dev/null)"
while read -r key; do
  [[ -n "$key" ]] || continue
  if ! grep -qi "^${key}[[:space:]]*=" <<<"$live"; then
    warn "parameter not present on the live interface: ${key}"
    missing=1
  fi
done < <(grep -oE '^[A-Za-z0-9]+' "$OBFS_FILE" | sort -u)
(( missing )) && die "the running module discarded parameters it does not implement.
     That is a tools/module version mismatch — re-run awg-install.sh."
ok "all obfuscation parameters are live on ${IFACE}"

# The firewall has to learn the port, subnet and MSS this run chose.
if [[ -x "${SCRIPT_DIR}/awg-install.sh" ]]; then
  say "Re-applying firewall for port ${PORT}, MTU ${MTU}"
  "${SCRIPT_DIR}/awg-install.sh" --firewall-only
else
  warn "awg-install.sh not beside this script; run it with --firewall-only yourself"
fi

say "Done. Add clients with: ./awg-peer.sh add <name>"
printf '    profile          : %s\n' "$PROFILE"
printf '    server public key: %s\n' "$(cat "${AWG_DIR}/server_public.key")"
printf '    endpoint         : %s:%s\n' "$ENDPOINT" "$PORT"
