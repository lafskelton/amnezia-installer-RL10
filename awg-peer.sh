#!/usr/bin/env bash
#
# awg-peer.sh — AmneziaWG 3.1 client lifecycle
#
#   ./awg-peer.sh add <name> [--keep-file] [--no-qr]
#   ./awg-peer.sh remove <name>
#   ./awg-peer.sh list
#
# Behaviour:
#
#  * Reads every deployment value from deployment.env.
#  * Takes an flock, so concurrent runs cannot hand the same address to two
#    peers.
#  * Applies the peer to the live interface itself (awg syncconf, not
#    `down && up`), so existing sessions are not torn down.
#  * Prints a QR code and does NOT leave the private key on the server's disk
#    unless --keep-file is given.
#  * Re-randomises Jc/Jmin/Jmax per client. Those are the only parameters
#    AmneziaWG permits to differ between the two ends, and varying them means
#    two clients of the same server do not present the same junk profile.
#  * `remove` drops a peer from the live interface, the config and the peer
#    index in one step.

set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

META_FILE="/etc/amnezia/amneziawg/deployment.env"
LOCK_FILE="/run/awg-peer.lock"

say()  { printf '\n\033[1;36m==>\033[0m %s\n' "$*"; }
ok()   { printf '    \033[1;32m[ok]\033[0m %s\n' "$*"; }
warn() { printf '    \033[1;33m[!!]\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31m[fatal]\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root"
[[ -f "$META_FILE" ]] || die "$META_FILE not found — run awg-bootstrap.sh first"
# shellcheck disable=SC1090
. "$META_FILE"

SERVER_CONF="${AWG_DIR}/${IFACE}.conf"
OBFS_FILE="${AWG_DIR}/obfuscation-params.conf"
CLIENT_DIR="/root/awg-clients"

exec 9>"$LOCK_FILE"
flock -w 10 9 || die "another awg-peer.sh is running"

sync_live() {
  if ip link show "$IFACE" >/dev/null 2>&1; then
    awg syncconf "$IFACE" <(awg-quick strip "$IFACE")
    ok "live interface synced (existing sessions untouched)"
  else
    warn "${IFACE} is down; config updated but nothing applied"
  fi
}

# ------------------------------------------------------------------------ list
cmd_list() {
  printf '%-20s %-18s %s\n' NAME ADDRESS 'LAST HANDSHAKE'
  local name ip pub
  while read -r name ip pub; do
    [[ -n "$name" ]] || continue
    local hs
    hs="$(awg show "$IFACE" latest-handshakes 2>/dev/null \
          | awk -v k="$pub" '$1==k{print $2}')"
    if [[ -z "$hs" || "$hs" == "0" ]]; then
      hs="never"
    else
      hs="$(( $(date +%s) - hs ))s ago"
    fi
    printf '%-20s %-18s %s\n' "$name" "$ip" "$hs"
  done < <(awk '/^# peer:/{print $3, $4, $5}' "$SERVER_CONF")
}

# ------------------------------------------------------------------------- add
cmd_add() {
  local name="$1" keep_file="$2" want_qr="$3"

  [[ "$name" =~ ^[a-zA-Z0-9_-]+$ ]] || die "name must be alphanumeric (dash/underscore ok)"
  grep -q "^# peer: ${name} " "$SERVER_CONF" && die "peer '${name}' already exists"

  # Next free octet, taken from the peer index rather than by grepping
  # AllowedIPs, so a malformed line cannot cause a silent duplicate.
  local used octet=""
  used="$(awk '/^# peer:/{split($4,a,"."); print a[4]}' "$SERVER_CONF" | sort -n)"
  local i
  for i in $(seq 2 254); do
    grep -qx "$i" <<<"$used" || { octet="$i"; break; }
  done
  [[ -n "$octet" ]] || die "no free addresses in ${VPN_SUBNET}.0/24"

  local cip="${VPN_SUBNET}.${octet}"
  local cip6="${VPN_SUBNET6}::${octet}"

  umask 077
  local priv pub psk
  priv="$(awg genkey)"
  pub="$(awg pubkey <<<"$priv")"
  psk="$(awg genpsk)"

  local allowed="0.0.0.0/0"
  local caddr="${cip}/32"
  local peer_allowed="${cip}/32"
  if [[ "${WANT_V6}" == "1" ]]; then
    allowed="0.0.0.0/0, ::/0"
    caddr="${cip}/32, ${cip6}/128"
    peer_allowed="${cip}/32, ${cip6}/128"
  fi

  # Jc/Jmin/Jmax are the only parameters allowed to differ per side.
  local jc jmin jmax
  jc="$(shuf -i "${PEER_JC:-4-12}" -n 1)"; jmin="${PEER_JMIN:-8}"
  jmax="$(shuf -i "${PEER_JMAX:-64-96}" -n 1)"

  local conf
  conf="$(
    printf '[Interface]\n'
    printf 'Address = %s\n' "$caddr"
    printf 'PrivateKey = %s\n' "$priv"
    printf 'DNS = %s\n' "$DNS"
    printf 'MTU = %s\n' "$MTU"
    printf '\n'
    printf '# Shared obfuscation parameters — must match the server exactly,\n'
    printf '# except Jc/Jmin/Jmax which are per-peer by design.\n'
    printf 'Jc = %s\nJmin = %s\nJmax = %s\n' "$jc" "$jmin" "$jmax"
    sed '/^#/d;/^$/d;/^J\(c\|min\|max\) /d' "$OBFS_FILE"
    printf '\n[Peer]\n'
    printf 'PublicKey = %s\n' "$(cat "${AWG_DIR}/server_public.key")"
    printf 'PresharedKey = %s\n' "$psk"
    printf 'Endpoint = %s\n' "$SERVER_ENDPOINT"
    printf 'AllowedIPs = %s\n' "$allowed"
    printf 'PersistentKeepalive = 25\n'
  )"

  {
    printf '\n# peer: %s %s %s (added %s)\n' "$name" "$cip" "$pub" "$(date -Iseconds)"
    printf '[Peer]\n'
    printf 'PublicKey = %s\n' "$pub"
    printf 'PresharedKey = %s\n' "$psk"
    printf 'AllowedIPs = %s\n' "$peer_allowed"
  } >> "$SERVER_CONF"

  sync_live

  say "Client '${name}' — ${cip}"
  if [[ "$want_qr" == "1" ]] && command -v qrencode >/dev/null 2>&1; then
    qrencode -t ansiutf8 <<<"$conf"
  fi

  if [[ "$keep_file" == "1" ]]; then
    install -d -m 700 "$CLIENT_DIR"
    printf '%s\n' "$conf" > "${CLIENT_DIR}/${name}.conf"
    chmod 600 "${CLIENT_DIR}/${name}.conf"
    warn "private key written to ${CLIENT_DIR}/${name}.conf — shred it after transfer"
  else
    printf '\n%s\n\n' "$conf"
    ok "config printed above and not stored on this host"
  fi
}

# ---------------------------------------------------------------------- remove
cmd_remove() {
  local name="$1" pub
  pub="$(awk -v n="$name" '/^# peer:/ && $3==n {print $5}' "$SERVER_CONF")"
  [[ -n "$pub" ]] || die "no peer named '${name}'"

  ip link show "$IFACE" >/dev/null 2>&1 && awg set "$IFACE" peer "$pub" remove

  # Delete the marker comment plus the [Peer] stanza that follows it.
  awk -v n="$name" '
    /^# peer:/ { drop = ($3 == n); if (drop) next }
    drop && /^\[Peer\]/ { next }
    drop && /^(PublicKey|PresharedKey|AllowedIPs) *=/ { next }
    drop && NF == 0 { drop = 0; next }
    { print }
  ' "$SERVER_CONF" > "${SERVER_CONF}.new"
  mv "${SERVER_CONF}.new" "$SERVER_CONF"
  chmod 600 "$SERVER_CONF"
  rm -f "${CLIENT_DIR}/${name}.conf"
  ok "peer '${name}' removed from the live interface and the config"
}

# ------------------------------------------------------------------------ main
KEEP=0; QR=1
CMD="${1:-}"; shift || true
NAME="${1:-}"; shift || true
while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep-file) KEEP=1; shift ;;
    --no-qr)     QR=0; shift ;;
    *) die "unknown argument: $1" ;;
  esac
done

case "$CMD" in
  add)    [[ -n "$NAME" ]] || die "usage: $0 add <name>";    cmd_add "$NAME" "$KEEP" "$QR" ;;
  remove) [[ -n "$NAME" ]] || die "usage: $0 remove <name>"; cmd_remove "$NAME" ;;
  list)   cmd_list ;;
  *) sed -n '2,6p' "$0"; exit 2 ;;
esac
