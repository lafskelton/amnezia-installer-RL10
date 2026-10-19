#!/usr/bin/env bash
#
# awg-doctor.sh — tells you which of the known failure modes this host has.
#
#   ./awg-doctor.sh              run every check
#   ./awg-doctor.sh --mtu-probe  additionally binary-search the real path MTU
#
# Each check corresponds to a known failure mode of this kind of deployment.
# Run it on the server and on a working client; the checks that differ are the
# ones that matter.

set -uo pipefail

PASS=0; FAIL=0; WARN=0
pass() { printf '  \033[1;32mPASS\033[0m  %s\n' "$*"; PASS=$((PASS+1)); }
fail() { printf '  \033[1;31mFAIL\033[0m  %s\n' "$*"; FAIL=$((FAIL+1)); }
warn() { printf '  \033[1;33mWARN\033[0m  %s\n' "$*"; WARN=$((WARN+1)); }
sect() { printf '\n\033[1;36m%s\033[0m\n' "$*"; }

META="/etc/amnezia/amneziawg/deployment.env"
IFACE=awg0; WAN_IF=eth0; MTU=1360; SERVER_ENDPOINT=""; PROFILE=balanced
# shellcheck disable=SC1090
[[ -f "$META" ]] && . "$META"
KVER="$(uname -r)"

sect "1. Module and tools"

if [[ -r /sys/module/amneziawg/version ]]; then
  loaded="$(cat /sys/module/amneziawg/version)"
  pass "module loaded, version ${loaded}"
else
  loaded=""
  fail "amneziawg module is not loaded (dmesg | grep -i amneziawg)"
fi

tools="$(awg --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]{8}' | head -1)"
[[ -n "$tools" ]] || fail "awg not installed or unversioned"

# Disk vs RAM is the meaningful comparison. Tools vs module is not: the module
# stamps its version from a header the build can only populate correctly when
# git metadata is present, so a source-copy build self-reports a placeholder
# (commonly 1.0.0) regardless of which tag it came from.
ondisk="$(modinfo -F version /lib/modules/"${KVER}"/*/amneziawg.ko* 2>/dev/null | head -1)"
if [[ -n "$ondisk" && -n "$loaded" && "$ondisk" != "$loaded" ]]; then
  fail "on disk ${ondisk}, running ${loaded} — an old module is still resident
        and the built one is unused. Every rebuild has changed nothing. Reboot."
elif [[ -n "$loaded" ]]; then
  pass "running module matches the one on disk (${loaded})"
fi

if [[ -n "$tools" && "$tools" != "$loaded" ]]; then
  warn "module reports '${loaded}', tools report '${tools}'. Check 5 decides
        whether this is a real UAPI mismatch or just a version-string artefact."
fi

# depmod prefers updates/ over extra/, so a leftover from an earlier install
# silently wins over everything DKMS builds afterwards.
mapfile -t kos < <(find "/lib/modules/${KVER}" -name 'amneziawg.ko*' 2>/dev/null)
case "${#kos[@]}" in
  0) fail "no amneziawg.ko under /lib/modules/${KVER}" ;;
  1) pass "exactly one module on disk: ${kos[0]}" ;;
  *) fail "${#kos[@]} copies of amneziawg.ko on disk:
        $(printf '%s\n        ' "${kos[@]}")
        depmod loads updates/ before extra/. Purge and reinstall." ;;
esac

sect "2. Kernel and build environment"

if [[ "$KVER" == *linode* ]]; then
  fail "running a provider-supplied kernel ($KVER); no kernel-devel exists for it.
        Boot the distribution kernel instead (e.g. 'GRUB 2' on Linode) and reboot."
elif [[ -d "/usr/src/kernels/${KVER}" ]]; then
  pass "kernel-devel matches the running kernel"
else
  fail "no /usr/src/kernels/${KVER} — DKMS cannot rebuild on kernel update"
fi

if dkms status 2>/dev/null | grep -q "amneziawg.*${KVER}.*installed"; then
  pass "DKMS reports the module installed for the running kernel"
else
  warn "DKMS has no installed entry for ${KVER}; next kernel update will lose the module"
fi

sect "3. Firewall"

RULES="$(nft list ruleset 2>/dev/null)"
if ! command -v nft >/dev/null 2>&1; then
  fail "nftables is not installed. Minimal cloud images often ship neither it
        nor firewalld, so there is no ruleset at all — and therefore no NAT.
        Clients forward out ${WAN_IF} still sourced from the VPN subnet and are
        dropped upstream. Run: dnf install -y nftables"
elif [[ -z "$RULES" ]]; then
  fail "nft is installed but the ruleset is empty. Same consequence: no
        masquerade, so tunnelled traffic leaves with a private source address.
        Load awg.nft and enable nftables.service."
elif ! grep -q 'masquerade' <<<"$RULES"; then
  fail "no masquerade rule in the live ruleset. VPN clients cannot reach the
        internet through this host."
else
  pass "ruleset loaded with a masquerade rule present"
fi

# NAT from two places at once is worse than from one.
if grep -qiE '^\s*Post(Up|Down)' /etc/amnezia/amneziawg/*.conf 2>/dev/null; then
  warn "awg0.conf carries PostUp/PostDown rules. If those do masquerade via
        iptables and you also load awg.nft, NAT is configured twice. Pick one —
        awg.nft expects to own it."
fi

if [[ -n "$RULES" ]] && grep -qE 'udp dport [0-9]+ notrack' <<<"$RULES" \
     && ! grep -qE 'iifname "[^"]+" udp dport [0-9]+ notrack' <<<"$RULES"; then
  fail "unscoped 'udp dport N notrack' in raw prerouting.
        This matches VPN clients' own outbound QUIC/HTTP-3 arriving on ${IFACE}.
        Untracked packets skip nf_nat, so they leave the box with a private
        source address and are dropped upstream. Browsers stall on every
        HTTP/3 site and fall back to TCP. Scope it to iifname ${WAN_IF}."
else
  pass "notrack is scoped to an interface (or absent)"
fi

if grep -q 'maxseg size set rt mtu' <<<"$RULES" && ! grep -q 'maxseg size >' <<<"$RULES"; then
  fail "MSS rule uses 'size set rt mtu' with no 'size >' guard.
        nftables writes the value unconditionally, so a correct small MSS from
        the tunnel gets RAISED to the WAN MTU. The remote then sends segments
        too large for the tunnel. Use a guarded clamp."
else
  pass "MSS clamping looks like a clamp, not an unconditional set"
fi

if grep -qE 'ip ttl set (6[0-9]|[0-9]{1,2})' <<<"$RULES"; then
  warn "TTL rewriting is active. An unusual TTL (e.g. 65) is a value almost
        nothing else on the internet emits — on a DPI-resistance host it is a
        signature, not a defence. Stock Linux uses 64."
fi

if grep -q 'icmpv6 type { nd-' <<<"$RULES" || ! grep -q 'icmpv6' <<<"$RULES"; then
  pass "ICMPv6 handling present or IPv6 unused"
else
  warn "ICMPv6 appears filtered without NDP accepts; IPv6 on ${WAN_IF} may be broken"
fi

sect "4. Conntrack capacity"

if [[ -r /proc/sys/net/netfilter/nf_conntrack_count ]]; then
  cur="$(cat /proc/sys/net/netfilter/nf_conntrack_count)"
  max="$(cat /proc/sys/net/netfilter/nf_conntrack_max)"
  pct=$(( cur * 100 / (max > 0 ? max : 1) ))
  if (( max < 131072 )); then
    fail "nf_conntrack_max is ${max} (${cur} in use, ${pct}%).
        A NAT gateway carrying this much traffic exhausts that and starts
        dropping new connections. Symptom: everything degrades at once under
        load, then recovers. Check: dmesg | grep -i 'table full'."
  elif (( pct > 70 )); then
    warn "conntrack ${pct}% full (${cur}/${max})"
  else
    pass "conntrack ${cur}/${max} (${pct}%)"
  fi
  dmesg 2>/dev/null | grep -qi 'nf_conntrack.*table full' \
    && fail "dmesg shows conntrack table-full drops"
else
  warn "nf_conntrack not loaded; its sysctls will not have applied at boot"
fi

sect "5. Live interface parameters"

if ip link show "$IFACE" >/dev/null 2>&1; then
  livemtu="$(ip -o link show "$IFACE" | grep -oP 'mtu \K[0-9]+')"
  if [[ "$livemtu" == "1420" ]]; then
    warn "${IFACE} MTU is 1420, the awg-quick default. That assumes a clean
        1500-byte path. Across a mobile carrier this produces stalls on large
        transfers while handshakes and small requests succeed. Run --mtu-probe."
  else
    pass "${IFACE} MTU = ${livemtu}"
  fi

  # The check that catches silently-discarded parameters. Expected keys are
  # read from the obfuscation file itself, so this follows the profile.
  live="$(awg showconf "$IFACE" 2>/dev/null)"
  obfs="/etc/amnezia/amneziawg/obfuscation-params.conf"
  pass "profile: ${PROFILE}"
  while read -r key; do
    [[ -n "$key" ]] || continue
    if grep -qi "^${key}[[:space:]]*=" <<<"$live"; then
      pass "live interface has ${key}"
    else
      fail "${key} is in the config file but NOT on the live interface.
        awg setconf accepted the file and discarded what the module does not
        implement. Version mismatch — see check 1."
    fi
  done < <(grep -oE '^[A-Za-z0-9]+' "$obfs" 2>/dev/null | sort -u)

  if [[ "$PROFILE" == "balanced" ]]; then
    # showconf prints these at their defaults whenever Header Protection is
    # active, so presence means nothing; only a non-default value is a cost.
    for key in RandomTrailers ContentPaddingAddition DisableCookies; do
      val="$(sed -n "s/^${key}[[:space:]]*=[[:space:]]*//Ip" <<<"$live" | head -1)"
      case "${val,,}" in
        ""|off|0|0-0) ;;
        *) warn "${key} = ${val} on a balanced host — per-packet cost you did not ask for" ;;
      esac
    done
    if ! grep -qi '^HeaderProtectionKey' "$obfs" 2>/dev/null; then
      grep -qi "^HeaderProtectionKey[[:space:]]*=" <<<"$live" \
        && warn "HeaderProtectionKey is live on a balanced host but not in ${obfs}"
    fi
    grep -qE '^H1[[:space:]]*=[[:space:]]*1$' <<<"$live" \
      && warn "H1-H4 are the stock 1-4 on a balanced host; message types are plain WireGuard"
  fi

  peers="$(awg show "$IFACE" peers 2>/dev/null | wc -l)"
  stale=0
  while read -r pk hs; do
    [[ "$hs" == "0" ]] && stale=$((stale+1))
  done < <(awg show "$IFACE" latest-handshakes 2>/dev/null)
  pass "${peers} peers configured, ${stale} have never completed a handshake"
else
  fail "${IFACE} is down"
fi

sect "6. Routing and sysctls"

[[ "$(sysctl -n net.ipv4.ip_forward)" == "1" ]] \
  && pass "ipv4 forwarding on" || fail "net.ipv4.ip_forward is 0"

v6fwd="$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null)"
v6cfg="$(grep -c '::/0' /etc/amnezia/amneziawg/*.conf 2>/dev/null || echo 0)"
if [[ "$v6cfg" != "0" && "$v6fwd" != "1" ]]; then
  fail "clients route ::/0 into the tunnel but net.ipv6.conf.all.forwarding=0.
        Every dual-stack destination eats a Happy-Eyeballs timeout before
        falling back to v4. Either enable v6 end to end or drop ::/0."
else
  pass "IPv6 forwarding is consistent with the client AllowedIPs"
fi

cc="$(sysctl -n net.ipv4.tcp_congestion_control)"
ts="$(sysctl -n net.ipv4.tcp_timestamps)"
if [[ "$cc" == "bbr" && "$ts" == "0" ]]; then
  fail "BBR is enabled with tcp_timestamps=0. BBR needs timestamped RTT
        samples; disabling them also disables PAWS. Set tcp_timestamps=1."
else
  pass "congestion control ${cc}, timestamps ${ts}"
fi

rp="$(sysctl -n net.ipv4.conf.${WAN_IF}.rp_filter 2>/dev/null || echo '?')"
[[ "$rp" == "?" ]] && warn "no rp_filter setting for ${WAN_IF} (check for sysctl
        entries naming interfaces that do not exist on this host)" \
                    || pass "${WAN_IF} rp_filter = ${rp}"

sect "7. Recent errors"
journalctl -u "awg-quick@${IFACE}" -n 15 --no-pager 2>/dev/null | grep -iE 'error|fail|invalid' \
  && fail "errors in the awg-quick journal (above)" \
  || pass "no recent awg-quick errors"

if [[ "${1:-}" == "--mtu-probe" && -n "$SERVER_ENDPOINT" ]]; then
  sect "8. Path MTU probe"
  host="${SERVER_ENDPOINT%%:*}"
  lo=1200; hi=1500; best=0
  while (( lo <= hi )); do
    mid=$(( (lo + hi) / 2 ))
    if ping -c1 -W2 -M do -s $(( mid - 28 )) "$host" >/dev/null 2>&1; then
      best=$mid; lo=$(( mid + 1 ))
    else
      hi=$(( mid - 1 ))
    fi
  done
  if (( best > 0 )); then
    printf '  path MTU to %s is %s; set the tunnel MTU to %s or below\n' \
      "$host" "$best" "$(( best - 80 ))"
  else
    warn "probe inconclusive (ICMP may be filtered on this path)"
  fi
fi

printf '\n\033[1m%d passed, %d warnings, %d failed\033[0m\n' "$PASS" "$WARN" "$FAIL"
exit $(( FAIL > 0 ))
