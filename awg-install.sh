#!/usr/bin/env bash
#
# awg-install.sh — AmneziaWG kernel module + tools installer for EL10
# (Rocky / Alma / RHEL 10) and Fedora 44 (7.x kernels). Idempotent; safe to
# re-run.
#
#   ./awg-install.sh                      install/repair at the pinned version
#   ./awg-install.sh --version vX         install a different tagged release
#   ./awg-install.sh --purge-only         tear down, install nothing
#   ./awg-install.sh --firewall-only      re-apply sysctls and nftables only
#   ./awg-install.sh --disable-firewalld  let awg.nft replace firewalld
#
# Fedora notes: the pinned tag predates 7.1, so the DKMS pre-build hook
# patches the 7.x API breaks into the build copy (see "Compat shims for 7.x").
# Fedora installs usually run firewalld and have Secure Boot on; both are
# handled below rather than assumed absent as on a cloud VM.
#
# Design notes:
#
#  1. BOTH repositories are pinned to the same release tag. amneziawg-tools and
#     the kernel module ship in lockstep with a shared date tag, and the UAPI
#     between them changes with it — 3.x added HeaderProtectionKey,
#     ContentPaddingAddition and the timing ranges as new netlink keys. Build
#     them on two different days and `awg setconf` will reject or silently
#     ignore parameters it does not know.
#
#  2. The purge covers updates/dkms/ and weak-updates/, not just extra/.
#     depmod's search order prefers updates/ over extra/, so a leftover module
#     from an earlier install wins over everything DKMS puts in extra/
#     afterwards. Every rebuild looks successful and the kernel keeps loading
#     the old module.
#
#  3. Kernel source resolution is layered, cached outside /tmp, and recorded.
#     The pre-build hook also runs unattended during DKMS autoinstall on kernel
#     updates, so it must not depend on /tmp surviving, and it prefers the
#     distribution's own (backported) kernel tree over upstream stable.
#
#  4. MOK enrollment is gated on Secure Boot actually being enabled. Most cloud
#     VMs have no MOK manager.
#
#  5. It verifies at the end that the module the kernel LOADED matches the
#     tools, rather than assuming a clean `dkms install` means success.

set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

# ---------------------------------------------------------------- configuration
AWG_TAG="${AWG_TAG:-v3.1.20260812}"
DKMS_NAME="amneziawg"
DKMS_VER="${AWG_TAG#v}"
DKMS_SRC="/usr/src/${DKMS_NAME}-${DKMS_VER}"
CACHE_DIR="/var/cache/amneziawg"
SRC_CACHE="${CACHE_DIR}/kernel-src"
STRATEGY_FILE="${CACHE_DIR}/source-strategy"
KVER="$(uname -r)"

MOD_REPO="https://github.com/amnezia-vpn/amneziawg-linux-kernel-module.git"
TOOLS_REPO="https://github.com/amnezia-vpn/amneziawg-tools.git"

MOK_PUB="/var/lib/dkms/mok.pub"

PURGE_ONLY=0
FIREWALL_ONLY=0
DISABLE_FIREWALLD=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) AWG_TAG="$2"; DKMS_VER="${AWG_TAG#v}"
               DKMS_SRC="/usr/src/${DKMS_NAME}-${DKMS_VER}"; shift 2 ;;
    --purge-only) PURGE_ONLY=1; shift ;;
    --firewall-only) FIREWALL_ONLY=1; shift ;;
    --disable-firewalld) DISABLE_FIREWALLD=1; shift ;;
    -h|--help) sed -n '2,42p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

say()  { printf '\n\033[1;36m==>\033[0m %s\n' "$*"; }
ok()   { printf '    \033[1;32m[ok]\033[0m %s\n' "$*"; }
warn() { printf '    \033[1;33m[!!]\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31m[fatal]\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root (this script does not shell out to sudo)"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NFT_SVC_CONF="/etc/sysconfig/nftables.conf"

# ------------------------------------------------------------------- firewall
# Installs the ruleset the way EL actually wants it, which is not the way the
# nftables documentation for Debian describes.
#
# Three things bite here and all three are automated below:
#
#  1. nftables.service reads /etc/sysconfig/nftables.conf. /etc/nftables.conf
#     is Debian's path and is ignored. Because ExecStop is `nft flush ruleset`,
#     a ruleset loaded by hand from the wrong path disappears at the next
#     service start — the firewall looks fine until it silently isn't.
#
#  2. The documented `include "/etc/nftables/foo.nft"` indirection fails under
#     enforcing SELinux when the included file was created by hand: the service
#     runs confined and cannot read a file labelled from your login shell, so
#     nft reports "Could not open file" for a file that plainly exists. Writing
#     the rules directly into the service's own config sidesteps it, and the
#     redirection below reuses that file's inode so it keeps the label the
#     package shipped.
#
#  3. WAN_IF and the MSS values have to match this host. Every forward and NAT
#     rule keys off WAN_IF, so a stale `eth0` on a host that names its
#     interface something else matches nothing and silently breaks egress.
#     The installer rewrites them from the live default route.
#
#  4. Fedora runs firewalld by default. awg.nft opens with `flush ruleset`,
#     which deletes firewalld's tables out from under it, and whatever
#     firewalld reinstates on its next reload is a second set of input and
#     forward hooks that drop AWG traffic regardless of what awg.nft accepts.
#     The two cannot share a host, so firewalld is only replaced on request.
install_firewall() {
  local src tmp bak wan mtu mss4 mss6

  src="${SCRIPT_DIR}/awg.nft"
  [[ -f "$src" ]] || src="${SCRIPT_DIR}/awg.nft.txt"
  [[ -f "$src" ]] || { warn "no awg.nft beside this script; skipping firewall"; return 0; }

  command -v nft >/dev/null 2>&1 || { warn "nft not installed; skipping firewall"; return 0; }

  if systemctl is-active --quiet firewalld 2>/dev/null; then
    if (( ! DISABLE_FIREWALLD )); then
      warn "firewalld is running; awg.nft would flush its tables. Skipping firewall."
      warn "Without awg.nft there is no NAT for VPN clients. To hand the host over:"
      warn "    ./awg-install.sh --firewall-only --disable-firewalld"
      return 0
    fi
    systemctl disable --now firewalld >/dev/null 2>&1 || die "could not stop firewalld"
    ok "firewalld stopped and disabled (--disable-firewalld)"
  fi

  wan="$(ip -o -4 route show default 2>/dev/null | awk 'NR==1{print $5}')"
  [[ -n "$wan" ]] || die "no default route; cannot determine the WAN interface"

  # Bootstrap writes the MTU it chose; before bootstrap runs, fall back to the
  # same default it uses so the two never disagree.
  # Port and subnets too, so --port / --subnet at bootstrap carry through.
  local port=443 net="10.4.20" net6="fd42:4:20"
  mtu=1360
  local ssh4="0.0.0.0/0" ssh6="::/0" ssh_allow="" tok
  if [[ -f /etc/amnezia/amneziawg/deployment.env ]]; then
    # shellcheck disable=SC1091
    read -r mtu port net net6 < <(
      . /etc/amnezia/amneziawg/deployment.env 2>/dev/null
      echo "${MTU:-1360} ${LISTEN_PORT:-${SERVER_ENDPOINT##*:}} ${VPN_SUBNET:-10.4.20} ${VPN_SUBNET6:-fd42:4:20}")
  fi
  # Optional SSH allowlist from deployment.env; unset keeps SSH open.
  if [[ -f /etc/amnezia/amneziawg/deployment.env ]]; then
    ssh_allow="$(. /etc/amnezia/amneziawg/deployment.env 2>/dev/null; echo "${SSH_ALLOW:-}")"
  fi
  if [[ -n "$ssh_allow" ]]; then
    ssh4=""; ssh6=""
    for tok in ${ssh_allow//,/ }; do
      [[ "$tok" =~ ^[0-9a-fA-F:./]+$ ]] || die "SSH_ALLOW entry '${tok}' is not an address or CIDR"
      if [[ "$tok" == *:* ]]; then ssh6+="${ssh6:+, }${tok}"; else ssh4+="${ssh4:+, }${tok}"; fi
    done
    # An empty family would be an invalid set; 0.0.0.0/32 and ::/128 match nothing.
    ssh4="${ssh4:-0.0.0.0/32}"; ssh6="${ssh6:-::/128}"
  fi
  mss4=$(( mtu - 40 ))
  mss6=$(( mtu - 60 ))

  tmp="$(mktemp)"
  sed -e "s|^define WAN_IF .*|define WAN_IF   = ${wan}|" \
      -e "s|^define AWG_PORT .*|define AWG_PORT = ${port}|" \
      -e "s|^define AWG_NET .*|define AWG_NET  = ${net}.0/24|" \
      -e "s|^define AWG_NET6 .*|define AWG_NET6 = ${net6}::/64|" \
      -e "s|^define SSH_SRC4 .*|define SSH_SRC4 = { ${ssh4} }|" \
      -e "s|^define SSH_SRC6 .*|define SSH_SRC6 = { ${ssh6} }|" \
      -e "s|^define MSS4 .*|define MSS4     = ${mss4}|" \
      -e "s|^define MSS6 .*|define MSS6     = ${mss6}|" \
      "$src" > "$tmp"

  nft -c -f "$tmp" || { rm -f "$tmp"; die "ruleset failed to parse; nothing applied"; }
  ok "ruleset parses (WAN_IF=${wan}, port ${port}, MTU=${mtu} -> MSS ${mss4}/${mss6})"

  if [[ -s "$NFT_SVC_CONF" ]]; then
    bak="${NFT_SVC_CONF}.bak-$(date +%Y%m%d%H%M%S)"
    cp -a "$NFT_SVC_CONF" "$bak"
    ok "existing config backed up to ${bak}"
  fi

  # Redirect rather than mv/cp: this keeps the original inode and therefore the
  # SELinux label that the nftables package applied. See note 2 above.
  install -d /etc/sysconfig
  cat "$tmp" > "$NFT_SVC_CONF"
  chmod 600 "$NFT_SVC_CONF"
  rm -f "$tmp"

  if command -v restorecon >/dev/null 2>&1 && [[ "$(getenforce 2>/dev/null)" != "Disabled" ]]; then
    restorecon -F "$NFT_SVC_CONF" 2>/dev/null || true
  fi

  systemctl enable nftables >/dev/null 2>&1 || true

  # Restart, not just start. Starting proves the file loads; restarting proves
  # it survives the flush-on-stop, which is the failure mode that matters.
  if ! systemctl restart nftables; then
    warn "nftables.service failed to start; restoring previous config"
    [[ -n "${bak:-}" ]] && cat "$bak" > "$NFT_SVC_CONF"
    systemctl restart nftables 2>/dev/null || true
    die "firewall not applied. Check: journalctl -xeu nftables.service"
  fi

  nft list table inet nat >/dev/null 2>&1 \
    || die "nftables started but the nat table is absent — clients will have no NAT"
  nft list table inet filter >/dev/null 2>&1 \
    || die "nftables started but the filter table is absent"

  ok "firewall applied and survives a service restart"
  ok "NAT masquerade present for VPN clients egressing via ${wan}"
}

apply_sysctls() {
  local f fwd conflict

  for f in "${SCRIPT_DIR}/99-awg-network.conf" "${SCRIPT_DIR}/99-awg-network.conf.txt"; do
    [[ -f "$f" ]] || continue
    install -m 644 "$f" /etc/sysctl.d/99-awg-network.conf
    ok "installed /etc/sysctl.d/99-awg-network.conf"
    break
  done
  # Optional: a kernel-hardening file of your own, kept separate from the
  # network tuning above.
  f="${SCRIPT_DIR}/60-kernel-hardening.conf"
  if [[ -f "$f" ]]; then
    install -m 644 "$f" /etc/sysctl.d/60-kernel-hardening.conf
    ok "installed /etc/sysctl.d/60-kernel-hardening.conf"
  fi

  # nf_conntrack first, so its keys exist by the time sysctl reads them.
  modprobe nf_conntrack 2>/dev/null || true
  sysctl --system >/dev/null 2>&1 || true

  # systemd-sysctl applies every file in lexical order across /etc/sysctl.d,
  # /usr/lib/sysctl.d and /run/sysctl.d, last definition wins, and
  # /etc/sysctl.conf is applied after all of them. So installing our file is no
  # guarantee it is the one in effect.
  conflict="$(grep -rlE '^[^#]*ip_forward' \
      /etc/sysctl.conf /etc/sysctl.d/ /usr/lib/sysctl.d/ /run/sysctl.d/ 2>/dev/null \
      | grep -v '99-awg-network.conf' || true)"
  if [[ -n "$conflict" ]]; then
    warn "ip_forward is also defined in:"
    printf '         %s\n' $conflict
    warn "anything sorting after 99-awg-network.conf overrides it"
  fi

  fwd="$(sysctl -n net.ipv4.ip_forward)"
  if [[ "$fwd" != "1" ]]; then
    warn "net.ipv4.ip_forward was ${fwd} after applying sysctl.d — forcing it now"
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    fwd="$(sysctl -n net.ipv4.ip_forward)"
  fi
  [[ "$fwd" == "1" ]] || die "could not enable net.ipv4.ip_forward.
     Clients will reach this host but never the internet."
  ok "net.ipv4.ip_forward = 1"

  if [[ -f /etc/amnezia/amneziawg/deployment.env ]]; then
    # shellcheck disable=SC1091
    if [[ "$(. /etc/amnezia/amneziawg/deployment.env; echo "${WANT_V6:-0}")" == "1" ]]; then
      sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
      [[ "$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null)" == "1" ]] \
        && ok "net.ipv6.conf.all.forwarding = 1" \
        || warn "IPv6 forwarding is off but clients route ::/0 — dual-stack sites will stall"
    fi
  fi
}

if [[ $FIREWALL_ONLY -eq 1 ]]; then
  say "Firewall and sysctls only"
  apply_sysctls
  install_firewall
  say "Done."
  exit 0
fi

# ------------------------------------------------------------------- preflight
say "Preflight"

[[ -r /etc/os-release ]] || die "no /etc/os-release"
# shellcheck disable=SC1091
. /etc/os-release
IS_FEDORA=0
case "${ID}${VERSION_ID%%.*}" in
  rocky10|almalinux10|rhel10|centos10) ok "EL10 detected: ${PRETTY_NAME}" ;;
  fedora44) IS_FEDORA=1; ok "Fedora 44 detected: ${PRETTY_NAME}" ;;
  fedora*)  IS_FEDORA=1; warn "expected Fedora 44, found ${PRETTY_NAME}. Continuing anyway." ;;
  *) warn "expected EL10 or Fedora 44, found ${PRETTY_NAME:-unknown}. Continuing anyway." ;;
esac

# Some providers (e.g. Linode with the "Latest 64 bit" boot setting) boot a
# provider-supplied kernel instead of the one on disk. There is no matching
# kernel-devel for it, so DKMS would build against a different tree than the
# one running.
if [[ "$KVER" == *linode* ]]; then
  die "running a provider-supplied kernel ($KVER). No kernel-devel exists for it.
     Switch the instance to boot the distribution kernel (e.g. Linode:
     Configuration Profile -> Boot Settings -> Kernel -> 'GRUB 2'), reboot,
     and re-run this script."
fi

if ! command -v awg >/dev/null 2>&1 && [[ $PURGE_ONLY -eq 0 ]]; then
  avail_kb="$(df -Pk /usr/src | awk 'NR==2{print $4}')"
  (( avail_kb > 3000000 )) || warn "less than 3 GB free on /usr/src; a full kernel source fallback may not fit"
fi

ok "kernel: $KVER"

# ----------------------------------------------------------------------- purge
say "Purging previous state"

systemctl stop 'awg-quick@*' 2>/dev/null || true

# An interface holding the module makes rmmod return EBUSY. Swallowing that
# leaves the OLD module resident, and every later modprobe is a silent no-op —
# so the build lands on disk unused and /sys/module reports the old version
# forever. Tear the interfaces down first, and refuse to continue if the
# module is still loaded afterwards.
for i in $(awg show interfaces 2>/dev/null); do
  warn "tearing down interface: $i"
  awg-quick down "$i" 2>/dev/null || ip link del "$i" 2>/dev/null || true
done
while read -r l; do
  [[ -n "$l" ]] && ip link del "$l" 2>/dev/null || true
done < <(ip -o link show type "$DKMS_NAME" 2>/dev/null | awk -F': ' '{print $2}')

if lsmod | grep -q "^${DKMS_NAME} "; then
  modprobe -r "$DKMS_NAME" 2>/dev/null || rmmod "$DKMS_NAME" 2>/dev/null || true
fi
if lsmod | grep -q "^${DKMS_NAME} "; then
  die "${DKMS_NAME} is still loaded and cannot be unloaded:
       $(lsmod | grep "^${DKMS_NAME} ")
     Something still holds a reference. Find it with
         awg show interfaces ; ip -d link show type ${DKMS_NAME}
     or just reboot — a fresh boot loads whatever is on disk. Re-run after."
fi
ok "module unloaded"

# Every DKMS version, not just the one we are about to install.
while read -r ver; do
  [[ -n "$ver" ]] || continue
  dkms remove -m "$DKMS_NAME" -v "$ver" --all 2>/dev/null || true
  rm -rf "/usr/src/${DKMS_NAME}-${ver}"
done < <(find /usr/src -maxdepth 1 -name "${DKMS_NAME}-*" -printf '%f\n' 2>/dev/null | sed "s/^${DKMS_NAME}-//")

# depmod prefers updates/ over extra/, so stale copies must go from all of them.
removed=0
for kdir in /lib/modules/*/; do
  for sub in extra updates/dkms updates weak-updates; do
    for f in "${kdir}${sub}/${DKMS_NAME}".ko*; do
      [[ -e "$f" ]] || continue
      warn "removing stale module: $f"
      rm -f "$f"
      removed=1
    done
  done
done
(( removed )) && warn "stale modules were present — that alone can explain a working build with broken behaviour"

# Keep the DKMS signing key if firmware already trusts it. Deleting it means
# DKMS mints a new one, which on a Secure Boot host is a reboot through
# MOKManager on every re-run, and until then every build is unloadable.
if [[ -f "$MOK_PUB" ]] && mokutil --test-key "$MOK_PUB" 2>/dev/null | grep -q 'already enrolled'; then
  ok "keeping DKMS signing key (enrolled in MOK)"
  rm -rf /root/mok 2>/dev/null || true
else
  rm -rf /root/mok /var/lib/dkms/mok.* 2>/dev/null || true
fi
depmod -a
ok "purged"

if [[ $PURGE_ONLY -eq 1 ]]; then
  say "Purge complete; nothing installed (--purge-only)."
  exit 0
fi

# ---------------------------------------------------------------- dependencies
say "Installing build dependencies"

# EL10 ships dnf5, where `config-manager --set-enabled` was replaced by
# `config-manager setopt`; try both.
enable_repo() {
  local repo="$1"
  if dnf config-manager setopt "${repo}.enabled=1" >/dev/null 2>&1; then
    ok "enabled repo: $repo (dnf5 syntax)"
  elif dnf config-manager --set-enabled "$repo" >/dev/null 2>&1; then
    ok "enabled repo: $repo (dnf4 syntax)"
  else
    warn "could not enable repo: $repo"
  fi
}

# Fedora carries everything below in its own repos. EPEL and CRB do not exist
# there, and the epel-release fallback failing would end the run under set -e.
if (( ! IS_FEDORA )); then
  dnf install -y "https://dl.fedoraproject.org/pub/epel/epel-release-latest-10.noarch.rpm" 2>/dev/null \
    || dnf install -y epel-release
  enable_repo crb
fi

dnf install -y dkms gcc make git bc openssl mokutil elfutils-libelf-devel \
               kernel-headers libmnl-devel qrencode nftables

# Minimal EL images often ship neither firewalld nor nftables. Without the
# nftables package there is no ruleset, and therefore no nat postrouting
# masquerade — VPN clients forward out of the WAN still carrying a private
# source address and get dropped upstream. The tunnel comes up and carries
# nothing.
systemctl enable nftables >/dev/null 2>&1 || warn "could not enable nftables.service"

# Exact-version kernel-devel. Installing bare `kernel-devel` pulls the newest
# available, which after any pending kernel update is NOT the running kernel.
if [[ ! -d "/usr/src/kernels/${KVER}" ]]; then
  if ! dnf install -y "kernel-devel-${KVER}"; then
    die "no kernel-devel-${KVER} available.
     Your running kernel is older than what the repos carry. Run:
         dnf -y update kernel && reboot
     then re-run this script."
  fi
fi
ok "kernel-devel present: /usr/src/kernels/${KVER}"

# ----------------------------------------------------------------------- tools
say "Building amneziawg-tools ${AWG_TAG}"

# Unconditional rebuild, so the tools never drift away from the module.
rm -rf "${CACHE_DIR}/tools"
mkdir -p "$CACHE_DIR"
git clone --depth 1 --branch "$AWG_TAG" "$TOOLS_REPO" "${CACHE_DIR}/tools"
make -C "${CACHE_DIR}/tools/src" -j"$(nproc)"
make -C "${CACHE_DIR}/tools/src" install
hash -r
ok "tools: $(awg --version 2>&1 | head -1)"

# ------------------------------------------------------- kernel source resolver
say "Preparing DKMS tree"

rm -rf "$DKMS_SRC" "${CACHE_DIR}/module"
git clone --depth 1 --branch "$AWG_TAG" "$MOD_REPO" "${CACHE_DIR}/module"
cp -a "${CACHE_DIR}/module/src" "$DKMS_SRC"

# The Makefile derives WIREGUARD_VERSION from git metadata when a .git exists
# and otherwise falls back to whatever the checked-in version.h carries — which
# in this tree is a placeholder (upstream's own docs build everything as
# "1.0.0"). Copying src/ out of the clone drops .git, so without this the
# module self-reports 1.0.0 no matter which tag was built, and every
# version-based check downstream reads as a mismatch.
if [[ -f "${DKMS_SRC}/version.h" ]] && grep -q 'WIREGUARD_VERSION' "${DKMS_SRC}/version.h"; then
  sed -i "s|^#define WIREGUARD_VERSION .*|#define WIREGUARD_VERSION \"${DKMS_VER}\"|" \
    "${DKMS_SRC}/version.h"
else
  printf '#ifndef WIREGUARD_VERSION\n#define WIREGUARD_VERSION "%s"\n#endif\n' \
    "$DKMS_VER" > "${DKMS_SRC}/version.h"
fi
ok "stamped version.h as ${DKMS_VER}"

mkdir -p "$SRC_CACHE"

# The resolver runs as the DKMS PRE_BUILD hook, so it also runs unattended when
# a kernel update triggers autoinstall. It reads a strategy recorded by this
# installer rather than rediscovering one, and caches under /var/cache so
# nothing depends on /tmp surviving.
cat > "${DKMS_SRC}/pre-build.sh" <<'PREBUILD'
#!/usr/bin/env bash
set -Eeuo pipefail

KERNEL_VER="${1:?kernel version required}"
K_BASE="$(cut -d. -f1,2 <<<"$KERNEL_VER")"
K_MAJ="$(cut -d. -f1 <<<"$KERNEL_VER")"
CACHE_DIR="/var/cache/amneziawg"
SRC_CACHE="${CACHE_DIR}/kernel-src"
STRATEGY="$(cat "${CACHE_DIR}/source-strategy" 2>/dev/null || echo headers)"

mkdir -p "$SRC_CACHE"
rm -f kernel

resolve_headers() {
  [[ -d "/usr/src/kernels/${KERNEL_VER}" ]] || return 1
  ln -sfn "/usr/src/kernels/${KERNEL_VER}" kernel
}

# The distribution's own source, pre-patched. This is the correct tree for an
# EL kernel; upstream stable is not.
resolve_srpm() {
  local dest="${SRC_CACHE}/el-${KERNEL_VER}"
  if [[ ! -d "$dest" ]]; then
    local work; work="$(mktemp -d "${CACHE_DIR}/srpm.XXXXXX")"
    ( cd "$work"
      dnf download --source "kernel-${KERNEL_VER%.*}" >/dev/null 2>&1 \
        || dnf download --source kernel >/dev/null 2>&1 || exit 1
      rpm2cpio ./*.src.rpm | cpio -idm 'linux-*.tar.xz' >/dev/null 2>&1 || exit 1
      mkdir -p "$dest.tmp"
      tar -xf ./linux-*.tar.xz -C "$dest.tmp" --strip-components=1
    ) || { rm -rf "$work" "$dest.tmp"; return 1; }
    rm -rf "$work"
    mv "$dest.tmp" "$dest"
  fi
  ln -sfn "$dest" kernel
}

resolve_upstream() {
  local dest="${SRC_CACHE}/upstream-${K_BASE}"
  if [[ ! -d "$dest" ]]; then
    local url="https://cdn.kernel.org/pub/linux/kernel/v${K_MAJ}.x/linux-${K_BASE}.tar.xz"
    mkdir -p "$dest.tmp"
    curl -fsSL "$url" | tar -xJ -C "$dest.tmp" --strip-components=1 || {
      rm -rf "$dest.tmp"; return 1; }
    mv "$dest.tmp" "$dest"
  fi
  ln -sfn "$dest" kernel
}

case "$STRATEGY" in
  headers)  resolve_headers  || resolve_srpm || resolve_upstream ;;
  srpm)     resolve_srpm     || resolve_upstream || resolve_headers ;;
  upstream) resolve_upstream || resolve_srpm || resolve_headers ;;
esac

[[ -e kernel ]] || { echo "pre-build: no usable kernel source tree" >&2; exit 1; }

# Compat shims for 6.12+. Guarded so they are idempotent and so a future
# upstream fix that removes the pattern does not fail the build.
if [[ -f compat/compat.h ]]; then
  grep -q '^static inline void netif_threaded_enable' compat/compat.h \
    && sed -i 's|^static inline void netif_threaded_enable|// &|' compat/compat.h
  grep -q '^#define timer_container_of from_timer' compat/compat.h \
    && sed -i 's|^#define timer_container_of from_timer|// &|' compat/compat.h
fi

# Compat shims for 7.x (Fedora 44 ships 7.2). Each one is keyed on what the
# target kernel's headers actually declare rather than on a version number:
# the UDP tunnel change was backported into 7.1.5 stable, and EL kernels
# backport freely, so a version cutoff would be wrong in both directions.
# DKMS passes KERNELRELEASE=$kernelver to make, so the module builds against
# /lib/modules/$kernelver/build — read the headers from the same place. All
# patterns match only the unpatched form, so re-running is a no-op, as is a
# future upstream tag that fixes these itself (v3.1.20260906 does).
KHDR="/lib/modules/${KERNEL_VER}/build/include"
[[ -d "$KHDR" ]] || KHDR="kernel/include"

# 7.1: setup_udp_tunnel_sock() and udp_tunnel_sock_release() take the
# struct sock rather than the struct socket. The pinned tag passes sockets,
# which is -Wincompatible-pointer-types, an error under the kernel's flags.
if grep -q 'void udp_tunnel_sock_release(struct sock \*' "$KHDR/net/udp_tunnel.h" 2>/dev/null; then
  sed -i -e 's/udp_tunnel_sock_release(sock->sk_socket)/udp_tunnel_sock_release(sock)/' \
         -e 's/udp_tunnel_sock_release(new\([46]\))/udp_tunnel_sock_release(new\1->sk)/' \
         socket.c
fi
if grep -q 'void setup_udp_tunnel_sock(struct net \*net, struct sock \*' "$KHDR/net/udp_tunnel.h" 2>/dev/null; then
  sed -i 's/setup_udp_tunnel_sock(net, new\([46]\), &cfg)/setup_udp_tunnel_sock(net, new\1->sk, \&cfg)/' socket.c
fi

# 7.2: strncpy() is gone from the kernel. Both call sites copy a bounded
# prefix and terminate it by hand, so strscpy() with count+1 is exact. It
# exists on every kernel this targets, so this one is unconditional.
sed -i 's/strncpy(addr_str, prefix_str, slash - prefix_str);/strscpy(addr_str, prefix_str, slash - prefix_str + 1);/' netlink.c

# 6.18+: a workqueue with neither WQ_PERCPU nor WQ_UNBOUND still works, but
# alloc_workqueue() WARN_ONCEs on it — a stack trace and a W taint on every
# boot, and a panic on hosts with panic_on_warn. Say explicitly what the old
# default was. wg-kex send is already WQ_UNBOUND and is left alone.
if grep -q 'WQ_PERCPU' "$KHDR/linux/workqueue.h" 2>/dev/null; then
  sed -i -e 's/WQ_CPU_INTENSIVE | WQ_FREEZABLE, 0, dev->name/WQ_CPU_INTENSIVE | WQ_FREEZABLE | WQ_PERCPU, 0, dev->name/' \
         -e 's/WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM, 0, dev->name/WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM | WQ_PERCPU, 0, dev->name/' \
         device.c
fi

exit 0
PREBUILD
chmod +x "${DKMS_SRC}/pre-build.sh"

cat > "${DKMS_SRC}/dkms.conf" <<EOF
PACKAGE_NAME="${DKMS_NAME}"
PACKAGE_VERSION="${DKMS_VER}"
AUTOINSTALL="yes"
PRE_BUILD="pre-build.sh \$kernelver"
MAKE[0]="make"
CLEAN="make clean"
BUILT_MODULE_NAME[0]="${DKMS_NAME}"
DEST_MODULE_LOCATION[0]="/extra"
EOF

# ----------------------------------------------------------------------- build
say "Building module (trying kernel source strategies in order)"

dkms add -m "$DKMS_NAME" -v "$DKMS_VER"

built=0
for strategy in headers srpm upstream; do
  echo "$strategy" > "$STRATEGY_FILE"
  printf '    trying source strategy: %s\n' "$strategy"
  if dkms build -m "$DKMS_NAME" -v "$DKMS_VER" --force >/dev/null 2>&1; then
    ok "built using: $strategy"
    built=1
    break
  fi
  warn "strategy '$strategy' failed"
done

if (( ! built )); then
  echo "$strategy" > "$STRATEGY_FILE"
  dkms build -m "$DKMS_NAME" -v "$DKMS_VER" --force || true
  die "build failed under every strategy. Log:
     /var/lib/dkms/${DKMS_NAME}/${DKMS_VER}/build/make.log"
fi

dkms install -m "$DKMS_NAME" -v "$DKMS_VER" --force

# SELinux is enforcing by default on EL10. A module file written outside the
# package manager can end up mislabelled, and modprobe then fails with a
# permission error that reads nothing like a labelling problem.
if command -v restorecon >/dev/null 2>&1 && [[ "$(getenforce 2>/dev/null)" != "Disabled" ]]; then
  restorecon -RF "/lib/modules/${KVER}/" 2>/dev/null || true
  ok "SELinux labels restored"
fi

depmod -a
install -d /etc/modules-load.d
printf '%s\nnf_conntrack\n' "$DKMS_NAME" > /etc/modules-load.d/awg.conf
ok "modules-load.d configured (nf_conntrack early, so its sysctls apply at boot)"

# ---------------------------------------------------------------- secure boot
say "Secure Boot"
sb_state="$(mokutil --sb-state 2>/dev/null || echo 'unsupported')"
if grep -qi 'enabled' <<<"$sb_state"; then
  if [[ ! -f "$MOK_PUB" ]]; then
    die "Secure Boot is ON but DKMS generated no signing key; the module cannot load"
  elif mokutil --test-key "$MOK_PUB" 2>/dev/null | grep -q 'already enrolled'; then
    ok "Secure Boot is ON and the DKMS signing key is enrolled"
  else
    # Nothing past this point can pass until the key is enrolled: modprobe is
    # refused with "Key was rejected by service". Stop cleanly instead of
    # dying in verification. The module is installed and signed, and the
    # purge above keeps this key once it is enrolled, so a re-run is cheap.
    warn "Secure Boot is ON — enrol the DKMS key (choose a one-time password):"
    mokutil --import "$MOK_PUB" || die "mokutil --import failed"
    say "Reboot, choose 'Enroll MOK' in MOKManager, enter that password,"
    printf '    then re-run %s to verify and apply the firewall.\n' "$0"
    exit 0
  fi
else
  ok "not enabled on this host — skipping MOK enrolment entirely"
fi

# ---------------------------------------------------------------------- verify
say "Verification"

mapfile -t kos < <(find /lib/modules/"${KVER}" -name "${DKMS_NAME}.ko*")
(( ${#kos[@]} == 1 )) || die "found ${#kos[@]} copies of ${DKMS_NAME}.ko under /lib/modules/${KVER}:
     $(printf '%s\n     ' "${kos[@]}")
     depmod prefers updates/ over extra/. Exactly one is required."
ok "exactly one module on disk: ${kos[0]}"

modprobe "$DKMS_NAME" || die "modprobe failed. dmesg | tail -30"

ondisk="$(modinfo -F version "${kos[0]}" 2>/dev/null || echo unknown)"
loaded="$(cat "/sys/module/${DKMS_NAME}/version" 2>/dev/null || echo unknown)"
tools="$(awg --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]{8}' | head -1 || echo unknown)"

printf '    on disk       : %s\n' "$ondisk"
printf '    loaded        : %s\n' "$loaded"
printf '    tools         : %s\n' "$tools"

# Disk and RAM disagreeing is unambiguous: an old module is still resident and
# the freshly built one is sitting unused. That is the case where a rebuild
# looks clean and changes nothing.
if [[ "$ondisk" != "$loaded" ]]; then
  die "the running module is NOT the one that was just built.
     An older module is still resident in the kernel. Reboot and re-run —
     a fresh boot loads what is on disk."
fi

# The authoritative test. Version strings are stamped from a header that a
# source copy without git metadata cannot populate correctly, so they are
# advisory. Whether the module actually implements the 3.1 netlink keys is
# what determines if the two ends of a tunnel obfuscate the same way, and the
# only honest way to know that is to set them and read them back.
uapi_probe() {
  local ifc="awgverify$$" conf out rc=0
  conf="$(mktemp)"
  {
    echo "[Interface]"
    echo "PrivateKey = $(awg genkey)"
    echo "S1 = 20"; echo "S2 = 20"; echo "S3 = 20"; echo "S4 = 20"
    echo "H1 = 1";  echo "H2 = 2";  echo "H3 = 3";  echo "H4 = 4"
    echo "HeaderProtectionKey = $(openssl rand -base64 32)"
    echo "ContentPaddingAddition = 0-64"
    echo "RandomTrailers = on"
    echo "DisableCookies = on"
  } > "$conf"

  ip link add dev "$ifc" type "$DKMS_NAME" 2>/dev/null || { rm -f "$conf"; return 2; }
  awg setconf "$ifc" "$conf" >/dev/null 2>&1 || rc=1
  out="$(awg showconf "$ifc" 2>/dev/null)"
  ip link del "$ifc" 2>/dev/null || true
  rm -f "$conf"

  (( rc == 0 )) || return 1
  local k
  for k in HeaderProtectionKey ContentPaddingAddition RandomTrailers; do
    grep -qi "^${k}" <<<"$out" || { printf '    dropped: %s\n' "$k"; return 1; }
  done
  return 0
}

case "$(uapi_probe; echo $?)" in
  *0) ok "3.1 UAPI probe passed — the module set and returned every 3.1 key" ;;
  *2) warn "could not create a probe interface; skipping the UAPI test" ;;
  *)  die "the module accepted a 3.1 config and discarded keys it does not
     implement. This is the real mismatch: awg setconf reports success and the
     parameters never reach the wire. Rebuild from a matching tag." ;;
esac

if [[ "$loaded" != "$tools" ]]; then
  warn "module reports '${loaded}', tools report '${tools}'.
        The UAPI probe passed, so this is a version-string stamping artefact
        rather than a real mismatch — but worth knowing when reading logs."
fi

say "Firewall and sysctls"

apply_sysctls
install_firewall

say "Done. Next: ./awg-bootstrap.sh to generate the server config."
warn "If bootstrap picks a different MTU, re-run: ./awg-install.sh --firewall-only"
