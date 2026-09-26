#!/usr/bin/env bash
# shellcheck disable=SC2317
# Trap handlers are invoked indirectly by bash and therefore look unreachable to ShellCheck.
set -euo pipefail
IFS=$'\n\t'
umask 077

fatal() {
  printf 'ores-proc-isolation[linux]: %s\n' "$*" >&2
  exit 125
}

need() {
  command -v "$1" >/dev/null 2>&1 || fatal "required helper not found in trusted PATH: $1"
}

EXE=''
NETWORK='external'
DENY_LOOPBACK='1'
DENY_PRIVATE='1'
MAX_OPEN_FILES='128'
CPU_SECONDS='300'
BEAMSCALE_HONEYPOT='0'
BEAMSCALE_TRIPWIRE_DIR='/opt/beamscale/honeypot-bin'
BEAMSCALE_TRIPWIRE_SOCKET='/run/bmscl-honeypot/tripwire.sock'
RO_PATHS=()
ENV_FILE=''
ENV_KEYS=()
ENV_VALUES=()
TARGET_ARGS=()

while (($#)); do
  case "$1" in
    --exe)
      (($# >= 2)) || fatal '--exe requires a value'
      EXE=$2
      shift 2
      ;;
    --network)
      (($# >= 2)) || fatal '--network requires a value'
      NETWORK=$2
      shift 2
      ;;
    --deny-loopback)
      DENY_LOOPBACK='1'
      shift
      ;;
    --allow-loopback)
      DENY_LOOPBACK='0'
      shift
      ;;
    --deny-private)
      DENY_PRIVATE='1'
      shift
      ;;
    --max-open-files)
      (($# >= 2)) || fatal '--max-open-files requires a value'
      MAX_OPEN_FILES=$2
      shift 2
      ;;
    --cpu-seconds)
      (($# >= 2)) || fatal '--cpu-seconds requires a value'
      CPU_SECONDS=$2
      shift 2
      ;;
    --beamscale-honeypot)
      BEAMSCALE_HONEYPOT='1'
      shift
      ;;
    --ro)
      (($# >= 2)) || fatal '--ro requires a value'
      RO_PATHS+=("$2")
      shift 2
      ;;
    --env-file)
      (($# >= 2)) || fatal '--env-file requires a value'
      ENV_FILE=$2
      shift 2
      ;;
    --)
      shift
      TARGET_ARGS=("$@")
      break
      ;;
    *)
      fatal "unknown helper option: $1"
      ;;
  esac
done

[[ -n "$EXE" ]] || fatal 'missing --exe'
[[ "$EXE" == /* ]] || fatal 'executable must be absolute'
[[ -f "$EXE" ]] || fatal "executable does not exist: $EXE"
[[ -x "$EXE" ]] || fatal "executable is not executable: $EXE"
[[ "$NETWORK" == 'external' || "$NETWORK" == 'none' ]] || fatal "unsupported network mode: $NETWORK"
[[ "$MAX_OPEN_FILES" =~ ^[0-9]+$ ]] || fatal 'max-open-files must be numeric'
[[ "$CPU_SECONDS" =~ ^[0-9]+$ ]] || fatal 'cpu-seconds must be numeric'
if [[ "$NETWORK" == 'external' ]]; then
  [[ "$DENY_LOOPBACK" == '1' ]] || fatal 'external networking requires loopback denial'
  [[ "$DENY_PRIVATE" == '1' ]] || fatal 'external networking requires private/local destination denial'
fi
if [[ -n "$ENV_FILE" ]]; then
  [[ -f "$ENV_FILE" && ! -L "$ENV_FILE" ]] || fatal 'environment file must be a real regular file'
  while IFS= read -r -d '' key && IFS= read -r -d '' value; do
    ENV_KEYS+=("$key")
    ENV_VALUES+=("$value")
  done <"$ENV_FILE"
fi
if [[ "$BEAMSCALE_HONEYPOT" == '1' ]]; then
  [[ -d "$BEAMSCALE_TRIPWIRE_DIR" ]] || fatal "BeamScale tripwire directory is unavailable: $BEAMSCALE_TRIPWIRE_DIR"
  [[ ! -L "$BEAMSCALE_TRIPWIRE_DIR" ]] || fatal 'BeamScale tripwire directory may not be a symlink'
  [[ -S "$BEAMSCALE_TRIPWIRE_SOCKET" ]] || fatal "BeamScale tripwire socket is unavailable: $BEAMSCALE_TRIPWIRE_SOCKET"
fi

need bwrap
BWRAP=$(command -v bwrap)
ulimit -n "$MAX_OPEN_FILES" || fatal 'unable to lower RLIMIT_NOFILE'
ulimit -t "$CPU_SECONDS" || fatal 'unable to lower RLIMIT_CPU'

RESOLV_FILE=''
STATUS_FIFO=''
GATE_FIFO=''
READY_FIFO=''
INFO_FIFO=''
USERNS_GATE_FIFO=''
IPC_DIR=''
SLIRP_PID=''
BWRAP_PID=''

cleanup() {
  local rc=$?
  if [[ -n "$SLIRP_PID" ]]; then
    kill "$SLIRP_PID" >/dev/null 2>&1 || true
    wait "$SLIRP_PID" >/dev/null 2>&1 || true
  fi
  if [[ -n "$BWRAP_PID" ]]; then
    kill "$BWRAP_PID" >/dev/null 2>&1 || true
    wait "$BWRAP_PID" >/dev/null 2>&1 || true
  fi
  [[ -n "$RESOLV_FILE" ]] && rm -f -- "$RESOLV_FILE"
  [[ -n "$IPC_DIR" ]] && rm -rf -- "$IPC_DIR"
  exit "$rc"
}
trap cleanup EXIT HUP INT TERM

RESOLV_FILE=$(mktemp "${TMPDIR:-/tmp}/ores-pi-resolv.XXXXXX")
printf 'nameserver 10.0.2.3\noptions attempts:1 timeout:2\n' >"$RESOLV_FILE"
chmod 0600 "$RESOLV_FILE"

TARGET_PATH='/nonexistent'
if [[ "$BEAMSCALE_HONEYPOT" == '1' ]]; then
  TARGET_PATH=$BEAMSCALE_TRIPWIRE_DIR
fi

# Bubblewrap creates exactly one unprivileged user namespace. For external
# networking the host supervisor pauses that namespace before initialization,
# installs a one-ID uid/gid map, disables any further user namespaces inside
# it, and then lets Bubblewrap finish the remaining namespace setup. This keeps
# the network namespace owned by the same user namespace that the trusted host
# supervisor can enter on Ubuntu 24.04, without relying on newer nsenter
# --user-parent support. The tenant still receives no capabilities.
BWRAP_ARGS=(
  --die-with-parent
  --new-session
  --unshare-user
  --uid 0
  --gid 0
  --unshare-ipc
  --unshare-pid
  --unshare-net
  --unshare-uts
  --unshare-cgroup
  --cap-drop ALL
  --hostname ores-sandbox
  --clearenv
  --setenv PATH "$TARGET_PATH"
  --setenv HOME /nonexistent
  --setenv TMPDIR /tmp
  --setenv LANG C.UTF-8
  --proc /proc
  --dev /dev
  --tmpfs /tmp
  --ro-bind "$EXE" "$EXE"
  --ro-bind "$RESOLV_FILE" /etc/resolv.conf
)

for runtime_path in /lib /lib64 /usr/lib /usr/lib64 /etc/ssl/certs /usr/share/ca-certificates; do
  if [[ -e "$runtime_path" ]]; then
    BWRAP_ARGS+=(--ro-bind "$runtime_path" "$runtime_path")
  fi
done
if [[ -f /etc/nsswitch.conf ]]; then
  BWRAP_ARGS+=(--ro-bind /etc/nsswitch.conf /etc/nsswitch.conf)
fi

if [[ "$BEAMSCALE_HONEYPOT" == '1' ]]; then
  BWRAP_ARGS+=(
    --dir /opt
    --dir /opt/beamscale
    --ro-bind "$BEAMSCALE_TRIPWIRE_DIR" "$BEAMSCALE_TRIPWIRE_DIR"
    --dir /run
    --dir /run/bmscl-honeypot
    --ro-bind "$BEAMSCALE_TRIPWIRE_SOCKET" "$BEAMSCALE_TRIPWIRE_SOCKET"
  )
fi

for ro_path in "${RO_PATHS[@]}"; do
  [[ "$ro_path" == /* ]] || fatal "read-only path must be absolute: $ro_path"
  [[ "$ro_path" != / ]] || fatal 'refusing to expose host root'
  if [[ "$BEAMSCALE_HONEYPOT" == '1' ]]; then
    case "$ro_path" in
      /bin|/sbin|/usr/bin|/usr/sbin|/run|/opt)
        fatal "BeamScale honeypot mode refuses broad utility/runtime mount: $ro_path"
        ;;
    esac
  fi
  [[ -e "$ro_path" ]] || fatal "read-only path does not exist: $ro_path"
  BWRAP_ARGS+=(--ro-bind "$ro_path" "$ro_path")
done

for ((i = 0; i < ${#ENV_KEYS[@]}; i++)); do
  BWRAP_ARGS+=(--setenv "${ENV_KEYS[$i]}" "${ENV_VALUES[$i]}")
done

# The strict BeamScale profile owns PATH. Re-assert it after generic reviewed
# environment injection so a policy PATH value cannot turn a canary-only PATH
# back into a host utility search path.
if [[ "$BEAMSCALE_HONEYPOT" == '1' ]]; then
  BWRAP_ARGS+=(--setenv PATH "$BEAMSCALE_TRIPWIRE_DIR")
fi

if [[ "$NETWORK" == 'none' ]]; then
  # Bubblewrap's built-in disable-userns path deliberately creates a nested
  # user namespace, which is fine when no host-side network supervisor must
  # enter the owning namespace.
  BWRAP_ARGS+=(--disable-userns)
  trap - EXIT HUP INT TERM
  exec "$BWRAP" "${BWRAP_ARGS[@]}" -- "$EXE" "${TARGET_ARGS[@]}"
fi

need slirp4netns
need nsenter
need ip
need iptables
need ip6tables
need id
SLIRP=$(command -v slirp4netns)
NSENTER=$(command -v nsenter)
IP=$(command -v ip)
IPTABLES=$(command -v iptables)
IP6TABLES=$(command -v ip6tables)
HOST_UID=$(id -u)
HOST_GID=$(id -g)

HOST_IPV4=()
while IFS=' ' read -r _ _ family cidr _; do
  [[ "$family" == 'inet' ]] || continue
  address=${cidr%%/*}
  [[ -n "$address" ]] && HOST_IPV4+=("$address")
done < <("$IP" -o -4 addr show scope global)

HOST_IPV6=()
while IFS=' ' read -r _ _ family cidr _; do
  [[ "$family" == 'inet6' ]] || continue
  address=${cidr%%/*}
  [[ -n "$address" ]] && HOST_IPV6+=("$address")
done < <("$IP" -o -6 addr show scope global)

IPC_DIR=$(mktemp -d "${TMPDIR:-/tmp}/ores-pi-ipc.XXXXXX")
chmod 0700 "$IPC_DIR"
STATUS_FIFO="$IPC_DIR/status"
GATE_FIFO="$IPC_DIR/gate"
READY_FIFO="$IPC_DIR/ready"
INFO_FIFO="$IPC_DIR/info"
USERNS_GATE_FIFO="$IPC_DIR/userns-gate"
mkfifo -m 0600 "$STATUS_FIFO" "$GATE_FIFO" "$READY_FIFO" "$INFO_FIFO" "$USERNS_GATE_FIFO"
exec 8<>"$STATUS_FIFO"
exec 9<>"$GATE_FIFO"
exec 10<>"$INFO_FIFO"
exec 11<>"$USERNS_GATE_FIFO"

# Hold the first user namespace before Bubblewrap initializes it. The host
# process owns that child namespace, so it can install the exact one-ID map,
# enter it with ordinary Ubuntu 24.04 nsenter, and set the namespaced userns
# limit to zero. Bubblewrap then verifies the limit via --assert-userns-disabled.
"$BWRAP" \
  --info-fd 5 \
  --userns-block-fd 6 \
  --assert-userns-disabled \
  --json-status-fd 3 \
  --block-fd 4 \
  "${BWRAP_ARGS[@]}" \
  -- "$EXE" "${TARGET_ARGS[@]}" \
  3>&8 4<&9 5>&10 6<&11 &
BWRAP_PID=$!

setup_pid=''
info_line=''
while IFS= read -r info_line <&10; do
  candidate=$(printf '%s\n' "$info_line" | sed -n 's/.*"child-pid"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p')
  if [[ -n "$candidate" ]]; then
    setup_pid=$candidate
    break
  fi
done
if [[ -z "$setup_pid" ]]; then
  wait "$BWRAP_PID" || true
  BWRAP_PID=''
  fatal 'bubblewrap exited before reporting the user namespace setup PID'
fi
[[ -e "/proc/$setup_pid/ns/user" ]] || fatal 'bubblewrap user namespace disappeared before mapping'

if [[ -e "/proc/$setup_pid/setgroups" ]]; then
  printf 'deny\n' >"/proc/$setup_pid/setgroups" \
    || fatal 'unable to disable setgroups in sandbox user namespace'
fi
printf '0 %s 1\n' "$HOST_UID" >"/proc/$setup_pid/uid_map" \
  || fatal 'unable to install sandbox uid map'
printf '0 %s 1\n' "$HOST_GID" >"/proc/$setup_pid/gid_map" \
  || fatal 'unable to install sandbox gid map'

"$NSENTER" -t "$setup_pid" -U --preserve-credentials -- "$BASH" -euc \
  'printf "0\n" > /proc/sys/user/max_user_namespaces' \
  || fatal 'unable to disable nested user namespaces in sandbox user namespace'
printf '1' >&11
exec 10>&-
exec 11>&-

status_line=''
if ! IFS= read -r status_line <&8; then
  wait "$BWRAP_PID" || true
  BWRAP_PID=''
  fatal 'bubblewrap exited before reporting the sandbox child PID'
fi
child_pid=$(printf '%s\n' "$status_line" | sed -n 's/.*"child-pid"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p')
[[ -n "$child_pid" ]] || fatal "unable to parse bubblewrap child PID from: $status_line"
NETNS_PATH="/proc/$child_pid/ns/net"
[[ -e "$NETNS_PATH" ]] || fatal 'sandbox network namespace disappeared before network setup'

# The network namespace is owned by the same first-level user namespace as the
# tenant. Enter that descendant user namespace first, gaining capabilities only
# there (never in the host initial userns), then let slirp configure the netns.
"$NSENTER" -t "$child_pid" -U --preserve-credentials -- \
  "$SLIRP" \
    --configure \
    --mtu=65520 \
    --disable-host-loopback \
    --enable-seccomp \
    --netns-type=path \
    --ready-fd=6 \
    "$NETNS_PATH" tap0 \
  6>"$READY_FIFO" &
SLIRP_PID=$!

ready=''
if ! IFS= read -r -n 1 ready <"$READY_FIFO"; then
  fatal 'slirp4netns exited before network setup completed'
fi
[[ "$ready" == '1' ]] || fatal 'slirp4netns did not acknowledge network readiness'

# Enter the sandbox user namespace before the network namespace. Namespace-root
# is scoped to this descendant userns and is not host root. The tenant executes
# with the full capability set dropped and cannot create another user namespace.
ns_net() {
  "$NSENTER" -t "$child_pid" -U --preserve-credentials -n -- "$@"
}

ns_net "$IP" link set lo down \
  || fatal 'unable to disable namespace loopback'

ns_iptables() {
  ns_net "$IPTABLES" "$@"
}

ns_ip6tables() {
  ns_net "$IP6TABLES" "$@"
}

ns_iptables -I OUTPUT 1 -d 10.0.2.3/32 -p udp --dport 53 -j ACCEPT
ns_iptables -I OUTPUT 2 -d 10.0.2.3/32 -p tcp --dport 53 -j ACCEPT
ns_iptables -A OUTPUT -d 0.0.0.0/8 -j REJECT
ns_iptables -A OUTPUT -d 127.0.0.0/8 -j REJECT
ns_iptables -A OUTPUT -d 10.0.2.2/32 -j REJECT
ns_iptables -A OUTPUT -d 169.254.0.0/16 -j REJECT
ns_iptables -A OUTPUT -d 10.0.0.0/8 -j REJECT
ns_iptables -A OUTPUT -d 172.16.0.0/12 -j REJECT
ns_iptables -A OUTPUT -d 192.168.0.0/16 -j REJECT
ns_iptables -A OUTPUT -d 100.64.0.0/10 -j REJECT
ns_iptables -A OUTPUT -d 224.0.0.0/4 -j REJECT
ns_iptables -A OUTPUT -d 240.0.0.0/4 -j REJECT
for host_ip in "${HOST_IPV4[@]}"; do
  ns_iptables -A OUTPUT -d "$host_ip/32" -j REJECT
done

ns_ip6tables -A OUTPUT -d ::1/128 -j REJECT
ns_ip6tables -A OUTPUT -d fe80::/10 -j REJECT
ns_ip6tables -A OUTPUT -d fc00::/7 -j REJECT
ns_ip6tables -A OUTPUT -d ff00::/8 -j REJECT
for host_ip in "${HOST_IPV6[@]}"; do
  ns_ip6tables -A OUTPUT -d "$host_ip/128" -j REJECT
done

printf '1' >&9

# The target and the user-mode network helper are one runtime unit. If Slirp
# dies while Bubblewrap still owns a live tenant, continuing would silently
# weaken a required dependency. Wait for whichever process exits first. If the
# helper exits first and the tenant is still live, terminate the tenant and
# return a supervisor failure. Normal tenant exit remains authoritative.
set +e
finished_pid=''
wait -n -p finished_pid "$BWRAP_PID" "$SLIRP_PID"
first_rc=$?
set -e

if [[ "$finished_pid" == "$SLIRP_PID" ]]; then
  SLIRP_PID=''
  bwrap_state=''
  if [[ -r "/proc/$BWRAP_PID/stat" ]]; then
    bwrap_state=$(awk '{print $3}' "/proc/$BWRAP_PID/stat" 2>/dev/null || true)
  fi
  if [[ -n "$bwrap_state" && "$bwrap_state" != 'Z' ]]; then
    printf 'ores-proc-isolation[linux]: network helper exited while tenant was still running\n' >&2
    kill "$BWRAP_PID" >/dev/null 2>&1 || true
    set +e
    wait "$BWRAP_PID" >/dev/null 2>&1
    set -e
    BWRAP_PID=''
    rc=125
  else
    set +e
    wait "$BWRAP_PID"
    rc=$?
    set -e
    BWRAP_PID=''
  fi
else
  rc=$first_rc
  BWRAP_PID=''
fi

if [[ -n "$SLIRP_PID" ]]; then
  kill "$SLIRP_PID" >/dev/null 2>&1 || true
  wait "$SLIRP_PID" >/dev/null 2>&1 || true
  SLIRP_PID=''
fi
trap - EXIT HUP INT TERM
exec 8>&-
exec 9>&-
rm -f -- "$RESOLV_FILE"
RESOLV_FILE=''
rm -rf -- "$IPC_DIR"
IPC_DIR=''
exit "$rc"
