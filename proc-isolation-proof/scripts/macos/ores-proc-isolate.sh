#!/usr/bin/env bash
# shellcheck disable=SC2317
# Trap handlers are invoked indirectly by bash and therefore look unreachable to ShellCheck.
set -euo pipefail
IFS=$'\n\t'
umask 077

EXE=''
NETWORK='external'
DENY_LOOPBACK='1'
DENY_PRIVATE='0'
MAX_OPEN_FILES='128'
CPU_SECONDS='300'
RO_PATHS=()
ENV_KEYS=()
ENV_VALUES=()
TARGET_ARGS=()

fatal() {
  printf 'ores-proc-isolation[macos]: %s\n' "$*" >&2
  exit 125
}

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
    --ro)
      (($# >= 2)) || fatal '--ro requires a value'
      RO_PATHS+=("$2")
      shift 2
      ;;
    --env)
      (($# >= 3)) || fatal '--env requires KEY VALUE'
      ENV_KEYS+=("$2")
      ENV_VALUES+=("$3")
      shift 3
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
[[ "$DENY_LOOPBACK" == '1' ]] || fatal 'macOS strict external mode refuses host loopback access'
[[ "$DENY_PRIVATE" == '0' ]] || fatal 'macOS Seatbelt cannot express RFC1918/CIDR egress denial; refusing to weaken requested policy'
[[ -x /usr/bin/sandbox-exec ]] || fatal '/usr/bin/sandbox-exec is unavailable'
[[ -x /usr/bin/env ]] || fatal '/usr/bin/env is unavailable'

ulimit -n "$MAX_OPEN_FILES" || fatal 'unable to lower RLIMIT_NOFILE'
ulimit -t "$CPU_SECONDS" || fatal 'unable to lower RLIMIT_CPU'

PROFILE=$(/usr/bin/mktemp "${TMPDIR:-/tmp}/ores-pi-seatbelt.XXXXXX")
cleanup() {
  local rc=$?
  /bin/rm -f -- "$PROFILE"
  exit "$rc"
}
trap cleanup EXIT HUP INT TERM

cat >"$PROFILE" <<'SBPL'
(version 1)

; Closed by default. Children inherit this sandbox and cannot opt themselves out.
(deny default)

(allow process-exec)
(allow process-fork)
(allow signal (target same-sandbox))
(allow process-info* (target same-sandbox))

; Minimal device/stdio surface.
(allow file-read* file-test-existence
  (literal "/dev/random")
  (literal "/dev/urandom")
  (literal "/dev/null")
  (literal "/dev/zero"))
(allow file-write-data (literal "/dev/null") (literal "/dev/zero"))
(allow file-read-data file-test-existence file-write-data (subpath "/dev/fd"))
(allow file-read* (regex "^/dev/fd/(0|1|2)$"))
(allow file-write* (regex "^/dev/fd/(1|2)$"))
(allow file-read* file-write* (literal "/dev/tty"))
(allow pseudo-tty)
(allow file-read* file-write* file-ioctl (literal "/dev/ptmx"))
(allow file-read* file-write* file-ioctl (regex "^/dev/ttys[0-9]+$"))

; The executable itself and only its ancestors for path traversal.
(allow file-read* file-map-executable file-test-existence
  (literal (param "EXECUTABLE")))
(allow file-read-metadata file-test-existence
  (path-ancestors (param "EXECUTABLE")))

; Loader/framework runtime. These are system files, not user/project data.
(allow file-map-executable
  (subpath "/Library/Apple/System/Library/Frameworks")
  (subpath "/Library/Apple/System/Library/PrivateFrameworks")
  (subpath "/Library/Apple/usr/lib")
  (subpath "/System/Library/Extensions")
  (subpath "/System/Library/Frameworks")
  (subpath "/System/Library/PrivateFrameworks")
  (subpath "/System/Library/SubFrameworks")
  (subpath "/usr/lib"))
(allow file-read* file-test-existence
  (subpath "/Library/Apple/System/Library/Frameworks")
  (subpath "/Library/Apple/System/Library/PrivateFrameworks")
  (subpath "/Library/Apple/usr/lib")
  (subpath "/System/Library/Frameworks")
  (subpath "/System/Library/PrivateFrameworks")
  (subpath "/System/Library/SubFrameworks")
  (subpath "/usr/lib")
  (subpath "/usr/share"))
(allow file-read* file-test-existence (literal "/"))

; CPU/runtime discovery required by common libc/runtimes.
(allow sysctl-read
  (sysctl-name "hw.activecpu")
  (sysctl-name "hw.byteorder")
  (sysctl-name "hw.cachelinesize_compat")
  (sysctl-name "hw.cpufamily")
  (sysctl-name "hw.cputype")
  (sysctl-name "hw.logicalcpu")
  (sysctl-name "hw.logicalcpu_max")
  (sysctl-name "hw.machine")
  (sysctl-name "hw.memsize")
  (sysctl-name "hw.model")
  (sysctl-name "hw.ncpu")
  (sysctl-name "hw.pagesize")
  (sysctl-name "hw.physicalcpu")
  (sysctl-name "hw.physicalcpu_max")
  (sysctl-name-prefix "hw.optional.arm.")
  (sysctl-name-prefix "hw.optional.armv8_")
  (sysctl-name "kern.argmax")
  (sysctl-name "kern.hostname")
  (sysctl-name "kern.maxfilesperproc")
  (sysctl-name "kern.maxproc")
  (sysctl-name "kern.osproductversion")
  (sysctl-name "kern.osrelease")
  (sysctl-name "kern.ostype")
  (sysctl-name "kern.osversion")
  (sysctl-name "kern.version")
  (sysctl-name "vm.loadavg"))

(allow iokit-open (iokit-registry-entry-class "RootDomainUserClient"))
(allow system-mac-syscall (mac-policy-name "vnguard"))

; Identity, DNS, routing, and TLS trust services. No arbitrary local unix socket
; access is granted.
(allow mach-lookup
  (global-name "com.apple.system.opendirectoryd.libinfo")
  (global-name "com.apple.system.opendirectoryd.membership")
  (global-name "com.apple.bsd.dirhelper")
  (global-name "com.apple.SecurityServer")
  (global-name "com.apple.networkd")
  (global-name "com.apple.ocspd")
  (global-name "com.apple.trustd")
  (global-name "com.apple.trustd.agent")
  (global-name "com.apple.SystemConfiguration.DNSConfiguration")
  (global-name "com.apple.SystemConfiguration.configd")
  (global-name "com.apple.PowerManagement.control"))
(allow system-socket
  (require-all
    (socket-domain AF_SYSTEM)
    (socket-protocol 2)))
SBPL

SANDBOX_ARGS=(-D "EXECUTABLE=$EXE")

for ((i = 0; i < ${#RO_PATHS[@]}; i++)); do
  ro_path=${RO_PATHS[$i]}
  [[ "$ro_path" == /* ]] || fatal "read-only path must be absolute: $ro_path"
  [[ "$ro_path" != / ]] || fatal 'refusing to expose host root'
  [[ -e "$ro_path" ]] || fatal "read-only path does not exist: $ro_path"
  param="RO_PATH_$i"
  SANDBOX_ARGS+=(-D "$param=$ro_path")
  cat >>"$PROFILE" <<SBPL
(allow file-read* file-test-existence
  (literal (param "$param"))
  (subpath (param "$param")))
(allow file-read-metadata file-test-existence
  (path-ancestors (param "$param")))
SBPL
done

if [[ "$NETWORK" == 'external' ]]; then
  cat >>"$PROFILE" <<'SBPL'
; IP egress is allowed, but host/self loopback is explicitly denied after the
; broad IP rule. Inbound/bind and unix-domain sockets remain denied by default.
(allow network-outbound (remote ip "*:*"))
(deny network-outbound (remote ip "localhost:*"))
SBPL
fi

ENV_ARGS=(
  PATH=/nonexistent
  HOME=/nonexistent
  TMPDIR=/nonexistent
  LANG=C
)
for ((i = 0; i < ${#ENV_KEYS[@]}; i++)); do
  ENV_ARGS+=("${ENV_KEYS[$i]}=${ENV_VALUES[$i]}")
done

TARGET_COMMAND=("$EXE")
if ((${#TARGET_ARGS[@]})); then
  TARGET_COMMAND+=("${TARGET_ARGS[@]}")
fi

cd /
set +e
/usr/bin/env -i "${ENV_ARGS[@]}" \
  /usr/bin/sandbox-exec "${SANDBOX_ARGS[@]}" -f "$PROFILE" -- \
  "${TARGET_COMMAND[@]}"
rc=$?
set -e
trap - EXIT HUP INT TERM
/bin/rm -f -- "$PROFILE"
exit "$rc"
