#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

: "${P2P_STRESS_N:=12}"
: "${P2P_STRESS_CHURN_PCT:=30}"
: "${P2P_STRESS_SEED:=1337}"
: "${P2P_STRESS_WARMUP_SEC:=20}"
: "${P2P_STRESS_RECOVERY_SEC:=20}"
: "${P2P_STRESS_PARTITION_SEC:=12}"
: "${P2P_PARTITION_WARMUP_TIMEOUT_SEC:=60}"
: "${P2P_STRESS_MIN_OUTBOUND:=1}"
: "${P2P_STRESS_MIN_PEERTABLE:=3}"
: "${P2P_STRESS_PEERTABLE_MAX:=256}"
: "${P2P_STRESS_SUBNET_MAX:=16}"
: "${P2P_STRESS_PEX_INSERT_MAX:=32}"
: "${P2P_STRESS_PEER_EXCHANGE_MAX:=8}"
: "${P2P_STRESS_OUTBOUND_TARGET:=3}"
: "${P2P_STRESS_OUTBOUND_EXPLORE:=1}"
: "${P2P_STRESS_PEX_INTERVAL_SEC:=2}"
: "${P2P_STRESS_CONNMAN_TICK_MS:=300}"
: "${P2P_STRESS_DIAL_TIMEOUT_MS:=1000}"
: "${P2P_STRESS_MAX_CONNS:=512}"
: "${P2P_STRESS_MAX_STREAMS_PER_CONN:=64}"
: "${P2P_STRESS_DISABLE_LIMITER:=1}"
: "${P2P_STRESS_LIMITER_MAX_CONNS_PER_IP:=1024}"
: "${P2P_STRESS_WEB4_DEBUG:=1}"
: "${P2P_STRESS_POISON_PEERS:=120}"
: "${P2P_STRESS_TIMEOUT_SEC:=240}"
: "${P2P_STRESS_SCENARIOS:=all}"
: "${P2P_STRESS_PPROF:=0}"
: "${P2P_STRESS_PPROF_ADDR:=127.0.0.1:6060}"
: "${P2P_STRESS_KEEPALIVE:=0}"
RTT_METRICS_ENABLED=0
if [[ "${WEB4_RTT_METRICS:-}" == "1" ]]; then
  RTT_METRICS_ENABLED=1
fi
WEB4_METRICS_DISK_WRITE_SEC_IS_SET=0
if [[ "${WEB4_METRICS_DISK_WRITE_SEC+x}" == "x" ]]; then
  WEB4_METRICS_DISK_WRITE_SEC_IS_SET=1
fi

START_TS="$(date +%s)"

pass() { echo "PASS: $1"; }
warn() { echo "WARN: $1"; }
skip() { echo "SKIP: $1"; }
fail() {
  echo "FAIL: $1"
  dump_fail_logs
  exit 1
}

TMPROOT="$(mktemp -d)"
TMPWORK="${TMPROOT}/work"
mkdir -p "${TMPWORK}"

WEB4_BIN="${WEB4_BIN:-${TMPWORK}/web4}"
WEB4_NODE_BIN="${WEB4_NODE_BIN:-${TMPWORK}/web4-node}"

if [[ ! -x "${WEB4_BIN}" ]]; then
  go build -o "${WEB4_BIN}" ./cmd/web4
fi
if [[ ! -x "${WEB4_NODE_BIN}" ]]; then
  go build -o "${WEB4_NODE_BIN}" ./cmd/web4-node
fi

declare -a NODE_HOME=()
declare -a NODE_ADDR=()
declare -a NODE_LOG=()
declare -a NODE_PID=()
declare -a NODE_ID=()
declare -a NODE_ALIVE=()
declare -a NODE_NS=()
declare -a CHURN_OK=()
declare -A USED_PORTS=()

TC_APPLIED=0
NETNS_READY=0
PARTITION_SKIP_REASON=""
NS_G1=""
NS_G2=""
NS_V1=""
NS_V2=""
NS_G1_IP="10.77.1.1"
NS_G2_IP="10.77.1.2"
DEVTLS_CERT_IPS="127.0.0.1"
BR_NAME="br-web4"
NETNS_PREFIX="web4stressns"
HOST_VETH_PREFIX="w4h"
NS_IFACE_PREFIX="w4n"
declare -a PART_NS_LIST=()
declare -a PART_NS_IP=()
declare -a PART_NS_GROUP=()
IPTABLES_PARTITION_APPLIED=0
SHARED_CA_PATH=""
SHARED_CA_CERT_PATH=""
SHARED_CA_KEY_PATH=""
KEEPALIVE_STOP=0

cleanup_tc() {
  :
}

cleanup_netns() {
  if [[ "${NETNS_READY}" -ne 1 && "${#PART_NS_LIST[@]}" -eq 0 ]]; then
    return 0
  fi
  local ns
  for ns in "${PART_NS_LIST[@]:-}"; do
    ip netns del "${ns}" >/dev/null 2>&1 || true
  done
  local i
  for i in $(seq 0 "${P2P_STRESS_N}"); do
    ip link del "${HOST_VETH_PREFIX}${i}" >/dev/null 2>&1 || true
  done
  ip link del "${BR_NAME}" >/dev/null 2>&1 || true
  PART_NS_LIST=()
  PART_NS_IP=()
  PART_NS_GROUP=()
  NS_G1=""
  NS_G2=""
  NS_V1=""
  NS_V2=""
  NETNS_READY=0
  IPTABLES_PARTITION_APPLIED=0
}

cleanup() {
  set +e
  clear_partition_iptables || true
  for pid in "${NODE_PID[@]:-}"; do
    if [[ -n "${pid:-}" ]]; then
      kill "${pid}" >/dev/null 2>&1 || true
      wait "${pid}" >/dev/null 2>&1 || true
    fi
  done
  wait >/dev/null 2>&1 || true
  cleanup_netns
  if [[ "${P2P_STRESS_KEEP_TMP:-0}" == "1" ]]; then
    echo "P2P_STRESS_KEEP_TMP=1 leaving ${TMPROOT}"
  else
    rm -rf "${TMPROOT}"
  fi
}
trap cleanup EXIT

keepalive_wait_if_enabled() {
  if [[ "${P2P_STRESS_PPROF}" != "1" || "${P2P_STRESS_KEEPALIVE}" != "1" ]]; then
    return 0
  fi
  if [[ -n "${NODE_NS[0]:-}" ]]; then
    echo "KEEPALIVE: node[0] running in netns=${NODE_NS[0]}, press Enter to stop"
    echo "KEEPALIVE: collect pprof with:"
    echo "  sudo ip netns exec ${NODE_NS[0]} go tool pprof \"http://${P2P_STRESS_PPROF_ADDR}/debug/pprof/profile?seconds=30\""
  else
    echo "KEEPALIVE: node[0] running, press Enter to stop"
  fi
  KEEPALIVE_STOP=0
  trap 'KEEPALIVE_STOP=1' INT TERM
  if [[ -t 0 ]]; then
    read -r || true
    KEEPALIVE_STOP=1
  fi
  while (( KEEPALIVE_STOP == 0 )); do
    sleep 1
  done
  trap cleanup EXIT
}

wipe_stale_partition_state() {
  if ! command -v ip >/dev/null 2>&1; then
    return 0
  fi
  local stale_ns
  stale_ns="$(ip netns list 2>/dev/null | awk '{print $1}' | grep -E "^${NETNS_PREFIX}_" || true)"
  if [[ -n "${stale_ns}" ]]; then
    echo "INFO: wiping stale netns artifacts"
    while IFS= read -r ns; do
      [[ -z "${ns}" ]] && continue
      ip netns del "${ns}" >/dev/null 2>&1 || true
    done <<< "${stale_ns}"
  fi
  ip link del "${BR_NAME}" >/dev/null 2>&1 || true
  local i
  for i in $(seq 0 "${P2P_STRESS_N}"); do
    ip link del "${HOST_VETH_PREFIX}${i}" >/dev/null 2>&1 || true
  done
}

setup_partition_netns() {
  if ! command -v ip >/dev/null 2>&1; then
    PARTITION_SKIP_REASON="partition (iproute2 not found)"
    return 1
  fi
  if ! command -v iptables >/dev/null 2>&1; then
    PARTITION_SKIP_REASON="partition (iptables not found)"
    return 1
  fi
  if [[ "$(id -u)" != "0" ]]; then
    PARTITION_SKIP_REASON="partition (root required for netns/iptables)"
    return 1
  fi

  wipe_stale_partition_state

  ip link add "${BR_NAME}" type bridge >/dev/null 2>&1 || {
    PARTITION_SKIP_REASON="partition (failed to create bridge ${BR_NAME})"
    return 1
  }
  ip link set "${BR_NAME}" up >/dev/null 2>&1 || {
    PARTITION_SKIP_REASON="partition (failed to bring bridge up)"
    cleanup_netns
    return 1
  }

  local mid=$(( P2P_STRESS_N / 2 ))
  local idx
  local ns
  local host_if
  local ns_if
  local group
  local ip_addr
  local g1_count=1
  local g2_count=1

  PART_NS_LIST=()
  PART_NS_IP=()
  PART_NS_GROUP=()
  PART_NS_LIST[0]="${NETNS_PREFIX}_0"
  PART_NS_GROUP[0]="A"
  PART_NS_IP[0]="10.10.0.1"
  for idx in $(seq 1 "${P2P_STRESS_N}"); do
    if (( idx <= mid )); then
      g1_count=$((g1_count + 1))
      PART_NS_GROUP[$idx]="A"
      PART_NS_IP[$idx]="10.10.0.${g1_count}"
    else
      g2_count=$((g2_count + 1))
      PART_NS_GROUP[$idx]="B"
      PART_NS_IP[$idx]="10.10.1.${g2_count}"
    fi
    PART_NS_LIST[$idx]="${NETNS_PREFIX}_${idx}"
  done

  for idx in $(seq 0 "${P2P_STRESS_N}"); do
    ns="${PART_NS_LIST[$idx]}"
    ip_addr="${PART_NS_IP[$idx]}"
    host_if="${HOST_VETH_PREFIX}${idx}"
    ns_if="${NS_IFACE_PREFIX}${idx}"
    group="${PART_NS_GROUP[$idx]}"

    ip netns add "${ns}" >/dev/null 2>&1 || {
      PARTITION_SKIP_REASON="partition (failed to create netns ${ns})"
      cleanup_netns
      return 1
    }
    ip link add "${host_if}" type veth peer name "${ns_if}" >/dev/null 2>&1 || {
      PARTITION_SKIP_REASON="partition (failed to create veth for ${ns})"
      cleanup_netns
      return 1
    }
    ip link set "${ns_if}" netns "${ns}" >/dev/null 2>&1 || {
      PARTITION_SKIP_REASON="partition (failed to move veth into ${ns})"
      cleanup_netns
      return 1
    }
    ip link set "${host_if}" master "${BR_NAME}" >/dev/null 2>&1 || {
      PARTITION_SKIP_REASON="partition (failed to attach ${host_if} to bridge)"
      cleanup_netns
      return 1
    }
    ip link set "${host_if}" up >/dev/null 2>&1 || {
      PARTITION_SKIP_REASON="partition (failed to bring up ${host_if})"
      cleanup_netns
      return 1
    }
    ip netns exec "${ns}" ip link set lo up >/dev/null 2>&1 || {
      PARTITION_SKIP_REASON="partition (failed to bring up lo in ${ns})"
      cleanup_netns
      return 1
    }
    ip netns exec "${ns}" ip link set "${ns_if}" up >/dev/null 2>&1 || {
      PARTITION_SKIP_REASON="partition (failed to bring up ${ns_if} in ${ns})"
      cleanup_netns
      return 1
    }
    ip netns exec "${ns}" ip addr add "${ip_addr}/24" dev "${ns_if}" >/dev/null 2>&1 || {
      PARTITION_SKIP_REASON="partition (failed to assign ${ip_addr} in ${ns})"
      cleanup_netns
      return 1
    }
    if [[ "${group}" == "A" ]]; then
      ip netns exec "${ns}" ip route replace 10.10.1.0/24 dev "${ns_if}" >/dev/null 2>&1 || true
    else
      ip netns exec "${ns}" ip route replace 10.10.0.0/24 dev "${ns_if}" >/dev/null 2>&1 || true
    fi
  done

  NS_G1="${PART_NS_LIST[0]}"
  NS_G2="${PART_NS_LIST[$((mid+1))]:-${PART_NS_LIST[0]}}"
  NS_G1_IP="${PART_NS_IP[0]}"
  NS_G2_IP="${PART_NS_IP[$((mid+1))]:-${PART_NS_IP[0]}}"
  NETNS_READY=1
  DEVTLS_CERT_IPS="$(IFS=,; echo "127.0.0.1,${PART_NS_IP[*]}")"
  return 0
}

clear_partition_iptables() {
  if [[ "${NETNS_READY}" -ne 1 ]]; then
    IPTABLES_PARTITION_APPLIED=0
    return 0
  fi
  local idx
  local ns
  local group
  for idx in $(seq 0 "${P2P_STRESS_N}"); do
    ns="${PART_NS_LIST[$idx]:-}"
    group="${PART_NS_GROUP[$idx]:-}"
    [[ -z "${ns}" || -z "${group}" ]] && continue
    if [[ "${group}" == "A" ]]; then
      ip netns exec "${ns}" iptables -D OUTPUT -d 10.10.1.0/24 -j DROP >/dev/null 2>&1 || true
      ip netns exec "${ns}" iptables -D INPUT -s 10.10.1.0/24 -j DROP >/dev/null 2>&1 || true
    else
      ip netns exec "${ns}" iptables -D OUTPUT -d 10.10.0.0/24 -j DROP >/dev/null 2>&1 || true
      ip netns exec "${ns}" iptables -D INPUT -s 10.10.0.0/24 -j DROP >/dev/null 2>&1 || true
    fi
  done
  IPTABLES_PARTITION_APPLIED=0
}

apply_partition_iptables() {
  if [[ "${NETNS_READY}" -ne 1 ]]; then
    return 1
  fi
  clear_partition_iptables || true
  local idx
  local ns
  local group
  for idx in $(seq 0 "${P2P_STRESS_N}"); do
    ns="${PART_NS_LIST[$idx]:-}"
    group="${PART_NS_GROUP[$idx]:-}"
    [[ -z "${ns}" || -z "${group}" ]] && continue
    if [[ "${group}" == "A" ]]; then
      ip netns exec "${ns}" iptables -I OUTPUT -d 10.10.1.0/24 -j DROP >/dev/null 2>&1 || return 1
      ip netns exec "${ns}" iptables -I INPUT -s 10.10.1.0/24 -j DROP >/dev/null 2>&1 || return 1
    else
      ip netns exec "${ns}" iptables -I OUTPUT -d 10.10.0.0/24 -j DROP >/dev/null 2>&1 || return 1
      ip netns exec "${ns}" iptables -I INPUT -s 10.10.0.0/24 -j DROP >/dev/null 2>&1 || return 1
    fi
  done
  IPTABLES_PARTITION_APPLIED=1
  return 0
}

pick_port() {
  python3 - <<'PY' 2>/dev/null || true
import socket
s=socket.socket()
s.bind(("127.0.0.1",0))
print(s.getsockname()[1])
s.close()
PY
}

port_available() {
  local port="$1"
  python3 - "$port" <<'PY' >/dev/null 2>&1
import socket,sys
p=int(sys.argv[1])
s=socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(("127.0.0.1", p))
except OSError:
    sys.exit(1)
finally:
    s.close()
sys.exit(0)
PY
}

pick_unique_port() {
  local p=""
  local i
  for i in $(seq 1 5000); do
    p="$(pick_port)"
    if [[ -z "${p}" ]]; then
      continue
    fi
    if [[ -n "${USED_PORTS[$p]:-}" ]]; then
      continue
    fi
    if ! port_available "$p"; then
      continue
    fi
    USED_PORTS["$p"]=1
    echo "$p"
    return 0
  done
  echo "failed to pick unique port" >&2
  return 1
}

ca_sha256() {
  local path="$1"
  if [[ ! -f "${path}" ]]; then
    echo "missing"
    return 0
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${path}" | awk '{print $1}'
    return 0
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${path}" | awk '{print $1}'
    return 0
  fi
  echo "unavailable"
}

ensure_shared_devtls_ca() {
  if [[ -z "${SHARED_CA_PATH}" ]]; then
    SHARED_CA_PATH="${TMPROOT}/shared_devtls_ca.pem"
  fi
  SHARED_CA_CERT_PATH="${SHARED_CA_PATH}/ca_cert.pem"
  SHARED_CA_KEY_PATH="${SHARED_CA_PATH}/ca_key.pem"
  if [[ -s "${SHARED_CA_CERT_PATH}" && -s "${SHARED_CA_KEY_PATH}" ]]; then
    return 0
  fi
  mkdir -p "${SHARED_CA_PATH}"
  "${WEB4_BIN}" devtls-ca-gen --out-dir "${SHARED_CA_PATH}" --ips "${DEVTLS_CERT_IPS}" >/dev/null
  for _ in $(seq 1 120); do
    if [[ -s "${SHARED_CA_CERT_PATH}" && -s "${SHARED_CA_KEY_PATH}" ]]; then
      return 0
    fi
    sleep 0.05
  done
  return 1
}

wait_ready() {
  local idx="$1"
  local log="${NODE_LOG[$idx]}"
  local pid="${NODE_PID[$idx]}"
  local deadline=$(( $(date +%s) + 30 ))
  while (( $(date +%s) < deadline )); do
    if grep -q "READY addr=" "${log}" 2>/dev/null; then
      return 0
    fi
    if ! kill -0 "${pid}" >/dev/null 2>&1; then
      return 1
    fi
    sleep 0.1
  done
  return 1
}

extract_node_id() {
  local log="$1"
  python3 - "$log" <<'PY'
import re,sys
p=sys.argv[1]
try:
    data=open(p,'r',encoding='utf-8',errors='ignore').read().splitlines()
except Exception:
    print("")
    raise SystemExit(0)
for line in reversed(data):
    m=re.search(r"node_id=([0-9a-fA-F]{64})", line)
    if m:
        print(m.group(1).lower())
        raise SystemExit(0)
print("")
PY
}

metrics_value() {
  local idx="$1"
  local key="$2"
  local path="${NODE_HOME[$idx]}/.web4mvp/metrics.json"
  python3 - "$path" "$key" <<'PY'
import json,sys
path,key=sys.argv[1],sys.argv[2]
try:
    with open(path,'r',encoding='utf-8') as f:
        o=json.load(f)
    v=o.get(key,0)
    if isinstance(v,bool):
        print(int(v))
    elif isinstance(v,(int,float)):
        print(int(v))
    else:
        print(0)
except Exception:
    print(0)
PY
}

metrics_file() {
  local idx="$1"
  echo "${NODE_HOME[$idx]}/.web4mvp/metrics.json"
}

print_node0_rtt_buckets() {
  if (( RTT_METRICS_ENABLED != 1 )); then
    return 0
  fi
  local path
  path="$(metrics_file 0)"
  echo "RTT_METRICS_FILE node[0]=${path}"
  python3 - "$path" <<'PY'
import json,sys
path=sys.argv[1]
try:
    with open(path,'r',encoding='utf-8') as f:
        m=json.load(f)
except Exception as e:
    print(f"RTT_BUCKETS_READ_ERROR: {e}")
    raise SystemExit(0)
def emit(name):
    v=m.get(name,{})
    if not isinstance(v,dict):
        v={}
    print(f"{name}={json.dumps(v, sort_keys=True)}")
emit("rtt_buckets_handshake")
emit("rtt_buckets_pex")
PY
}

classify_churn_failure() {
  local idx="$1"
  local path
  path="$(metrics_file "$idx")"
  python3 - "$path" <<'PY'
import json,sys
path=sys.argv[1]
try:
    with open(path,'r',encoding='utf-8') as f:
        m=json.load(f)
except Exception:
    print("METRIC_MISMATCH")
    raise SystemExit(0)

def map_sum(k):
    v=m.get(k,{})
    if isinstance(v,dict):
        return sum(int(x) for x in v.values() if isinstance(x,(int,float)))
    return 0

out=int(m.get("outbound_connected",0) or 0)
cand_seed_attempts=0
cand_seed_success=0
attempt_map=m.get("dial_attempt_total_by_reason",{}) if isinstance(m.get("dial_attempt_total_by_reason",{}),dict) else {}
success_map=m.get("dial_success_total_by_reason",{}) if isinstance(m.get("dial_success_total_by_reason",{}),dict) else {}
for k,v in attempt_map.items():
    if "seed" in str(k):
        cand_seed_attempts += int(v or 0)
for k,v in success_map.items():
    if "seed" in str(k):
        cand_seed_success += int(v or 0)
cand=int(m.get("candidate_available",0) or 0)
back=int(m.get("backoff_blocked",0) or 0)
dial_fail=map_sum("dial_fail_total_by_reason")
hello_rej=map_sum("hello_handshake_fail_total_by_reason")
hello_ok=int(m.get("hello_handshake_success_total",0) or 0)
dial_attempts=int(m.get("dial_attempts_total",0) or 0)
dial_success=int(m.get("dial_success_total",0) or 0)
drop=m.get("drop_by_reason",{}) if isinstance(m.get("drop_by_reason",{}),dict) else {}
other_drop=int(drop.get("other",0) or 0)
ptable=int(m.get("peertable_size",0) or 0)

if out > 0:
    print("METRIC_MISMATCH")
elif cand == 0:
    print("NO_CANDIDATES")
elif back > 0 and dial_attempts == 0:
    print("BACKOFF_LOCK")
elif hello_rej > 0 and hello_ok == 0:
    print("HELLO_REJECTED")
elif cand_seed_attempts == 0 and ptable == 0:
    print("SEED_DISABLED")
elif cand_seed_attempts > 0 and cand_seed_success == 0 and hello_ok == 0:
    print("DIAL_FAILED")
elif hello_rej > 0:
    print("HELLO_REJECTED")
elif other_drop > 0 and dial_fail == 0 and dial_success == 0:
    print("INBOUND_FULL")
elif dial_fail > 0 or (dial_attempts > 0 and dial_success == 0):
    print("DIAL_FAILED")
else:
    print("METRIC_MISMATCH")
PY
}

print_churn_metrics_focus() {
  local idx="$1"
  local path
  path="$(metrics_file "$idx")"
  python3 - "$path" <<'PY'
import json,sys
path=sys.argv[1]
keys=[
  "outbound_connected","inbound_connected","peertable_size",
  "dial_attempts_total","dial_success_total",
  "quic_connect_success_total",
  "dial_attempt_total_by_reason","dial_success_total_by_reason","dial_fail_total_by_reason",
  "hello_handshake_success_total","hello_handshake_fail_total","hello_handshake_fail_total_by_reason",
  "hello_success_total","hello_reject_total_by_reason",
  "candidate_available","backoff_blocked","seed_dial_skipped_total",
  "recovery_mode_active","recovery_enter_total","recovery_exit_total","recovery_panic_dials_total"
]
try:
    with open(path,'r',encoding='utf-8') as f:
        m=json.load(f)
except Exception:
    print("{}")
    raise SystemExit(0)
out={k:m.get(k) for k in keys}
print(json.dumps(out, indent=2, sort_keys=True))
PY
}

print_connman_tail() {
  local idx="$1"
  local log="${NODE_LOG[$idx]}"
  if [[ ! -f "${log}" ]]; then
    return
  fi
  local filtered
  filtered="$(grep -E "connman|forced_dial|recovery|dial failed|hello_reject|hello_decode|hello1 to_id mismatch" "${log}" | tail -n 120 || true)"
  if [[ -n "${filtered}" ]]; then
    printf "%s\n" "${filtered}"
  else
    tail -n 120 "${log}" 2>/dev/null || true
  fi
}

report_churn_failure() {
  local idx="$1"
  local reason
  reason="$(classify_churn_failure "$idx")"
  echo "CHURN_FAILURE node=${idx} classification=${reason}"
  echo "CHURN_FAILURE_METRICS node=${idx}"
  print_churn_metrics_focus "$idx"
  echo "CHURN_FAILURE_CONNMAN_LOG_TAIL node=${idx} lines=120"
  print_connman_tail "$idx"
}

probe_seed_listen() {
  local seed_addr="${NODE_ADDR[0]:-}"
  local seed_pid="${NODE_PID[0]:-}"
  if [[ -z "${seed_addr}" ]]; then
    echo "PROBE seed_addr=missing"
    return
  fi
  local seed_port="${seed_addr##*:}"
  local alive=0
  if [[ -n "${seed_pid}" ]] && kill -0 "${seed_pid}" >/dev/null 2>&1; then
    alive=1
  fi
  echo "PROBE seed_pid=${seed_pid:-none} alive=${alive} addr=${seed_addr} port=${seed_port}"
  if command -v ss >/dev/null 2>&1; then
    echo "PROBE ss_seed_port"
    ss -lunpt 2>/dev/null | grep -E "[:.]${seed_port}[[:space:]]" || true
  elif command -v lsof >/dev/null 2>&1; then
    echo "PROBE lsof_seed_port"
    lsof -nP -iUDP:"${seed_port}" || true
  else
    echo "PROBE seed_port_check=skipped(no ss/lsof)"
  fi
}

probe_tc_netns_state() {
  echo "PROBE tc_lo_qdisc"
  if command -v tc >/dev/null 2>&1; then
    tc qdisc show dev lo 2>/dev/null || true
  else
    echo "tc not found"
  fi
  echo "PROBE netns_created_by_script"
  if command -v ip >/dev/null 2>&1; then
    ip netns list 2>/dev/null | grep -E "^${NETNS_PREFIX}_" || true
  else
    echo "ip not found"
  fi
}

probe_churn_failure_env() {
  probe_seed_listen
  probe_tc_netns_state
}

node_listen_addr_from_log() {
  local idx="$1"
  local log="${NODE_LOG[$idx]}"
  if [[ ! -f "${log}" ]]; then
    echo "unknown"
    return 0
  fi
  awk '
    /READY addr=/ {
      for (i=1;i<=NF;i++) {
        if ($i ~ /^addr=/) {
          sub(/^addr=/, "", $i)
          addr=$i
        }
      }
    }
    END {
      if (addr == "") addr="unknown"
      print addr
    }
  ' "${log}" 2>/dev/null || echo "unknown"
}

print_top_dial_candidates() {
  local idx="$1"
  local path="${NODE_HOME[$idx]}/.web4mvp/peers.jsonl"
  python3 - "$path" <<'PY'
import json,sys
path=sys.argv[1]
peers={}
try:
    with open(path,"r",encoding="utf-8",errors="ignore") as f:
        for line in f:
            line=line.strip()
            if not line:
                continue
            try:
                o=json.loads(line)
            except Exception:
                continue
            nid=str(o.get("node_id",""))
            if not nid:
                continue
            dial=str(o.get("dial_addr") or o.get("addr") or "").strip()
            score=float(o.get("score",0.0) or 0.0)
            peers[nid]={"dial":dial,"score":score}
except Exception:
    print("  (no peers.jsonl)")
    raise SystemExit(0)
rows=[(v["score"],k,v["dial"]) for k,v in peers.items() if v["dial"]]
rows.sort(reverse=True)
if not rows:
    print("  (no dial candidates)")
    raise SystemExit(0)
for score,nid,dial in rows[:10]:
    print(f"  node={nid[:12]} dial_addr={dial} score={score:.3f}")
PY
}

print_ca_path_per_node() {
  local idx
  local cert_sha
  local key_sha
  cert_sha="$(ca_sha256 "${SHARED_CA_CERT_PATH}")"
  key_sha="$(ca_sha256 "${SHARED_CA_KEY_PATH}")"
  for idx in $(seq 0 "${P2P_STRESS_N}"); do
    if [[ "${NODE_ALIVE[$idx]:-0}" == "1" || "${NODE_ALIVE[$idx]:-0}" == "2" ]]; then
      echo "node[$idx] devtls_ca_cert_path=${SHARED_CA_CERT_PATH} cert_sha256=${cert_sha} devtls_ca_key_path=${SHARED_CA_KEY_PATH} key_sha256=${key_sha}"
    fi
  done
}

report_partition_failure() {
  local failing_idx="${1:-0}"
  local idx
  if [[ -z "${failing_idx}" || "${failing_idx}" == "-1" ]]; then
    failing_idx=0
    for idx in $(seq 0 "${P2P_STRESS_N}"); do
      if [[ "${NODE_ALIVE[$idx]:-0}" == "1" ]]; then
        failing_idx="${idx}"
        break
      fi
    done
  fi
  echo "PARTITION_FAILURE node=${failing_idx}"
  echo "PARTITION_FAILURE_METRICS node=${failing_idx}"
  cat "$(metrics_file "${failing_idx}")" 2>/dev/null || true
  echo "PARTITION_FAILURE_CONNMAN_LOG_TAIL node=${failing_idx} lines=200"
  tail -n 200 "${NODE_LOG[$failing_idx]}" 2>/dev/null || true
  echo "PARTITION_FAILURE_CA"
  print_ca_path_per_node
  echo "PARTITION_FAILURE_LISTEN_ADDR_AND_DIAL_CANDIDATES"
  for idx in $(seq 0 "${P2P_STRESS_N}"); do
    if [[ "${NODE_ALIVE[$idx]:-0}" != "1" && "${NODE_ALIVE[$idx]:-0}" != "2" ]]; then
      continue
    fi
    echo "node[$idx] listen_addr=$(node_listen_addr_from_log "${idx}")"
    print_top_dial_candidates "${idx}"
  done
}

status_dump() {
  local idx="$1"
  HOME="${NODE_HOME[$idx]}" "${WEB4_NODE_BIN}" status || true
}

dump_fail_logs() {
  echo "---- failure diagnostics ----"
  echo "WEB4_DEVTLS_CERT_IPS=${DEVTLS_CERT_IPS}"
  if [[ -n "${SHARED_CA_PATH}" ]]; then
    echo "WEB4_DEVTLS_CA_CERT_PATH=${SHARED_CA_CERT_PATH} cert_sha256=$(ca_sha256 "${SHARED_CA_CERT_PATH}")"
    echo "WEB4_DEVTLS_CA_KEY_PATH=${SHARED_CA_KEY_PATH} key_sha256=$(ca_sha256 "${SHARED_CA_KEY_PATH}")"
    print_ca_path_per_node || true
  fi
  if [[ "${NETNS_READY}" -eq 1 ]]; then
    echo "NETNS_DIAG ip netns list:"
    ip netns list 2>/dev/null || true
    echo "NETNS_DIAG bridge links (${BR_NAME}):"
    ip -br link show master "${BR_NAME}" 2>/dev/null || true
    echo "NETNS_DIAG ip a (group A: ${NS_G1}):"
    ip netns exec "${NS_G1}" ip a 2>/dev/null || true
    echo "NETNS_DIAG ip a (group B: ${NS_G2}):"
    ip netns exec "${NS_G2}" ip a 2>/dev/null || true
    echo "NETNS_DIAG iptables -S (group A: ${NS_G1}):"
    ip netns exec "${NS_G1}" iptables -S 2>/dev/null || true
    echo "NETNS_DIAG iptables -S (group B: ${NS_G2}):"
    ip netns exec "${NS_G2}" iptables -S 2>/dev/null || true
    echo "NETNS_DIAG ss -lunpt (seed ns: ${NODE_NS[0]:-${NS_G1}}):"
    ip netns exec "${NODE_NS[0]:-${NS_G1}}" ss -lunpt 2>/dev/null || true
  fi
  local i
  for i in "${!NODE_LOG[@]}"; do
    if [[ "${NODE_ALIVE[$i]:-0}" == "1" || "${NODE_ALIVE[$i]:-0}" == "2" ]]; then
      echo "node[$i] addr=${NODE_ADDR[$i]} alive=${NODE_ALIVE[$i]} log=${NODE_LOG[$i]}"
      tail -n 200 "${NODE_LOG[$i]}" 2>/dev/null || true
      echo "node[$i] status:"
      status_dump "$i"
      echo "node[$i] metrics:"
      tail -n 80 "${NODE_HOME[$i]}/.web4mvp/metrics.json" 2>/dev/null || true
    fi
  done
}

start_node() {
  local idx="$1"
  local mode="$2"
  local addr="$3"
  local bootstrap_addr="$4"
  local netns="${5:-}"
  local reject_loopback="0"
  if [[ -n "${netns}" ]]; then
    reject_loopback="1"
  fi
  local home="${TMPROOT}/node_${idx}"
  mkdir -p "${home}"
  local log="${TMPROOT}/node_${idx}.log"
  local envs=(
    "HOME=${home}"
    "WEB4_NODE_MODE=${mode}"
    "WEB4_OUTBOUND_TARGET=${P2P_STRESS_OUTBOUND_TARGET}"
    "WEB4_OUTBOUND_EXPLORE=${P2P_STRESS_OUTBOUND_EXPLORE}"
    "WEB4_PEX_INTERVAL_SEC=${P2P_STRESS_PEX_INTERVAL_SEC}"
    "WEB4_CONNMAN_TICK_MS=${P2P_STRESS_CONNMAN_TICK_MS}"
    "WEB4_DIAL_TIMEOUT_MS=${P2P_STRESS_DIAL_TIMEOUT_MS}"
    "WEB4_MAX_CONNS=${P2P_STRESS_MAX_CONNS}"
    "WEB4_MAX_STREAMS_PER_CONN=${P2P_STRESS_MAX_STREAMS_PER_CONN}"
    "WEB4_DISABLE_LIMITER=${P2P_STRESS_DISABLE_LIMITER}"
    "WEB4_LIMITER_MAX_CONNS_PER_IP=${P2P_STRESS_LIMITER_MAX_CONNS_PER_IP}"
    "WEB4_DEBUG=${P2P_STRESS_WEB4_DEBUG}"
    "WEB4_PEERTABLE_MAX=${P2P_STRESS_PEERTABLE_MAX}"
    "WEB4_SUBNET_MAX=${P2P_STRESS_SUBNET_MAX}"
    "WEB4_PEX_INSERT_MAX=${P2P_STRESS_PEX_INSERT_MAX}"
    "WEB4_PEER_EXCHANGE_MAX=${P2P_STRESS_PEER_EXCHANGE_MAX}"
    "WEB4_PEER_EXCHANGE_SEED=${P2P_STRESS_SEED}"
    "WEB4_DEVTLS_CERT_IPS=${DEVTLS_CERT_IPS}"
    "WEB4_REJECT_LOOPBACK_DIAL_ADDR=${reject_loopback}"
    "WEB4_DEVTLS_CA_PATH=${SHARED_CA_CERT_PATH}"
    "WEB4_DEVTLS_CA_CERT_PATH=${SHARED_CA_CERT_PATH}"
    "WEB4_DEVTLS_CA_KEY_PATH=${SHARED_CA_KEY_PATH}"
  )
  if [[ -n "${bootstrap_addr}" ]]; then
    envs+=("WEB4_BOOTSTRAP_ADDRS=${bootstrap_addr}")
  fi
  if [[ "${idx}" == "0" && "${P2P_STRESS_PPROF}" == "1" ]]; then
    envs+=("WEB4_PPROF=1" "WEB4_PPROF_ADDR=${P2P_STRESS_PPROF_ADDR}")
  fi
  if [[ "${idx}" == "0" && "${RTT_METRICS_ENABLED}" == "1" && "${WEB4_METRICS_DISK_WRITE_SEC_IS_SET}" != "1" ]]; then
    envs+=("WEB4_METRICS_DISK_WRITE_SEC=1")
  fi
  if [[ -n "${netns}" ]]; then
    ip netns exec "${netns}" env "${envs[@]}" "${WEB4_NODE_BIN}" run --devtls --addr "${addr}" >"${log}" 2>&1 &
  else
    env "${envs[@]}" "${WEB4_NODE_BIN}" run --devtls --addr "${addr}" >"${log}" 2>&1 &
  fi
  local pid=$!

  NODE_HOME[$idx]="${home}"
  NODE_ADDR[$idx]="${addr}"
  NODE_LOG[$idx]="${log}"
  NODE_PID[$idx]="${pid}"
  NODE_ALIVE[$idx]="1"
  NODE_NS[$idx]="${netns}"

  if ! wait_ready "$idx"; then
    fail "node[$idx] did not become ready"
  fi
  NODE_ID[$idx]="$(extract_node_id "${log}")"
  if [[ -z "${NODE_ID[$idx]}" ]]; then
    fail "node[$idx] missing node id"
  fi
  if [[ "${idx}" == "0" && "${P2P_STRESS_PPROF}" == "1" ]]; then
    if [[ -n "${NODE_NS[$idx]:-}" ]]; then
      echo "P2P_STRESS_PPROF: node[0] pprof=http://${P2P_STRESS_PPROF_ADDR}/debug/pprof/ (netns=${NODE_NS[$idx]})"
      echo "P2P_STRESS_PPROF: use -> sudo ip netns exec ${NODE_NS[$idx]} go tool pprof \"http://${P2P_STRESS_PPROF_ADDR}/debug/pprof/profile?seconds=30\""
    else
      echo "P2P_STRESS_PPROF: node[0] pprof=http://${P2P_STRESS_PPROF_ADDR}/debug/pprof/"
    fi
  fi
}

require_timeout() {
  local now
  now="$(date +%s)"
  if (( now - START_TS > P2P_STRESS_TIMEOUT_SEC )); then
    fail "global timeout exceeded (${P2P_STRESS_TIMEOUT_SEC}s)"
  fi
}

wait_for_growth() {
  local sec="$1"
  local end=$(( $(date +%s) + sec ))
  while (( $(date +%s) < end )); do
    require_timeout
    sleep 1
  done
}

assert_health() {
  local idx="$1"
  local out
  local pt
  out="$(metrics_value "$idx" "outbound_connected")"
  pt="$(metrics_value "$idx" "peertable_size")"
  if (( out < P2P_STRESS_MIN_OUTBOUND )); then
    echo "node[$idx] outbound_connected=${out} < ${P2P_STRESS_MIN_OUTBOUND}"
    return 1
  fi
  if (( pt < P2P_STRESS_MIN_PEERTABLE )); then
    echo "node[$idx] peertable_size=${pt} < ${P2P_STRESS_MIN_PEERTABLE}"
    return 1
  fi
  if (( pt > P2P_STRESS_PEERTABLE_MAX )); then
    echo "node[$idx] peertable_size=${pt} > ${P2P_STRESS_PEERTABLE_MAX}"
    return 1
  fi
  return 0
}

partition_outbound_threshold() {
  local min="${P2P_STRESS_MIN_OUTBOUND}"
  if (( min < 2 )); then
    min=2
  fi
  echo "${min}"
}

assert_partition_warmup_health() {
  local idx="$1"
  local out
  local pt
  local part_min_out
  part_min_out="$(partition_outbound_threshold)"
  out="$(metrics_value "$idx" "outbound_connected")"
  pt="$(metrics_value "$idx" "peertable_size")"
  if (( out < part_min_out )); then
    return 1
  fi
  if (( pt < 5 )); then
    return 1
  fi
  return 0
}

dump_partition_warmup_snapshot() {
  local idx
  local out
  local pt
  local part_min_out
  part_min_out="$(partition_outbound_threshold)"
  echo "PARTITION_WARMUP_SNAPSHOT threshold_outbound=${part_min_out} threshold_peertable=5"
  for idx in $(seq 0 "${P2P_STRESS_N}"); do
    if [[ "${NODE_ALIVE[$idx]:-0}" != "1" ]]; then
      continue
    fi
    out="$(metrics_value "$idx" "outbound_connected")"
    pt="$(metrics_value "$idx" "peertable_size")"
    echo "node[${idx}] outbound_connected=${out} peertable_size=${pt}"
  done
}

wait_for_partition_warmup() {
  local timeout="${P2P_PARTITION_WARMUP_TIMEOUT_SEC}"
  local deadline=$(( $(date +%s) + timeout ))
  local idx
  local all_ok
  while (( $(date +%s) < deadline )); do
    require_timeout
    all_ok=1
    for idx in $(seq 0 "${P2P_STRESS_N}"); do
      if [[ "${NODE_ALIVE[$idx]:-0}" != "1" ]]; then
        continue
      fi
      if ! assert_partition_warmup_health "${idx}"; then
        all_ok=0
        break
      fi
    done
    if (( all_ok == 1 )); then
      return 0
    fi
    sleep 1
  done
  echo "PARTITION_WARMUP_TIMEOUT after ${timeout}s"
  dump_partition_warmup_snapshot
  return 1
}

kill_node() {
  local idx="$1"
  if [[ "${NODE_ALIVE[$idx]:-0}" != "1" ]]; then
    return
  fi
  kill "${NODE_PID[$idx]}" >/dev/null 2>&1 || true
  wait "${NODE_PID[$idx]}" >/dev/null 2>&1 || true
  NODE_ALIVE[$idx]="2"
}

pick_kill_set() {
  local n="$1"
  local k="$2"
  local seed="$3"
  python3 - "$n" "$k" "$seed" <<'PY'
import random,sys
n,k,seed = map(int, sys.argv[1:4])
random.seed(seed)
arr=list(range(1,n+1))
random.shuffle(arr)
print(" ".join(map(str,arr[:k])))
PY
}

run_churn() {
  echo "SCENARIO: churn"
  local k=$(( (P2P_STRESS_N * P2P_STRESS_CHURN_PCT + 99) / 100 ))
  if (( k < 1 )); then k=1; fi
  local kill_set
  local interval
  local sample
  kill_set="$(pick_kill_set "${P2P_STRESS_N}" "${k}" "${P2P_STRESS_SEED}")"
  wait_for_growth "${P2P_STRESS_WARMUP_SEC}"
  local idx
  for idx in ${kill_set}; do
    kill_node "$idx"
  done
  interval=$(( P2P_STRESS_RECOVERY_SEC / 3 ))
  if (( interval < 1 )); then
    interval=1
  fi
  for idx in $(seq 1 "${P2P_STRESS_N}"); do
    CHURN_OK[$idx]=0
  done
  for sample in 1 2 3; do
    for idx in $(seq 1 "${P2P_STRESS_N}"); do
      if [[ "${NODE_ALIVE[$idx]:-0}" == "1" ]]; then
        if assert_health "$idx" >/dev/null 2>&1; then
          CHURN_OK[$idx]=$(( ${CHURN_OK[$idx]:-0} + 1 ))
        fi
      fi
    done
    if (( sample < 3 )); then
      wait_for_growth "${interval}"
    fi
  done
  for idx in $(seq 1 "${P2P_STRESS_N}"); do
    if [[ "${NODE_ALIVE[$idx]:-0}" == "1" ]]; then
      if (( ${CHURN_OK[$idx]:-0} < 2 )); then
        assert_health "$idx" || true
        echo "node[$idx] churn samples ok=${CHURN_OK[$idx]:-0}/3 (<2)"
        report_churn_failure "$idx"
        probe_churn_failure_env
        fail "churn recovery check failed for node[$idx]"
      fi
    fi
  done
  pass "churn"
}

run_partition() {
  echo "SCENARIO: partition"
  local mid
  local idx
  local g1_ok=0
  local g2_ok=0
  local pt
  if [[ "${NETNS_READY}" -ne 1 ]]; then
    if [[ -n "${PARTITION_SKIP_REASON}" ]]; then
      skip "${PARTITION_SKIP_REASON}"
    else
      skip "partition (netns topology not available)"
    fi
    return 0
  fi
  if ! wait_for_partition_warmup; then
    report_partition_failure -1
    fail "partition warmup failed before firewall partition"
  fi
  if ! apply_partition_iptables; then
    clear_partition_iptables || true
    skip "partition (failed to apply iptables partition rules)"
    return 0
  fi
  sleep "${P2P_STRESS_PARTITION_SEC}"
  mid=$(( P2P_STRESS_N / 2 ))
  for idx in $(seq 1 "${mid}"); do
    if [[ "${NODE_ALIVE[$idx]:-0}" == "1" ]]; then
      pt="$(metrics_value "$idx" "peertable_size")"
      if (( pt >= 1 )); then
        g1_ok=1
        break
      fi
    fi
  done
  for idx in $(seq $((mid + 1)) "${P2P_STRESS_N}"); do
    if [[ "${NODE_ALIVE[$idx]:-0}" == "1" ]]; then
      pt="$(metrics_value "$idx" "peertable_size")"
      if (( pt >= 1 )); then
        g2_ok=1
        break
      fi
    fi
  done
  if (( g1_ok == 0 || g2_ok == 0 )); then
    report_partition_failure -1
    fail "partition activity check failed (one side stalled during partition)"
  fi
  clear_partition_iptables || true
  wait_for_growth "${P2P_STRESS_RECOVERY_SEC}"
  for idx in $(seq 1 "${P2P_STRESS_N}"); do
    if [[ "${NODE_ALIVE[$idx]:-0}" == "1" ]]; then
      if ! assert_health "$idx"; then
        report_partition_failure "$idx"
        fail "partition recovery check failed for node[$idx]"
      fi
    fi
  done
  pass "partition"
}

gen_poison_resp() {
  local out="$1"
  local count="$2"
  python3 - "$out" "$count" <<'PY'
import json,sys
out,count=sys.argv[1],int(sys.argv[2])
peers=[]
for i in range(count):
    # Duplicate-heavy, same-subnet-heavy payload.
    host=f"127.9.9.{(i%32)+1}"
    port=50000 + (i % 12)
    addr=f"{host}:{port}"
    node_id=(f"{i:064x}")[-64:]
    pubkey="00"
    peers.append({"node_id": node_id, "pubkey": pubkey, "addr": addr})
    if i % 3 == 0:
        peers.append({"node_id": node_id, "pubkey": pubkey, "addr": addr})
msg={
    "type":"peer_exchange_resp",
    "proto_version":"0.0.2",
    "suite":"web4-wire-v1",
    "peers":peers,
}
with open(out,"w",encoding="utf-8") as f:
    json.dump(msg,f,separators=(",",":"))
PY
}

run_poison_lite() {
  echo "SCENARIO: pex poison-lite"
  local target=1
  while [[ "${NODE_ALIVE[$target]:-0}" != "1" && "$target" -le "${P2P_STRESS_N}" ]]; do
    target=$((target+1))
  done
  if (( target > P2P_STRESS_N )); then
    fail "no live peer for poison-lite"
  fi
  local before
  before="$(metrics_value "$target" "peertable_size")"
  local poison_file="${TMPROOT}/poison_resp.json"
  gen_poison_resp "${poison_file}" "${P2P_STRESS_POISON_PEERS}"

  local ca_path="${SHARED_CA_CERT_PATH}"
  HOME="${NODE_HOME[0]}" "${WEB4_BIN}" quic-send --devtls --devtls-ca "${ca_path}" --addr "${NODE_ADDR[$target]}" --in "${poison_file}" >/dev/null 2>&1 || true

  wait_for_growth 4
  local after
  after="$(metrics_value "$target" "peertable_size")"
  local growth=$(( after - before ))

  if (( after > P2P_STRESS_PEERTABLE_MAX )); then
    fail "poison-lite peertable blowup: ${after} > ${P2P_STRESS_PEERTABLE_MAX}"
  fi
  local max_growth=$(( P2P_STRESS_PEX_INSERT_MAX + 12 ))
  if (( growth > max_growth )); then
    fail "poison-lite excessive growth: +${growth} > +${max_growth}"
  fi
  pass "pex poison-lite"
}

stop_nodes() {
  local i
  for i in "${!NODE_PID[@]}"; do
    if [[ -n "${NODE_PID[$i]:-}" ]]; then
      kill "${NODE_PID[$i]}" >/dev/null 2>&1 || true
      wait "${NODE_PID[$i]}" >/dev/null 2>&1 || true
      NODE_PID[$i]=""
      NODE_ALIVE[$i]="0"
    fi
  done
}

reset_cluster_arrays() {
  NODE_HOME=()
  NODE_ADDR=()
  NODE_LOG=()
  NODE_PID=()
  NODE_ID=()
  NODE_ALIVE=()
  NODE_NS=()
  CHURN_OK=()
  USED_PORTS=()
}

start_cluster() {
  local use_netns="$1"
  local bootstrap_host="127.0.0.1"
  local bootstrap_ns=""
  local peer_host=""
  local peer_ns=""
  local bootstrap_port=""
  local bootstrap_addr=""
  local i
  local p

  reset_cluster_arrays
  DEVTLS_CERT_IPS="127.0.0.1"
  if [[ "${use_netns}" == "1" ]]; then
    SHARED_CA_PATH="${TMPROOT}/shared_devtls_ca_netns"
  else
    SHARED_CA_PATH="${TMPROOT}/shared_devtls_ca_local"
  fi
  if [[ "${use_netns}" == "1" ]]; then
    if ! setup_partition_netns; then
      return 1
    fi
    bootstrap_host="${PART_NS_IP[0]}"
    bootstrap_ns="${PART_NS_LIST[0]}"
  fi
  if ! ensure_shared_devtls_ca; then
    fail "failed to generate shared devtls CA"
  fi

  bootstrap_port="$(pick_unique_port)" || fail "unable to allocate bootstrap port"
  bootstrap_addr="${bootstrap_host}:${bootstrap_port}"
  start_node 0 bootstrap "${bootstrap_addr}" "" "${bootstrap_ns}"

  for i in $(seq 1 "${P2P_STRESS_N}"); do
    p="$(pick_unique_port)" || fail "unable to allocate port for peer[$i]"
    peer_host="127.0.0.1"
    peer_ns=""
    if [[ "${use_netns}" == "1" ]]; then
      peer_host="${PART_NS_IP[$i]}"
      peer_ns="${PART_NS_LIST[$i]}"
    fi
    start_node "$i" peer "${peer_host}:${p}" "${bootstrap_addr}" "${peer_ns}"
  done
  return 0
}

parse_scenarios() {
  local raw="${1// /}"
  raw="${raw//|/,}"
  if [[ -z "${raw}" ]]; then
    raw="all"
  fi
  if [[ "${raw}" == "all" ]]; then
    echo "churn,partition,poison-lite"
    return
  fi
  local out=()
  local tok
  IFS=',' read -r -a _parts <<<"${raw}"
  for tok in "${_parts[@]}"; do
    case "${tok}" in
      churn) out+=("churn") ;;
      partition) out+=("partition") ;;
      poison|poison-lite) out+=("poison-lite") ;;
      all) out+=("churn" "partition" "poison-lite") ;;
      "") ;;
      *) warn "unknown scenario token '${tok}', skipping" ;;
    esac
  done
  if (( ${#out[@]} == 0 )); then
    out=("churn")
  fi
  local joined=""
  local item
  for item in "${out[@]}"; do
    if [[ -z "${joined}" ]]; then
      joined="${item}"
    else
      joined="${joined},${item}"
    fi
  done
  echo "${joined}"
}

scenarios_csv="$(parse_scenarios "${P2P_STRESS_SCENARIOS}")"
IFS=',' read -r -a scenarios <<<"${scenarios_csv}"
echo "CONFIG: n=${P2P_STRESS_N} churn_pct=${P2P_STRESS_CHURN_PCT} min_outbound=${P2P_STRESS_MIN_OUTBOUND} min_peertable=${P2P_STRESS_MIN_PEERTABLE}"

start_cluster "0"
for s in "${scenarios[@]}"; do
  if [[ "${s}" == "partition" ]]; then
    continue
  fi
  case "${s}" in
    churn) run_churn ;;
    poison-lite) run_poison_lite ;;
    "") ;;
    *) warn "unknown scenario '${s}', skipping" ;;
  esac
  require_timeout
done

need_partition=0
for s in "${scenarios[@]}"; do
  if [[ "${s}" == "partition" ]]; then
    need_partition=1
    break
  fi
done
if (( need_partition == 1 )); then
  stop_nodes
  if start_cluster "1"; then
    run_partition
  else
    skip "${PARTITION_SKIP_REASON:-partition (failed to initialize netns cluster)}"
  fi
  require_timeout
fi

print_node0_rtt_buckets
echo "ALL P2P STRESS SCENARIOS COMPLETED"
keepalive_wait_if_enabled
