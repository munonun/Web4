#!/usr/bin/env bash

set -euo pipefail
: "${WEB4_STORE_MAX_BYTES:?set WEB4_STORE_MAX_BYTES (e.g. 65536) to run smoke tests}"
: "${WEB4_QUIC_IDLE_TIMEOUT_SEC:=60}"
: "${WEB4_QUIC_HANDSHAKE_TIMEOUT_SEC:=30}"
: "${WEB4_QUIC_STREAM_TIMEOUT_SEC:=30}"
: "${WEB4_QUIC_ACCEPT_TIMEOUT_SEC:=30}"
: "${WEB4_QUIC_ACQUIRE_TIMEOUT_MS:=500}"
: "${WEB4_DISABLE_LIMITER:=1}"
: "${WEB4_ZK_SMOKE:=0}"
export WEB4_QUIC_IDLE_TIMEOUT_SEC WEB4_QUIC_HANDSHAKE_TIMEOUT_SEC WEB4_QUIC_STREAM_TIMEOUT_SEC WEB4_QUIC_ACCEPT_TIMEOUT_SEC WEB4_QUIC_ACQUIRE_TIMEOUT_MS WEB4_DISABLE_LIMITER
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=check6_lib.sh
source "${SCRIPT_DIR}/check6_lib.sh"
pass() {
	echo "PASS: $1"
}

fail() {
	echo "FAIL: $1"
	exit 1
}

pick_port() {
	local fallback="$1"
	local port=""
	if command -v python3 >/dev/null 2>&1; then
		port="$(python3 - <<'PY' 2>/dev/null || true
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"
	fi
	if [[ -z "${port}" ]]; then
		port="${fallback}"
	fi
	printf '%s' "${port}"
}

declare -A USED_PORTS=()
USED_PORT_LIST=()

port_available() {
	local port="$1"
	if command -v python3 >/dev/null 2>&1; then
		python3 - "$port" <<'PY' >/dev/null 2>&1
import socket, sys
port = int(sys.argv[1])
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(("127.0.0.1", port))
except OSError:
    sys.exit(1)
finally:
    s.close()
sys.exit(0)
PY
		return $?
	fi
	# Fallback: /dev/tcp returns success if something is listening.
	if (echo >/dev/tcp/127.0.0.1/"${port}") >/dev/null 2>&1; then
		return 1
	fi
	return 0
}

pick_unique_port() {
	local fallback="$1"
	local p=""
	for _ in $(seq 1 6000); do
		p="$(pick_port "${fallback}")"
		# 중복이면 다시
		if [[ -n "${USED_PORTS[${p}]:-}" ]]; then
			continue
		fi
		if ! port_available "${p}"; then
			continue
		fi
		USED_PORTS["${p}"]=1
		USED_PORT_LIST+=("${p}")
		printf '%s' "${p}"
		return 0
	done
	echo "FAIL: could not pick unique port" >&2
	exit 1
}

TMPA="$(mktemp -d)"
TMPB="$(mktemp -d)"
TMPC="$(mktemp -d)"
TMPD="$(mktemp -d)"
TMPWORK="$(mktemp -d)"
NODEIDA=""
NODEIDB=""
NODEIDC=""
NODEIDD=""
LISTENER_PIDS=()
SERVER_PID=""
SERVER_PID_B=""
SERVER_PID_C=""
SERVER_PID_A=""
STATEFUL_PID=""
SENDER_PID=""

cleanup() {
	local status=$?
	set +e
	# Kill any child jobs/processes before removing TMPWORK.
	if jobs -pr >/dev/null 2>&1; then
		jobs -pr | xargs -r kill 2>/dev/null || true
	fi
	if command -v pgrep >/dev/null 2>&1; then
		pgrep -P $$ | xargs -r kill 2>/dev/null || true
	fi
	for pid in "${LISTENER_PIDS[@]}"; do
		if [[ -n "${pid}" ]]; then
			kill "${pid}" 2>/dev/null || true
			wait "${pid}" 2>/dev/null || true
		fi
	done
	if [[ -n "${SERVER_PID}" ]]; then
		kill "${SERVER_PID}" 2>/dev/null || true
		wait "${SERVER_PID}" 2>/dev/null || true
	fi
	if [[ -n "${SERVER_PID_B}" ]]; then
		kill "${SERVER_PID_B}" 2>/dev/null || true
		wait "${SERVER_PID_B}" 2>/dev/null || true
	fi
	if [[ -n "${SERVER_PID_C}" ]]; then
		kill "${SERVER_PID_C}" 2>/dev/null || true
		wait "${SERVER_PID_C}" 2>/dev/null || true
	fi
	if [[ -n "${SERVER_PID_A}" ]]; then
		kill "${SERVER_PID_A}" 2>/dev/null || true
		wait "${SERVER_PID_A}" 2>/dev/null || true
	fi
	if [[ -n "${STATEFUL_PID}" ]]; then
		kill "${STATEFUL_PID}" 2>/dev/null || true
		wait "${STATEFUL_PID}" 2>/dev/null || true
	fi
	if [[ -n "${SENDER_PID}" ]]; then
		kill "${SENDER_PID}" 2>/dev/null || true
		wait "${SENDER_PID}" 2>/dev/null || true
	fi
	wait 2>/dev/null || true
	for port in "${USED_PORT_LIST[@]}"; do
		for _ in $(seq 1 200); do
			if port_available "${port}"; then
				break
			fi
			sleep 0.01
		done
	done
	if [[ "${SMOKE_KEEP_TMP:-}" == "1" ]]; then
		echo "SMOKE_KEEP_TMP=1 leaving tmp dirs: ${TMPA} ${TMPB} ${TMPC} ${TMPD} ${TMPWORK}" >&2
	else
		rm -rf "${TMPA}" "${TMPB}" "${TMPC}" "${TMPD}" "${TMPWORK}"
	fi
	exit "${status}"
}
trap cleanup EXIT

if [[ "${WEB4_SMOKE_PKILL:-}" == "1" ]]; then
	pkill -f "web4 quic-listen" 2>/dev/null || true
fi

if [[ -n "${WEB4_BIN:-}" ]]; then
	if [[ ! -x "${WEB4_BIN}" ]]; then
		fail "WEB4_BIN not executable: ${WEB4_BIN}"
	fi
else
	WEB4_BIN="${TMPWORK}/web4"
	go build -o "${WEB4_BIN}" ./cmd/web4
fi

if [[ -n "${WEB4_NODE_BIN:-}" ]]; then
	if [[ ! -x "${WEB4_NODE_BIN}" ]]; then
		fail "WEB4_NODE_BIN not executable: ${WEB4_NODE_BIN}"
	fi
else
	WEB4_NODE_BIN="${TMPWORK}/web4-node"
	go build -o "${WEB4_NODE_BIN}" ./cmd/web4-node
fi

run_a() {
	HOME="${TMPA}" "${WEB4_BIN}" "$@"
}

run_b() {
	HOME="${TMPB}" "${WEB4_BIN}" "$@"
}

run_c() {
	HOME="${TMPC}" "${WEB4_BIN}" "$@"
}

run_d() {
	HOME="${TMPD}" "${WEB4_BIN}" "$@"
}

run_node_a() {
	HOME="${TMPA}" "${WEB4_NODE_BIN}" "$@"
}

run_node_b() {
	HOME="${TMPB}" "${WEB4_NODE_BIN}" "$@"
}

if [[ "${WEB4_ZK_SMOKE}" == "1" ]]; then
	if ! go test ./internal/zk/linear -run '^TestProveVerifyLinearNullspace$' -count=1; then
		fail "zk smoke failed"
	fi
fi

declare -A DEBUG_PEER_SEEN
debug_peer_seen_once() {
	if [[ "${WEB4_DEBUG:-}" != "1" ]]; then
		return 0
	fi
	local label="$1"
	local file="$2"
	local id="$3"
	local key="${label}:${id}"
	if [[ -n "${DEBUG_PEER_SEEN[${key}]:-}" ]]; then
		return 0
	fi
	if [[ -f "${file}" ]] && grep -q "${id}" "${file}"; then
		DEBUG_PEER_SEEN["${key}"]=1
		local line
		line="$(grep -n "${id}" "${file}" | head -n 1 || true)"
		echo "debug peers: ${label} saw ${id} at ${line}" >&2
	fi
}

wait_quic_ready() {
	local log="$1"
	local label="$2"
	for _ in $(seq 1 400); do
		if grep -q "quic listen ready:" "${log}"; then
			return 0
		fi
		sleep 0.05
	done
	fail "${label}: server did not start"
}

prefill_jsonl() {
	local path="$1"
	local target_bytes="$2"
	local line_bytes=900000
	local prefix='{"pad":"'
	local suffix='"}'
	local line_len=$((line_bytes + ${#prefix} + ${#suffix} + 1))
	local size=0

	: > "${path}"
	if command -v python3 >/dev/null 2>&1; then
		python3 - "${path}" "${target_bytes}" "${line_bytes}" <<'PY'
import sys

path = sys.argv[1]
target = int(sys.argv[2])
line_bytes = int(sys.argv[3])
payload = "a" * line_bytes
line = ('{"pad":"' + payload + '"}\n').encode("ascii")

size = 0
with open(path, "wb") as f:
    while size + len(line) < target:
        f.write(line)
        size += len(line)
PY
		return
	fi

	while [[ "${size}" -lt "${target_bytes}" ]]; do
		printf '%s' "${prefix}" >> "${path}"
		head -c "${line_bytes}" < /dev/zero | tr '\0' 'a' >> "${path}"
		printf '%s\n' "${suffix}" >> "${path}"
		size=$((size + line_len))
	done
}

tamper_sealed_field() {
	local in_path="$1"
	local out_path="$2"
	if command -v python3 >/dev/null 2>&1; then
		python3 - "${in_path}" "${out_path}" <<'PY'
import json
import sys

in_path, out_path = sys.argv[1], sys.argv[2]
with open(in_path, "r", encoding="utf-8") as f:
    data = json.load(f)
sealed = data.get("sealed", "")
if sealed:
    last = sealed[-1]
    data["sealed"] = sealed[:-1] + ("A" if last != "A" else "B")
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(data, f)
PY
		return
	fi
	sed 's/"sealed":"\([^"]*\)"/"sealed":"\1A"/' "${in_path}" > "${out_path}"
}

run_a keygen >/dev/null
run_b keygen >/dev/null
run_c keygen >/dev/null
run_d keygen >/dev/null
PUBA="$(cat "${TMPA}/.web4mvp/pub.hex")"

contracts_path="${TMPA}/.web4mvp/contracts.jsonl"
max_bytes=$((64 * 1024 * 1024))
headroom_bytes=$((64 * 1024))
prefill_jsonl "${contracts_path}" $((max_bytes - headroom_bytes))

STATEFUL_PORT="$(pick_unique_port 42420)"
stateful_log="${TMPWORK}/stateful_recv.log"
echo "Starting QUIC stateful receiver: env HOME=${TMPA} ${WEB4_BIN} quic-listen --devtls --addr 127.0.0.1:${STATEFUL_PORT}"
env HOME="${TMPA}" "${WEB4_BIN}" quic-listen --devtls --addr "127.0.0.1:${STATEFUL_PORT}" >"${stateful_log}" 2>&1 &
STATEFUL_PID=$!
LISTENER_PIDS+=("${STATEFUL_PID}")

wait_quic_ready "${stateful_log}" "check 1 (JSONL rotation): stateful receiver did not start"
for _ in $(seq 1 20); do
	if [[ -f "${TMPA}/.web4mvp/devtls_ca.pem" ]]; then
		break
	fi
	sleep 0.05
done
if [[ ! -f "${TMPA}/.web4mvp/devtls_ca.pem" ]]; then
	fail "check 1 (JSONL rotation): missing devtls CA"
fi
NODEIDA="$(run_a node id | awk '/node_id:/ {print $2}')"
NODEIDB="$(run_b node id | awk '/node_id:/ {print $2}')"
PUBB="$(cat "${TMPB}/.web4mvp/pub.hex")"
invite_ab_check1="${TMPWORK}/invite_ab_check1.json"
run_a node invite --to "${PUBB}" --scope all --pow-bits 18 --expires 3600 > "${invite_ab_check1}"
if [[ ! -s "${invite_ab_check1}" ]]; then
	fail "check 1 (JSONL rotation): invite payload missing"
fi
run_b recv --in "${invite_ab_check1}" >/dev/null
invite_send_log="${TMPWORK}/quic_invite_send.log"
if ! ( env HOME="${TMPB}" WEB4_DISABLE_CLIENT_POOL=1 "${WEB4_BIN}" quic-send --devtls --addr "127.0.0.1:${STATEFUL_PORT}" --devtls-ca "${TMPA}/.web4mvp/devtls_ca.pem" --in "${invite_ab_check1}" >"${invite_send_log}" 2>&1 ); then
	echo "check 1 debug: invite quic-send failed"
	tail -n 200 "${invite_send_log}" || true
	fail "check 1 (JSONL rotation): invite send failed"
fi
invite_ready=0
for _ in $(seq 1 1200); do
	if grep -q "RECV INVITE OK invitee=${NODEIDB}" "${stateful_log}" 2>/dev/null; then
		invite_ready=1
		break
	fi
	sleep 0.05
done
if [[ "${invite_ready}" -ne 1 ]]; then
	echo "check 1 debug: invite not processed"
	tail -n 200 "${stateful_log}" || true
	tail -n 200 "${invite_send_log}" || true
	echo "A members:"
	run_a node members || true
	echo "A peers:"
	run_a node list || true
	echo "B members:"
	run_b node members || true
	echo "B peers:"
	run_b node list || true
	fail "check 1 (JSONL rotation): invite not processed"
fi
sender_fifo="${TMPWORK}/stateful_sender.fifo"
mkfifo "${sender_fifo}"
env HOME="${TMPB}" "${WEB4_BIN}" quic-send-secure --devtls --addr "127.0.0.1:${STATEFUL_PORT}" --devtls-ca "${TMPA}/.web4mvp/devtls_ca.pem" --to-id "${NODEIDA}" --stdin < "${sender_fifo}" >"${TMPWORK}/stateful_sender.log" 2>&1 &
SENDER_PID=$!
exec 3> "${sender_fifo}"

open_msg="${TMPWORK}/open.json"
close_msg="${TMPWORK}/close.json"
rotated=0
max_iters=400

for i in $(seq 1 "${max_iters}"); do
	run_b open --to "${PUBA}" --amount 5 --nonce "${i}" --out "${open_msg}" >/dev/null
	if ! kill -0 "${SENDER_PID}" 2>/dev/null; then
		fail "check 1 (JSONL rotation): sender exited early"
	fi
	printf '%s\n' "${open_msg}" >&3
	CID="$(run_b list | awk 'END{print $2}')"
	found=0
	for _ in $(seq 1 40); do
		if run_a list | grep -q "${CID}"; then
			found=1
			break
		fi
		sleep 0.05
	done
	if [[ "${found}" -ne 1 ]]; then
		fail "check 1 (JSONL rotation): open not received"
	fi
	run_b close --id "${CID}" --reqnonce 1 --out "${close_msg}" >/dev/null
	printf '%s\n' "${close_msg}" >&3
	if ls "${TMPA}/.web4mvp"/*.jsonl.* >/dev/null 2>&1; then
		rotated=1
		break
	fi
done

exec 3>&-
wait "${SENDER_PID}" || fail "check 1 (JSONL rotation): sender failed"
SENDER_PID=""
kill "${STATEFUL_PID}" 2>/dev/null || true
wait "${STATEFUL_PID}" 2>/dev/null || true
STATEFUL_PID=""

if [[ "${rotated}" -ne 1 ]]; then
	fail "check 1 (JSONL rotation): no rotation observed"
fi
run_a list >/dev/null
pass "check 1 (JSONL rotation)"

valid_open="${TMPWORK}/valid_open.json"
run_b open --to "${PUBA}" --amount 5 --nonce 9001 --out "${valid_open}" >/dev/null
tampered_open="${TMPWORK}/tampered_open.json"
tamper_sealed_field "${valid_open}" "${tampered_open}"

orphan_open="${TMPWORK}/orphan_open.json"
run_b open --to "${PUBA}" --amount 7 --nonce 9002 --out "${orphan_open}" >/dev/null
orphan_cid="$(run_b list | awk 'END{print $2}')"
orphan_close="${TMPWORK}/orphan_close.json"
run_b close --id "${orphan_cid}" --reqnonce 1 --out "${orphan_close}" >/dev/null

check_invalid_recv() {
	local file="$1"
	local out
	out="$(WEB4_DEBUG= HOME="${TMPA}" "${WEB4_BIN}" recv --in "${file}" 2>&1 || true)"
	printf '%s\n' "${out}" | grep -q "invalid message" || {
		fail "check 2 (recv oracle): missing generic invalid message"
	}
	if printf '%s\n' "${out}" | grep -qiE 'sig|decrypt|state|missing|nonce'; then
		fail "check 2 (recv oracle): leaked detailed reason"
	fi
}

check_invalid_recv "${tampered_open}"
check_invalid_recv "${orphan_close}"

debug_out="$(WEB4_DEBUG=1 HOME="${TMPA}" "${WEB4_BIN}" recv --in "${tampered_open}" 2>&1 || true)"
printf '%s\n' "${debug_out}" | grep -q "recv error:" || {
	fail "check 2 (recv oracle): debug detail missing"
}
pass "check 2 (recv oracle suppression)"

quic_fail() {
	echo "FAIL: $1"
	if [[ -n "${server_log:-}" && -f "${server_log}" ]]; then
		echo "QUIC server log tail:"
		tail -n 50 "${server_log}" || true
	fi
	exit 1
}

run_checked() {
	local label="$1"
	shift
	local logs=()
	local quiet=0
	while [[ "${1:-}" == "--log" ]]; do
		logs+=("$2")
		shift 2
	done
	if [[ "${1:-}" == "--quiet" ]]; then
		quiet=1
		shift
	fi
	local cmd_display=""
	if [[ "$#" -gt 0 ]]; then
		cmd_display="$(printf '%q ' "$@")"
	fi
	local out=""
	if [[ "${quiet}" -eq 1 ]]; then
		out="$("$@" 2>&1)" || {
			echo "Command failed (${label}): ${cmd_display}"
			printf '%s\n' "${out}"
			for log in "${logs[@]}"; do
				if [[ -n "${log}" && -f "${log}" ]]; then
					echo "Log tail (${log}):"
					tail -n 50 "${log}" || true
				fi
			done
			quic_fail "${label}"
		}
		return
	fi
	if ! "$@"; then
		echo "Command failed (${label}): ${cmd_display}"
		for log in "${logs[@]}"; do
			if [[ -n "${log}" && -f "${log}" ]]; then
				echo "Log tail (${log}):"
				tail -n 50 "${log}" || true
			fi
		done
		quic_fail "${label}"
	fi
}

PORT="$(pick_unique_port 42424)"

quic_msg="${TMPWORK}/quic_open.json"
run_b open --to "${PUBA}" --amount 5 --nonce 9900 --out "${quic_msg}" >/dev/null

server_log="${TMPWORK}/quic_server.log"
echo "Starting QUIC server: env HOME=${TMPA} WEB4_DISABLE_LIMITER=0 ${WEB4_BIN} quic-listen --devtls --addr 127.0.0.1:${PORT}"
env HOME="${TMPA}" WEB4_DISABLE_LIMITER=0 "${WEB4_BIN}" quic-listen --devtls --addr "127.0.0.1:${PORT}" >"${server_log}" 2>&1 &
SERVER_PID=$!
LISTENER_PIDS+=("${SERVER_PID}")

wait_quic_ready "${server_log}" "check 3 (QUIC limiter): server did not start"

listening=0
if command -v ss >/dev/null 2>&1; then
	for _ in $(seq 1 50); do
		if ss -ltnu | grep -q ":${PORT}"; then
			listening=1
			break
		fi
		sleep 0.05
	done
elif command -v lsof >/dev/null 2>&1; then
	for _ in $(seq 1 50); do
		if lsof -i ":${PORT}" >/dev/null 2>&1; then
			listening=1
			break
		fi
		sleep 0.05
	done
else
	for _ in $(seq 1 5); do
		if env HOME="${TMPB}" "${WEB4_BIN}" quic-send --devtls --addr "127.0.0.1:${PORT}" --devtls-ca "${TMPA}/.web4mvp/devtls_ca.pem" --in "${quic_msg}" >/dev/null 2>&1; then
			listening=1
			break
		fi
		sleep 0.1
	done
fi
if [[ "${listening}" -ne 1 ]]; then
	quic_fail "check 3 (QUIC limiter): server not listening"
fi

cap="$(awk -F= '/maxConnsPerIP/ {gsub(/[ \t]/,"",$2); print $2; exit}' internal/network/quic.go 2>/dev/null || true)"
cap="${cap:-4}"
total=$((cap * 3))
client_dir="${TMPWORK}/clients"
mkdir -p "${client_dir}"
pids=()
NODEIDA="$(run_a node id | awk '/node_id:/ {print $2}')"
limiter_home="${client_dir}/limiter_home"
mkdir -p "${limiter_home}"
env HOME="${limiter_home}" "${WEB4_BIN}" keygen >/dev/null 2>&1 || true
limiter_id="$(env HOME="${limiter_home}" "${WEB4_BIN}" node id | awk '/node_id:/ {print $2}')"
run_checked "check 3 (QUIC limiter): node join (A<-limiter)" --quiet run_a node join --node-id "${limiter_id}"
quic_msg_dir="${client_dir}/msgs"
mkdir -p "${quic_msg_dir}"
echo "QUIC client command: env HOME=${limiter_home} ${WEB4_BIN} quic-send-secure --devtls --addr 127.0.0.1:${PORT} --devtls-ca ${TMPA}/.web4mvp/devtls_ca.pem --to-id ${NODEIDA} --in <msg>"

for i in $(seq 1 "${total}"); do
	log="${client_dir}/client_${i}.log"
	msg="${quic_msg_dir}/open_${i}.json"
	nonce=$((9900 + i))
	env HOME="${limiter_home}" "${WEB4_BIN}" open --to "${PUBA}" --amount 5 --nonce "${nonce}" --out "${msg}" >/dev/null
	(env HOME="${limiter_home}" "${WEB4_BIN}" quic-send-secure --devtls --addr "127.0.0.1:${PORT}" --devtls-ca "${TMPA}/.web4mvp/devtls_ca.pem" --to-id "${NODEIDA}" --in "${msg}" >"${log}" 2>&1) &
	pids+=($!)
done

success=0
limited=0
for i in $(seq 1 "${total}"); do
	log="${client_dir}/client_${i}.log"
	if wait "${pids[$((i - 1))]}"; then
		success=$((success + 1))
	else
		limited=$((limited + 1))
	fi
done

if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
	quic_fail "check 3 (QUIC limiter): server exited early"
fi

if [[ "${success}" -eq 0 ]]; then
	for idx in 1 2; do
		log="${client_dir}/client_${idx}.log"
		if [[ -f "${log}" ]]; then
			echo "QUIC client_${idx} log tail:"
			tail -n 50 "${log}" || true
		fi
	done
	quic_fail "check 3 (QUIC limiter): no successful connections"
fi
if [[ "${limited}" -eq 0 ]]; then
	if grep -qiE 'rejected|per-ip limit|limit' "${server_log}"; then
		limited=1
	fi
fi
if [[ "${limited}" -eq 0 ]]; then
	quic_fail "check 3 (QUIC limiter): no limiter-triggered failures"
fi

kill "${SERVER_PID}" 2>/dev/null || true
wait "${SERVER_PID}" 2>/dev/null || true
SERVER_PID=""
pass "check 3 (QUIC per-IP limiter)"

PORT="$(pick_unique_port 42425)"

server_log="${TMPWORK}/quic_hello_server.log"
echo "Starting QUIC server: env HOME=${TMPB} ${WEB4_BIN} quic-listen --devtls --addr 127.0.0.1:${PORT}"
env HOME="${TMPB}" "${WEB4_BIN}" quic-listen --devtls --addr "127.0.0.1:${PORT}" >"${server_log}" 2>&1 &
SERVER_PID=$!
LISTENER_PIDS+=("${SERVER_PID}")

wait_quic_ready "${server_log}" "check 4 (QUIC node hello): server did not start"

for _ in $(seq 1 20); do
	if [[ -f "${TMPB}/.web4mvp/devtls_ca.pem" ]]; then
		break
	fi
	sleep 0.05
done
if [[ ! -f "${TMPB}/.web4mvp/devtls_ca.pem" ]]; then
	quic_fail "check 4 (QUIC node hello): missing devtls CA"
fi

NODEIDA="$(run_a node id | awk '/node_id:/ {print $2}')"
NODEIDB="$(run_b node id | awk '/node_id:/ {print $2}')"
run_a node hello --devtls --addr "127.0.0.1:${PORT}" --devtls-ca "${TMPB}/.web4mvp/devtls_ca.pem" --to-id "${NODEIDB}" >/dev/null

found=0
for _ in $(seq 1 40); do
	if run_b node list | grep -q "${NODEIDA}"; then
		found=1
		break
	fi
	sleep 0.05
done
if [[ "${found}" -ne 1 ]]; then
	quic_fail "check 4 (QUIC node hello): peer not recorded"
fi

kill "${SERVER_PID}" 2>/dev/null || true
wait "${SERVER_PID}" 2>/dev/null || true
SERVER_PID=""
pass "check 4 (QUIC node hello)"

PORT="$(pick_unique_port 42426)"
PORTB="$(pick_unique_port 42427)"
PORTC="$(pick_unique_port 42428)"
PORTA_HELLO="$(pick_unique_port 42429)"
PORTD="$(pick_unique_port 42430)"
while [[ "${PORTD}" == "${PORTB}" || "${PORTD}" == "${PORTC}" || "${PORTD}" == "${PORTA_HELLO}" ]]; do
	PORTD="$(pick_port 42430)"
done

mkdir -p "${TMPC}/.web4mvp"
if [[ ! -f "${TMPC}/.web4mvp/pub.hex" ]]; then
	env HOME="${TMPC}" "${WEB4_BIN}" keygen >/dev/null
fi
PUBC="$(cat "${TMPC}/.web4mvp/pub.hex")"
NODEIDC="$(run_c node id | awk '/node_id:/ {print $2}')"
PEER_ADDR="127.0.0.1:${PORTC}"
printf '{"node_id":"%s","pubkey":"%s","addr":"%s"}\n' "${NODEIDC}" "${PUBC}" "${PEER_ADDR}" >> "${TMPA}/.web4mvp/peers.jsonl"

PORTB_HELLO="$(pick_unique_port 12334)"

server_log_b_hello="${TMPWORK}/quic_b_hello.log"
echo "Starting QUIC server B (hello): env HOME=${TMPB} ${WEB4_BIN} quic-listen --devtls --addr 127.0.0.1:${PORTB_HELLO}"
env HOME="${TMPB}" "${WEB4_BIN}" quic-listen --devtls --addr "127.0.0.1:${PORTB_HELLO}" >"${server_log_b_hello}" 2>&1 &
SERVER_PID_B=$!
LISTENER_PIDS+=("${SERVER_PID_B}")

wait_quic_ready "${server_log_b_hello}" "check 5 (QUIC peer exchange): B hello server did not start"

for _ in $(seq 1 20); do
	if [[ -f "${TMPB}/.web4mvp/devtls_ca.pem" ]]; then
		break
	fi
	sleep 0.05
done
if [[ ! -f "${TMPB}/.web4mvp/devtls_ca.pem" ]]; then
	quic_fail "check 5 (QUIC peer exchange): missing devtls CA"
fi

run_checked "check 5 (QUIC peer exchange): node add" --log "${server_log_b_hello}" --quiet run_b node add --addr "127.0.0.1:${PORT}"
NODEIDB="$(run_b node id | awk '/node_id:/ {print $2}')"
run_checked "check 5 (QUIC peer exchange): node hello (A->B)" --log "${server_log_b_hello}" --quiet run_a node hello --devtls --addr "127.0.0.1:${PORTB_HELLO}" --devtls-ca "${TMPB}/.web4mvp/devtls_ca.pem" --to-id "${NODEIDB}"

kill "${SERVER_PID_B}" 2>/dev/null || true
wait "${SERVER_PID_B}" 2>/dev/null || true
SERVER_PID_B=""

server_log="${TMPWORK}/quic_exchange_server.log"
echo "Starting QUIC server: env HOME=${TMPA} ${WEB4_BIN} quic-listen --devtls --addr 127.0.0.1:${PORT}"
env HOME="${TMPA}" "${WEB4_BIN}" quic-listen --devtls --addr "127.0.0.1:${PORT}" >"${server_log}" 2>&1 &
SERVER_PID=$!
LISTENER_PIDS+=("${SERVER_PID}")

wait_quic_ready "${server_log}" "check 5 (QUIC peer exchange): server did not start"

for _ in $(seq 1 20); do
	if [[ -f "${TMPA}/.web4mvp/devtls_ca.pem" ]]; then
		break
	fi
	sleep 0.05
done
if [[ ! -f "${TMPA}/.web4mvp/devtls_ca.pem" ]]; then
	quic_fail "check 5 (QUIC peer exchange): missing devtls CA"
fi

before_count="$(run_b node list | wc -l | tr -d ' ')"
NODEIDA="$(run_a node id | awk '/node_id:/ {print $2}')"
run_checked "check 5 (QUIC peer exchange): node hello (B->A)" --log "${server_log}" --quiet run_b node hello --devtls --addr "127.0.0.1:${PORT}" --devtls-ca "${TMPA}/.web4mvp/devtls_ca.pem" --to-id "${NODEIDA}"
NODEIDB="$(run_b node id | awk '/node_id:/ {print $2}')"
found=0
for _ in $(seq 1 60); do
	if run_a node list | grep -q "${NODEIDB}"; then
		found=1
		break
	fi
	sleep 0.05
done
if [[ "${found}" -ne 1 ]]; then
	quic_fail "check 5 (QUIC peer exchange): peer hello not recorded"
fi
run_checked "check 5 (QUIC peer exchange): node exchange (B->A)" --log "${server_log}" --quiet run_b node exchange --devtls --addr "127.0.0.1:${PORT}" --devtls-ca "${TMPA}/.web4mvp/devtls_ca.pem" --to-id "${NODEIDA}" --k 16

found=0
for _ in $(seq 1 40); do
	if run_b node list | grep -q "${NODEIDC}"; then
		found=1
		break
	fi
	sleep 0.05
done
if [[ "${found}" -ne 1 ]]; then
	quic_fail "check 5 (QUIC peer exchange): peer not recorded"
fi
after_count="$(run_b node list | wc -l | tr -d ' ')"
if [[ "${after_count}" -le "${before_count}" ]]; then
	quic_fail "check 5 (QUIC peer exchange): peer count did not increase"
fi

kill "${SERVER_PID}" 2>/dev/null || true
wait "${SERVER_PID}" 2>/dev/null || true
SERVER_PID=""
pass "check 5 (QUIC peer exchange)"

PORT_PAY="$(pick_unique_port 42431)"
server_log_pay="${TMPWORK}/quic_pay_server.log"
NODEIDA="$(run_a node id | awk '/node_id:/ {print $2}')"
NODEIDB="$(run_b node id | awk '/node_id:/ {print $2}')"
PUBA="$(cat "${TMPA}/.web4mvp/pub.hex")"
PUBB="$(cat "${TMPB}/.web4mvp/pub.hex")"
rm -f "${TMPA}/.web4mvp/members.jsonl" "${TMPB}/.web4mvp/members.jsonl" 2>/dev/null || true
printf '{"node_id":"%s","scope":3}\n' "${NODEIDA}" > "${TMPA}/.web4mvp/members.jsonl"
printf '{"node_id":"%s","scope":3}\n' "${NODEIDB}" >> "${TMPA}/.web4mvp/members.jsonl"
printf '{"node_id":"%s","scope":3}\n' "${NODEIDA}" > "${TMPB}/.web4mvp/members.jsonl"
printf '{"node_id":"%s","scope":3}\n' "${NODEIDB}" >> "${TMPB}/.web4mvp/members.jsonl"
printf '{"node_id":"%s","pubkey":"%s","addr":"127.0.0.1:%s"}\n' "${NODEIDA}" "${PUBA}" "${PORT_PAY}" >> "${TMPB}/.web4mvp/peers.jsonl"

echo "Starting QUIC server (wallet pay): env HOME=${TMPA} WEB4_DELTA_MODE=deltab WEB4_ZK_MODE=1 ${WEB4_NODE_BIN} run --devtls --addr 127.0.0.1:${PORT_PAY}"
env HOME="${TMPA}" WEB4_DELTA_MODE=deltab WEB4_ZK_MODE=1 "${WEB4_NODE_BIN}" run --devtls --addr "127.0.0.1:${PORT_PAY}" >"${server_log_pay}" 2>&1 &
SERVER_PID=$!
LISTENER_PIDS+=("${SERVER_PID}")
server_log="${server_log_pay}"

wait_quic_ready "${server_log_pay}" "check 5b (wallet pay): server did not start"

for _ in $(seq 1 20); do
	if [[ -f "${TMPA}/.web4mvp/devtls_ca.pem" ]]; then
		break
	fi
	sleep 0.05
done
if [[ ! -f "${TMPA}/.web4mvp/devtls_ca.pem" ]]; then
	quic_fail "check 5b (wallet pay): missing devtls CA"
fi

pay_log="${TMPWORK}/wallet_pay.log"
if ! ( env HOME="${TMPB}" WEB4_DELTA_MODE=deltab WEB4_ZK_MODE=1 "${WEB4_NODE_BIN}" pay --to "${NODEIDA}" --amount 5 --send --devtls --devtls-ca "${TMPA}/.web4mvp/devtls_ca.pem" >"${pay_log}" 2>&1 ); then
	tail -n 200 "${pay_log}" 2>/dev/null || true
	quic_fail "check 5b (wallet pay): pay failed"
fi

found=0
for _ in $(seq 1 30); do
	if [[ -f "${TMPA}/.web4mvp/metrics.json" ]] && grep -Eq '"verified":[[:space:]]*[1-9]' "${TMPA}/.web4mvp/metrics.json"; then
		found=1
		break
	fi
	sleep 0.1
done
if [[ "${found}" -ne 1 ]]; then
	quic_fail "check 5b (wallet pay): delta_b not observed"
fi

kill "${SERVER_PID}" 2>/dev/null || true
wait "${SERVER_PID}" 2>/dev/null || true
SERVER_PID=""
pass "check 5b (wallet pay delta_b)"

PORT_SCOPE="$(pick_unique_port 42431)"

rm -f "${TMPA}/.web4mvp/members.jsonl"* "${TMPB}/.web4mvp/members.jsonl"* 2>/dev/null || true

server_log_scope_a="${TMPWORK}/quic_scope_server_a.log"
server_log_scope_b="${TMPWORK}/quic_scope_server_b.log"
gossip_push_log="${TMPWORK}/scope_gossip_push.log"
echo "Starting QUIC server (scope+revoke): env HOME=${TMPA} WEB4_DEBUG=1 WEB4_CHECK6_ACK=1 ${WEB4_BIN} quic-listen --devtls --addr 127.0.0.1:${PORT_SCOPE}"
env HOME="${TMPA}" WEB4_DEBUG=1 WEB4_CHECK6_ACK=1 "${WEB4_BIN}" quic-listen --devtls --addr "127.0.0.1:${PORT_SCOPE}" >"${server_log_scope_a}" 2>&1 &
SERVER_PID_SCOPE=$!
LISTENER_PIDS+=("${SERVER_PID_SCOPE}")
server_log="${server_log_scope_a}"
scope_debug_dump() {
	local reason="$1"
	echo "check 6b debug: ${reason}"
	if [[ -f "${server_log_scope_a}" ]]; then
		echo "scope server A log tail:"
		tail -n 200 "${server_log_scope_a}" || true
	fi
	if [[ -f "${server_log_scope_b}" ]]; then
		echo "scope server B log tail:"
		tail -n 200 "${server_log_scope_b}" || true
	fi
	if [[ -f "${gossip_push_log}" ]]; then
		echo "gossip push client log tail:"
		tail -n 200 "${gossip_push_log}" || true
	fi
	echo "A members:"
	run_a node members || true
	echo "A peers:"
	run_a node list || true
	echo "B members:"
	run_b node members || true
	echo "B peers:"
	run_b node list || true
	echo "A peers.jsonl tail:"
	tail -n 50 "${TMPA}/.web4mvp/peers.jsonl" 2>/dev/null || true
	echo "B peers.jsonl tail:"
	tail -n 50 "${TMPB}/.web4mvp/peers.jsonl" 2>/dev/null || true
	echo "scope log grep (scope/missing scope/unknown sender/peer resolve):"
	grep -nE "scope|missing scope|unknown sender|peer resolve" "${server_log_scope_a}" "${server_log_scope_b}" 2>/dev/null || true
}

wait_quic_ready "${server_log_scope_a}" "check 6b (scope+revoke): server did not start"

for _ in $(seq 1 20); do
	if [[ -f "${TMPA}/.web4mvp/devtls_ca.pem" ]]; then
		break
	fi
	sleep 0.05
done
if [[ ! -f "${TMPA}/.web4mvp/devtls_ca.pem" ]]; then
	scope_debug_dump "missing devtls CA"
	server_log="${server_log_scope_a}"
	quic_fail "check 6b (scope+revoke): missing devtls CA"
fi

NODEIDA="$(run_a node id | awk '/node_id:/ {print $2}')"
NODEIDB="$(run_b node id | awk '/node_id:/ {print $2}')"
PUBA="$(cat "${TMPA}/.web4mvp/pub.hex")"
PUBB="$(cat "${TMPB}/.web4mvp/pub.hex")"

run_checked "check 6b (scope+revoke): node hello (B->A)" --log "${server_log_scope_a}" --quiet run_b node hello --devtls --addr "127.0.0.1:${PORT_SCOPE}" --devtls-ca "${TMPA}/.web4mvp/devtls_ca.pem" --to-id "${NODEIDA}"
printf '{"node_id":"%s","pubkey":"%s","addr":"%s"}\n' "${NODEIDA}" "${PUBA}" "127.0.0.1:${PORT_SCOPE}" >> "${TMPB}/.web4mvp/peers.jsonl"
peer_seeded=0
for _ in $(seq 1 40); do
	if grep -q "127.0.0.1:${PORT_SCOPE}" "${TMPB}/.web4mvp/peers.jsonl" 2>/dev/null; then
		peer_seeded=1
		break
	fi
	sleep 0.05
done
if [[ "${peer_seeded}" -ne 1 ]]; then
	scope_debug_dump "B missing A addr mapping"
	server_log="${server_log_scope_a}"
	quic_fail "check 6b (scope+revoke): peer seed missing on B"
fi

invite_ab_gossip="${TMPWORK}/invite_ab_gossip.json"
run_checked "check 6b (scope+revoke): invite gossip scope" --quiet bash -c "HOME='${TMPA}' '${WEB4_BIN}' node invite --to '${PUBB}' --scope gossip --pow-bits 18 --expires 3600 > '${invite_ab_gossip}'"
invite_send_log="${TMPWORK}/scope_invite_gossip_send.log"
if ! ( env HOME="${TMPB}" WEB4_DISABLE_CLIENT_POOL=1 "${WEB4_BIN}" quic-send --devtls --addr "127.0.0.1:${PORT_SCOPE}" --devtls-ca "${TMPA}/.web4mvp/devtls_ca.pem" --in "${invite_ab_gossip}" >"${invite_send_log}" 2>&1 ); then
	tail -n 200 "${invite_send_log}" || true
	scope_debug_dump "invite gossip send failed"
	server_log="${server_log_scope_a}"
	quic_fail "check 6b (scope+revoke): invite gossip send failed"
fi
invite_gossip_ok=0
for _ in $(seq 1 80); do
	if grep -q "RECV INVITE OK invitee=${NODEIDB}.*scope=1" "${server_log_scope_a}" 2>/dev/null; then
		invite_gossip_ok=1
		break
	fi
	sleep 0.05
done
if [[ "${invite_gossip_ok}" -ne 1 ]]; then
	scope_debug_dump "invite gossip not accepted"
	server_log="${server_log_scope_a}"
	quic_fail "check 6b (scope+revoke): invite gossip not accepted"
fi

gossip_hello_scope="${TMPWORK}/gossip_hello_scope.json"
run_checked "check 6b (scope+revoke): hello payload for gossip" --quiet run_b node hello --to-id "${NODEIDA}" --out "${gossip_hello_scope}"
set +e
gossip_out="$(WEB4_CHECK6_ACK=1 run_b gossip push --devtls --addr "127.0.0.1:${PORT_SCOPE}" --devtls-ca "${TMPA}/.web4mvp/devtls_ca.pem" --in "${gossip_hello_scope}" 2>&1)"
gossip_status=$?
set -e
printf '%s\n' "${gossip_out}" > "${gossip_push_log}"
if [[ "${gossip_status}" -ne 0 ]]; then
	scope_debug_dump "gossip push failed"
	server_log="${server_log_scope_a}"
	quic_fail "check 6b (scope+revoke): gossip push failed"
fi
if ! grep -q "GOSSIP_ACK status=ok" "${gossip_push_log}" 2>/dev/null; then
	scope_debug_dump "gossip push not accepted"
	server_log="${server_log_scope_a}"
	quic_fail "check 6b (scope+revoke): gossip push not accepted"
fi

open1="${TMPWORK}/scope_open1.json"
run_checked "check 6b (scope+revoke): open (gossip-only)" --quiet run_b open --to "${PUBA}" --amount 7 --nonce 9001 --out "${open1}"
CID1="$(run_b list | awk 'END{print $2}')"
open1_send_log="${TMPWORK}/scope_open1_send.log"
if ! ( env HOME="${TMPB}" WEB4_DISABLE_CLIENT_POOL=1 "${WEB4_BIN}" quic-send-secure --devtls --addr "127.0.0.1:${PORT_SCOPE}" --devtls-ca "${TMPA}/.web4mvp/devtls_ca.pem" --to-id "${NODEIDA}" --in "${open1}" >"${open1_send_log}" 2>&1 ); then
	tail -n 200 "${open1_send_log}" || true
	scope_debug_dump "secure send failed (open1)"
	server_log="${server_log_scope_a}"
	quic_fail "check 6b (scope+revoke): secure send failed"
fi
found=0
for _ in $(seq 1 40); do
	if run_a list | grep -q "${CID1}"; then
		found=1
		break
	fi
	sleep 0.05
done
if [[ "${found}" -eq 1 ]]; then
	scope_debug_dump "contract accepted without contract scope"
	server_log="${server_log_scope_a}"
	quic_fail "check 6b (scope+revoke): contract accepted without contract scope"
fi

invite_ab_contract="${TMPWORK}/invite_ab_contract.json"
run_checked "check 6b (scope+revoke): invite contract scope" --quiet bash -c "HOME='${TMPA}' '${WEB4_BIN}' node invite --to '${PUBB}' --scope contract --pow-bits 18 --expires 3600 > '${invite_ab_contract}'"
invite_contract_send_log="${TMPWORK}/scope_invite_contract_send.log"
if ! ( env HOME="${TMPB}" WEB4_DISABLE_CLIENT_POOL=1 "${WEB4_BIN}" quic-send --devtls --addr "127.0.0.1:${PORT_SCOPE}" --devtls-ca "${TMPA}/.web4mvp/devtls_ca.pem" --in "${invite_ab_contract}" >"${invite_contract_send_log}" 2>&1 ); then
	tail -n 200 "${invite_contract_send_log}" || true
	scope_debug_dump "invite contract send failed"
	server_log="${server_log_scope_a}"
	quic_fail "check 6b (scope+revoke): invite contract send failed"
fi
invite_contract_ok=0
for _ in $(seq 1 80); do
	if grep -q "RECV INVITE OK invitee=${NODEIDB}.*scope=2" "${server_log_scope_a}" 2>/dev/null; then
		invite_contract_ok=1
		break
	fi
	sleep 0.05
done
if [[ "${invite_contract_ok}" -ne 1 ]]; then
	scope_debug_dump "invite contract not accepted"
	server_log="${server_log_scope_a}"
	quic_fail "check 6b (scope+revoke): invite contract not accepted"
fi

open2="${TMPWORK}/scope_open2.json"
run_checked "check 6b (scope+revoke): open (contract scope)" --quiet run_b open --to "${PUBA}" --amount 9 --nonce 9002 --out "${open2}"
CID2="$(run_b list | awk 'END{print $2}')"
open2_send_log="${TMPWORK}/scope_open2_send.log"
if ! ( env HOME="${TMPB}" WEB4_DISABLE_CLIENT_POOL=1 "${WEB4_BIN}" quic-send-secure --devtls --addr "127.0.0.1:${PORT_SCOPE}" --devtls-ca "${TMPA}/.web4mvp/devtls_ca.pem" --to-id "${NODEIDA}" --in "${open2}" >"${open2_send_log}" 2>&1 ); then
	tail -n 200 "${open2_send_log}" || true
	scope_debug_dump "secure send failed (open2)"
	server_log="${server_log_scope_a}"
	quic_fail "check 6b (scope+revoke): secure send failed"
fi
accepted=0
for _ in $(seq 1 80); do
	if run_a list | grep -q "${CID2}"; then
		accepted=1
		break
	fi
	sleep 0.05
done
if [[ "${accepted}" -ne 1 ]]; then
	scope_debug_dump "contract not accepted after upgrade"
	server_log="${server_log_scope_a}"
	quic_fail "check 6b (scope+revoke): contract not accepted after upgrade"
fi

revoke_ab="${TMPWORK}/revoke_ab.json"
run_checked "check 6b (scope+revoke): revoke" --quiet bash -c "HOME='${TMPA}' '${WEB4_BIN}' node revoke --to '${NODEIDB}' --reason 'smoke' > '${revoke_ab}'"
revoke_send_log="${TMPWORK}/scope_revoke_send.log"
if ! ( env HOME="${TMPB}" WEB4_DISABLE_CLIENT_POOL=1 "${WEB4_BIN}" quic-send --devtls --addr "127.0.0.1:${PORT_SCOPE}" --devtls-ca "${TMPA}/.web4mvp/devtls_ca.pem" --in "${revoke_ab}" >"${revoke_send_log}" 2>&1 ); then
	tail -n 200 "${revoke_send_log}" || true
	scope_debug_dump "revoke send failed"
	server_log="${server_log_scope_a}"
	quic_fail "check 6b (scope+revoke): revoke send failed"
fi

open3="${TMPWORK}/scope_open3.json"
run_checked "check 6b (scope+revoke): open (revoked)" --quiet run_b open --to "${PUBA}" --amount 11 --nonce 9003 --out "${open3}"
CID3="$(run_b list | awk 'END{print $2}')"
open3_send_log="${TMPWORK}/scope_open3_send.log"
if ! ( env HOME="${TMPB}" WEB4_DISABLE_CLIENT_POOL=1 "${WEB4_BIN}" quic-send-secure --devtls --addr "127.0.0.1:${PORT_SCOPE}" --devtls-ca "${TMPA}/.web4mvp/devtls_ca.pem" --to-id "${NODEIDA}" --in "${open3}" >"${open3_send_log}" 2>&1 ); then
	tail -n 200 "${open3_send_log}" || true
	scope_debug_dump "secure send failed (open3)"
	server_log="${server_log_scope_a}"
	quic_fail "check 6b (scope+revoke): secure send failed"
fi
found=0
for _ in $(seq 1 40); do
	if run_a list | grep -q "${CID3}"; then
		found=1
		break
	fi
	sleep 0.05
done
if [[ "${found}" -eq 1 ]]; then
	scope_debug_dump "contract accepted after revoke"
	server_log="${server_log_scope_a}"
	quic_fail "check 6b (scope+revoke): contract accepted after revoke"
fi

kill "${SERVER_PID_SCOPE}" 2>/dev/null || true
wait "${SERVER_PID_SCOPE}" 2>/dev/null || true
SERVER_PID_SCOPE=""
pass "check 6b (scope + revoke)"

(
	check6_apply_env_defaults
	CHECK6_FAIL_EXIT=0
	CHECK6_SUMMARY_ON_FAIL=1
	CHECK6_PHASE=""
	CHECK6_ADDR_A=""
	CHECK6_ADDR_B=""
	CHECK6_ADDR_C=""

	check6_cleanup() {
		if [[ -n "${SERVER_PID_A:-}" ]]; then
			kill "${SERVER_PID_A}" 2>/dev/null || true
			wait "${SERVER_PID_A}" 2>/dev/null || true
			SERVER_PID_A=""
		fi
		if [[ -n "${SERVER_PID_B:-}" ]]; then
			kill "${SERVER_PID_B}" 2>/dev/null || true
			wait "${SERVER_PID_B}" 2>/dev/null || true
			SERVER_PID_B=""
		fi
		if [[ -n "${SERVER_PID_C:-}" ]]; then
			kill "${SERVER_PID_C}" 2>/dev/null || true
			wait "${SERVER_PID_C}" 2>/dev/null || true
			SERVER_PID_C=""
		fi
	}
	trap check6_cleanup EXIT
	check6_quic_fail() {
		local reason="$1"
		local msg="$2"
		check6_fail "${reason}" "${msg}"
		quic_fail "${msg}"
	}

	server_log_a="${TMPWORK}/quic_gossip_a.log"
	server_log_b="${TMPWORK}/quic_gossip_b.log"
	server_log_c="${TMPWORK}/quic_gossip_c.log"
	server_log="${server_log_b}"
	if [[ "${WEB4_CHECK6_DEBUG:-0}" == "1" ]]; then
		echo "CHECK6_LIB_SOURCED=1"
		type -t pick_n_ports >/dev/null || { echo "MISSING pick_n_ports"; exit 1; }
	fi
	ports="$(pick_n_ports 3)" || {
		echo "CHECK6_FAIL reason=bad_port phase=servers_start details=\"pick_n_ports rc=$?\""
		exit 1
	}
	if [[ "${WEB4_CHECK6_DEBUG:-0}" == "1" ]]; then
		echo "CHECK6_PICKED_PORTS raw='${ports}'"
	fi
	read -r PORTA_HELLO PORTB PORTC <<<"${ports}"
	if [[ -z "${PORTA_HELLO}" || -z "${PORTB}" || -z "${PORTC}" ]]; then
		echo "CHECK6_FAIL reason=bad_port phase=servers_start details=\"empty ports after read\""
		exit 1
	fi
	if ! [[ "${PORTA_HELLO}" =~ ^[0-9]+$ && "${PORTB}" =~ ^[0-9]+$ && "${PORTC}" =~ ^[0-9]+$ ]]; then
		echo "CHECK6_FAIL reason=bad_port phase=servers_start details=\"port selection failed\""
		check6_env_summary
		exit 1
	fi
	HOME_A="${TMPA}"
	HOME_B="${TMPB}"
	HOME_C="${TMPC}"
	export HOME_A HOME_B HOME_C
	a_addr="127.0.0.1:${PORTA_HELLO}"
	b_addr="127.0.0.1:${PORTB}"
	c_addr="127.0.0.1:${PORTC}"
	CHECK6_ADDR_A="${a_addr}"
	CHECK6_ADDR_B="${b_addr}"
	CHECK6_ADDR_C="${c_addr}"
	CA_A="${HOME_A}/.web4mvp/devtls_ca.pem"
	CA_B="${HOME_B}/.web4mvp/devtls_ca.pem"
	CA_C="${HOME_C}/.web4mvp/devtls_ca.pem"
	export CA_A CA_B CA_C
	if [[ "${WEB4_CHECK6_DEBUG:-0}" == "1" ]]; then
		echo "CHECK6_PORTS porta=${PORTA_HELLO} portb=${PORTB} portc=${PORTC}"
		echo "CHECK6_HOMES a=${HOME_A} b=${HOME_B} c=${HOME_C}"
		echo "CHECK6_CAS ca_a=${CA_A} ca_b=${CA_B} ca_c=${CA_C}"
		echo "CHECK6_ADDRS a=${a_addr} b=${b_addr} c=${c_addr}"
	fi
	if [[ -z "${PORTB}" || -z "${PORTC}" ]]; then
		echo "CHECK6_FAIL reason=bad_port phase=servers_start details=\"empty PORTB/PORTC\""
		check6_env_summary
		exit 1
	fi
	if ! check6_must_addr "${b_addr}" || ! check6_must_addr "${c_addr}"; then
		echo "CHECK6_FAIL reason=bad_addr phase=servers_start details=\"empty port for B/C\""
		check6_env_summary
		exit 1
	fi
	echo "Starting QUIC server A (hello): env HOME=${HOME_A} ${WEB4_BIN} quic-listen --devtls --addr ${a_addr}"
	env HOME="${HOME_A}" "${WEB4_BIN}" quic-listen --devtls --addr "${a_addr}" >"${server_log_a}" 2>&1 &
	SERVER_PID_A=$!
	LISTENER_PIDS+=("${SERVER_PID_A}")
	echo "Starting QUIC server B: env HOME=${HOME_B} ${WEB4_BIN} quic-listen --devtls --addr ${b_addr}"
	env HOME="${HOME_B}" WEB4_GOSSIP_FANOUT=2 WEB4_GOSSIP_TTL_HOPS=3 "${WEB4_BIN}" quic-listen --devtls --addr "${b_addr}" >"${server_log_b}" 2>&1 &
	SERVER_PID_B=$!
	LISTENER_PIDS+=("${SERVER_PID_B}")
	echo "Starting QUIC server C: env HOME=${HOME_C} ${WEB4_BIN} quic-listen --devtls --addr ${c_addr}"
	env HOME="${HOME_C}" "${WEB4_BIN}" quic-listen --devtls --addr "${c_addr}" >"${server_log_c}" 2>&1 &
	SERVER_PID_C=$!
	LISTENER_PIDS+=("${SERVER_PID_C}")

	check6_wait_ready "${server_log_a}" || { check6_quic_fail "listen_error" "check 6 (gossip forward): server A did not start"; }
	check6_wait_ready "${server_log_b}" || { check6_quic_fail "listen_error" "check 6 (gossip forward): server B did not start"; }
	check6_wait_ready "${server_log_c}" || { check6_quic_fail "listen_error" "check 6 (gossip forward): server C did not start"; }
	a_addr="$(check6_extract_ready_addr "${server_log_a}")"
	b_addr="$(check6_extract_ready_addr "${server_log_b}")"
	c_addr="$(check6_extract_ready_addr "${server_log_c}")"
	if [[ -z "${a_addr}" || -z "${b_addr}" || -z "${c_addr}" ]]; then
		check6_quic_fail "listen_error" "check 6 (gossip forward): server did not start"
	fi
	CHECK6_ADDR_A="${a_addr}"
	CHECK6_ADDR_B="${b_addr}"
	CHECK6_ADDR_C="${c_addr}"

	for home_label in A B C; do
		ca_var="CA_${home_label}"
		ca_path="${!ca_var}"
		if [[ ! -f "${ca_path}" ]]; then
			echo "CHECK6_FAIL reason=missing_ca phase=servers_start details=\"CA not found for ${home_label}\""
			check6_env_summary
			exit 1
		fi
	done
	check6_phase_mark "servers_ready"

	PUBC="$(cat "${TMPC}/.web4mvp/pub.hex")"
	NODEIDC="$(run_c node id | awk '/node_id:/ {print $2}')"
	NODEIDA="$(run_a node id | awk '/node_id:/ {print $2}')"
	NODEIDB="$(run_b node id | awk '/node_id:/ {print $2}')"

	# Seed A's peer store so gossip push can resolve B's pubkey+addr
	PUBB="$(cat "${TMPB}/.web4mvp/pub.hex")"
	printf '{"node_id":"%s","pubkey":"%s","addr":"%s"}\n' "${NODEIDB}" "${PUBB}" "${b_addr}" >> "${TMPA}/.web4mvp/peers.jsonl"
	found=0
	for _ in $(seq 1 20); do
		if grep -q "${NODEIDB}" "${TMPA}/.web4mvp/peers.jsonl" && grep -q "${b_addr}" "${TMPA}/.web4mvp/peers.jsonl"; then
			found=1
			break
		fi
		sleep 0.05
	done
	if [[ "${found}" -ne 1 ]]; then
		check6_quic_fail "no_conn" "check 6 (gossip forward): peer seed missing on A"
	fi

	# forward precondition: B must know C (addr+pubkey)
	run_checked "check 6: learn C on B" --log "${server_log_c}" --quiet run_b node hello --devtls --addr "${c_addr}" --devtls-ca "${CA_C}" --to-id "${NODEIDC}"
	run_checked "check 6: learn B on C" --log "${server_log_b}" --quiet run_c node hello --devtls --addr "${b_addr}" --devtls-ca "${CA_B}" --to-id "${NODEIDB}"

	# Build peer mappings first so B learns C's pubkey+addr and vice versa
	run_checked "check 6 (gossip forward): node hello (A->B)" --log "${server_log_b}" --quiet run_a node hello --devtls --addr "${b_addr}" --devtls-ca "${CA_B}" --to-id "${NODEIDB}" --advertise-addr "${a_addr}"
	run_checked "check 6 (gossip forward): node hello (C->B)" --log "${server_log_b}" --quiet run_c node hello --devtls --addr "${b_addr}" --devtls-ca "${CA_B}" --to-id "${NODEIDB}" --advertise-addr "${c_addr}"
	run_checked "check 6 (gossip forward): node hello (B->C)" --log "${server_log_c}" --quiet run_b node hello --devtls --addr "${c_addr}" --devtls-ca "${CA_C}" --to-id "${NODEIDC}"

	# Wait until B knows A and C identities
	found=0
	for _ in $(seq 1 60); do
		if run_b node list | grep -q "${NODEIDA}" && run_b node list | grep -q "${NODEIDC}"; then
			found=1
			break
		fi
		sleep 0.05
	done
	if [[ "${found}" -ne 1 ]]; then
		check6_quic_fail "no_conn" "check 6 (gossip forward): peer hello missing on B"
	fi
	# Wait until C knows B identity (needed for membership gate on receive)
	found=0
	for _ in $(seq 1 60); do
		if run_c node list | grep -q "${NODEIDB}"; then
			found=1
			break
		fi
		sleep 0.05
	done
	if [[ "${found}" -ne 1 ]]; then
		check6_quic_fail "no_conn" "check 6 (gossip forward): peer hello missing on C"
	fi
	wait_for_member_b_c() {
		local deadline=$((SECONDS + 30))
		while [[ "${SECONDS}" -lt "${deadline}" ]]; do
			if run_b node list | grep -q "${NODEIDC}"; then
				if awk -v id="${NODEIDC}" -v pub="${PUBC}" -v addr="${c_addr}" '$0 ~ id && $0 ~ pub && $0 ~ addr {found=1} END {exit !found}' "${TMPB}/.web4mvp/peers.jsonl"; then
					return 0
				fi
			fi
			sleep 0.2
		done
		return 1
	}
	# Precondition gate: B must already know C addr+pubkey before forward.
	check6_phase_mark "pre_forward"
	if ! wait_for_member_b_c; then
		if [[ "${WEB4_CHECK6_DEBUG:-0}" == "1" ]]; then
			node_list_summary="$(run_b node list | tr '\n' ' ' | tr -s ' ' | sed 's/ $//')"
			echo "check 6 debug: B node list=${node_list_summary}"
		fi
		echo "CHECK6_FAIL reason=missing_member phase=pre_forward details=\"B missing C addr/pubkey\""
		check6_env_summary
		exit 1
	fi
	# Ensure addr->node_id mapping points to C's identity based on latest JSONL entry
	found=0
	for _ in $(seq 1 60); do
		if tac "${TMPB}/.web4mvp/peers.jsonl" | awk -v addr="${c_addr}" -v id="${NODEIDC}" '
			$0 ~ addr {found=1; if ($0 ~ id) ok=1; exit}
			END {exit !(found && ok)}
		'; then
			found=1
			break
		fi
		sleep 0.05
	done
	if [[ "${found}" -ne 1 ]]; then
		check6_quic_fail "no_conn" "check 6 (gossip forward): B addr mapping mismatch for C"
		check6_quic_fail "no_conn" "grep \"${c_addr}\" -n \"${TMPB}/.web4mvp/peers.jsonl\" | tail -n 20"
	fi
	check6_phase_mark "hello_done"

	# Club gate: membership must be set before gossip is accepted/forwarded
	run_checked "check 6 (gossip forward): node join (B<-A)" --quiet run_b node join --node-id "${NODEIDA}"
	run_checked "check 6 (gossip forward): node join (B<-C)" --quiet run_b node join --node-id "${NODEIDC}"
	run_checked "check 6 (gossip forward): node join (B<-B)" --quiet run_b node join --node-id "${NODEIDB}"
	invite_ab="${TMPWORK}/invite_ab.json"
	run_checked "check 6 (gossip forward): invite cert (A->B)" --quiet bash -c "HOME='${TMPA}' '${WEB4_BIN}' node invite --to '${PUBB}' --scope gossip --pow-bits 18 --expires 3600 > '${invite_ab}'"
	if [[ ! -s "${invite_ab}" ]]; then
		check6_quic_fail "no_conn" "check 6 (gossip forward): invite payload missing"
	fi
	invite_send_log="${TMPWORK}/quic_invite_c_send.log"
	if ! ( env HOME="${TMPA}" WEB4_DISABLE_CLIENT_POOL=1 "${WEB4_BIN}" quic-send --devtls --addr "${c_addr}" --devtls-ca "${CA_C}" --in "${invite_ab}" >"${invite_send_log}" 2>&1 ); then
		echo "check 6 debug: invite quic-send failed"
		tail -n 200 "${invite_send_log}" || true
		check6_quic_fail "no_conn" "check 6 (gossip forward): invite send failed"
	fi
	found=0
	for _ in $(seq 1 1200); do
		if grep -q "RECV INVITE OK invitee=${NODEIDB}" "${server_log_c}" 2>/dev/null; then
			found=1
			break
		fi
		sleep 0.05
	done
	if [[ "${found}" -ne 1 ]]; then
		echo "check 6 debug: invite not processed"
		tail -n 200 "${server_log_c}" || true
		tail -n 200 "${invite_send_log}" || true
		echo "C members:"
		run_c node members || true
		echo "C peers:"
		run_c node list || true
		check6_quic_fail "no_conn" "check 6 (gossip forward): invite missing on C"
	fi
	run_checked "check 6 (gossip forward): node join (C<-C)" --quiet run_c node join --node-id "${NODEIDC}"

	if [[ "${WEB4_CHECK6_DEBUG:-0}" == "1" ]]; then
		run_b node members
		run_c node members
		run_b node list
	fi
	gossip_hello="${TMPWORK}/gossip_hello.json"
	forwarded=0
	run_checked "check 6 (gossip forward): node hello payload (A->B)" --quiet run_a node hello --devtls --addr "${b_addr}" --devtls-ca "${CA_B}" --to-id "${NODEIDB}" --advertise-addr "${a_addr}" --out "${gossip_hello}"
	if [[ "${WEB4_DEBUG:-}" == "1" ]]; then
		payload_from="$(awk -F\" '/"from_node_id"/{print $4; exit}' "${gossip_hello}" 2>/dev/null || true)"
		payload_to="$(awk -F\" '/"to_node_id"/{print $4; exit}' "${gossip_hello}" 2>/dev/null || true)"
		echo "check 6 debug: A_ID=${NODEIDA} B_ID=${NODEIDB} C_ID=${NODEIDC} payload_from=${payload_from} payload_to=${payload_to}" >&2
	fi
	server_log="${server_log_c}"
	for attempt in $(seq 1 1); do
		if ! ( export WEB4_GOSSIP_TTL_HOPS=3; run_a gossip push --devtls --addr "${b_addr}" --devtls-ca "${CA_B}" --in "${gossip_hello}" ); then
			echo "gossip push attempt failed"
		fi
		check6_phase_mark "gossip_push_sent"
		b_received_phase=0
		for _ in $(seq 1 300); do
			debug_peer_seen_once "A peers" "${TMPA}/.web4mvp/peers.jsonl" "${NODEIDA}"
			debug_peer_seen_once "A peers" "${TMPA}/.web4mvp/peers.jsonl" "${NODEIDB}"
			debug_peer_seen_once "A peers" "${TMPA}/.web4mvp/peers.jsonl" "${NODEIDC}"
			debug_peer_seen_once "B peers" "${TMPB}/.web4mvp/peers.jsonl" "${NODEIDA}"
			debug_peer_seen_once "B peers" "${TMPB}/.web4mvp/peers.jsonl" "${NODEIDB}"
			debug_peer_seen_once "B peers" "${TMPB}/.web4mvp/peers.jsonl" "${NODEIDC}"
			debug_peer_seen_once "C peers" "${TMPC}/.web4mvp/peers.jsonl" "${NODEIDA}"
			debug_peer_seen_once "C peers" "${TMPC}/.web4mvp/peers.jsonl" "${NODEIDB}"
			debug_peer_seen_once "C peers" "${TMPC}/.web4mvp/peers.jsonl" "${NODEIDC}"
			if run_c node list | grep -q "${NODEIDA}"; then
				forwarded=1
				check6_phase_mark "c_learned_a"
				break
			fi
			if [[ "${b_received_phase}" -eq 0 ]] && grep -q "type=gossip_push" "${server_log_b}"; then
				check6_phase_mark "b_received_gossip_push"
				b_received_phase=1
			fi
			if grep -q "type=gossip_push" "${server_log_c}"; then
				forwarded=1
				break
			fi
			sleep 0.1
		done
		if [[ "${forwarded}" -eq 1 ]]; then
			break
		fi
	done
	if [[ "${forwarded}" -ne 1 ]]; then
		# club model: print full command and state for easier diagnostics
		echo "Command failed (check 6 (gossip forward): gossip push (A->B)): ( export WEB4_GOSSIP_TTL_HOPS=3; run_a gossip push --devtls --addr ${b_addr} --devtls-ca ${CA_B} --in ${gossip_hello} )"
		pattern="dial|connect|handshake|open stream|accept|timeout|deadline|reject|member|unaccepted|unknown sender"
		for log in "${server_log_a}" "${server_log_b}" "${server_log_c}"; do
			if [[ -n "${log}" && -f "${log}" ]]; then
				echo "Log matches (${log}):"
				grep -nE "${pattern}" "${log}" | tail -n 200 || true
			fi
		done
		if [[ "${WEB4_CHECK6_DEBUG:-0}" == "1" ]]; then
			echo "A members:"
			run_a node members || true
		fi
		echo "A peers file tail:"
		tail -n 5 "${TMPA}/.web4mvp/peers.jsonl" || true
		if [[ "${WEB4_CHECK6_DEBUG:-0}" == "1" ]]; then
			echo "B members:"
			run_b node members || true
			echo "B peers (list):"
			run_b node list || true
		fi
		echo "B peers file tail:"
		tail -n 5 "${TMPB}/.web4mvp/peers.jsonl" || true
		echo "gossip payload head:"
		head -n 30 "${gossip_hello}" || true
		pattern="dial|connect|handshake|open stream|accept|timeout|deadline|reject|member|unaccepted|unknown sender"
		echo "Log matches (${server_log_a}):"
		grep -nE "${pattern}" "${server_log_a}" | tail -n 200 || true
		echo "Log matches (${server_log_b}):"
		grep -nE "${pattern}" "${server_log_b}" | tail -n 200 || true
		echo "Log matches (${server_log_c}):"
		grep -nE "${pattern}" "${server_log_c}" | tail -n 200 || true
		check6_quic_fail "no_conn" "check 6 (gossip forward): peer not forwarded"
	fi

	if grep -n "\\.\\.\\." scripts/smoke.sh >/dev/null 2>&1; then
		echo "ERROR: ellipsis present in scripts/smoke.sh"
		exit 1
	fi

	kill "${SERVER_PID_B}" 2>/dev/null || true
	wait "${SERVER_PID_B}" 2>/dev/null || true
	SERVER_PID_B=""
	kill "${SERVER_PID_C}" 2>/dev/null || true
	wait "${SERVER_PID_C}" 2>/dev/null || true
	SERVER_PID_C=""
	kill "${SERVER_PID_A}" 2>/dev/null || true
	wait "${SERVER_PID_A}" 2>/dev/null || true
	SERVER_PID_A=""
	pass "check 6 (gossip forward)"
)

echo "ALL SMOKE CHECKS PASSED"
