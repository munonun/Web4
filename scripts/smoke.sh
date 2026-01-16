#!/usr/bin/env bash
set -euo pipefail
: "${WEB4_STORE_MAX_BYTES:?set WEB4_STORE_MAX_BYTES (e.g. 65536) to run smoke tests}"
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

pick_unique_port() {
	local fallback="$1"
	local p=""
	for _ in $(seq 1 6000); do
		p="$(pick_port "${fallback}")"
		# 중복이면 다시
		if [[ -n "${USED_PORTS[${p}]:-}" ]]; then
			continue
		fi
		USED_PORTS["${p}"]=1
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
LISTENER_PIDS=()
SERVER_PID=""
SERVER_PID_B=""
SERVER_PID_C=""
SERVER_PID_A=""
STATEFUL_PID=""
SENDER_PID=""

cleanup() {
	local status=$?
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
	rm -rf "${TMPA}" "${TMPB}" "${TMPC}" "${TMPD}" "${TMPWORK}"
	exit "${status}"
}
trap cleanup EXIT

if [[ "${WEB4_SMOKE_PKILL:-}" == "1" ]]; then
	pkill -f "web4 quic-listen" 2>/dev/null || true
fi

WEB4_BIN="${TMPWORK}/web4"
go build -o "${WEB4_BIN}" ./cmd/web4

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

wait_quic_ready() {
	local log="$1"
	local label="$2"
	for _ in $(seq 1 80); do
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
echo "Starting QUIC server: env HOME=${TMPA} ${WEB4_BIN} quic-listen --devtls --addr 127.0.0.1:${PORT}"
env HOME="${TMPA}" "${WEB4_BIN}" quic-listen --devtls --addr "127.0.0.1:${PORT}" >"${server_log}" 2>&1 &
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

server_log_a="${TMPWORK}/quic_gossip_a.log"
server_log_b="${TMPWORK}/quic_gossip_b.log"
server_log_c="${TMPWORK}/quic_gossip_c.log"
server_log="${server_log_b}"
echo "Starting QUIC server A (hello): env HOME=${TMPA} ${WEB4_BIN} quic-listen --devtls --addr 127.0.0.1:${PORTA_HELLO}"
env HOME="${TMPA}" "${WEB4_BIN}" quic-listen --devtls --addr "127.0.0.1:${PORTA_HELLO}" >"${server_log_a}" 2>&1 &
SERVER_PID_A=$!
LISTENER_PIDS+=("${SERVER_PID_A}")
echo "Starting QUIC server B: env HOME=${TMPB} ${WEB4_BIN} quic-listen --devtls --addr 127.0.0.1:${PORTB}"
env HOME="${TMPB}" WEB4_GOSSIP_FANOUT=2 WEB4_GOSSIP_TTL_HOPS=3 "${WEB4_BIN}" quic-listen --devtls --addr "127.0.0.1:${PORTB}" >"${server_log_b}" 2>&1 &
SERVER_PID_B=$!
LISTENER_PIDS+=("${SERVER_PID_B}")
echo "Starting QUIC server C: env HOME=${TMPC} ${WEB4_BIN} quic-listen --devtls --addr 127.0.0.1:${PORTC}"
env HOME="${TMPC}" "${WEB4_BIN}" quic-listen --devtls --addr "127.0.0.1:${PORTC}" >"${server_log_c}" 2>&1 &
SERVER_PID_C=$!
LISTENER_PIDS+=("${SERVER_PID_C}")

wait_quic_ready "${server_log_a}" "check 6 (gossip forward): server A did not start"
wait_quic_ready "${server_log_b}" "check 6 (gossip forward): server B did not start"
wait_quic_ready "${server_log_c}" "check 6 (gossip forward): server C did not start"

for _ in $(seq 1 20); do
	if [[ -f "${TMPA}/.web4mvp/devtls_ca.pem" ]]; then
		break
	fi
	sleep 0.05
done
for _ in $(seq 1 20); do
	if [[ -f "${TMPB}/.web4mvp/devtls_ca.pem" ]]; then
		break
	fi
	sleep 0.05
done
for _ in $(seq 1 20); do
	if [[ -f "${TMPC}/.web4mvp/devtls_ca.pem" ]]; then
		break
	fi
	sleep 0.05
done
if [[ ! -f "${TMPA}/.web4mvp/devtls_ca.pem" || ! -f "${TMPB}/.web4mvp/devtls_ca.pem" || ! -f "${TMPC}/.web4mvp/devtls_ca.pem" ]]; then
	quic_fail "check 6 (gossip forward): missing devtls CA"
fi

PUBC="$(cat "${TMPC}/.web4mvp/pub.hex")"
NODEIDC="$(run_c node id | awk '/node_id:/ {print $2}')"
NODEIDA="$(run_a node id | awk '/node_id:/ {print $2}')"
NODEIDB="$(run_b node id | awk '/node_id:/ {print $2}')"

# Seed A's peer store so gossip push can resolve B's pubkey+addr
PUBB="$(cat "${TMPB}/.web4mvp/pub.hex")"
printf '{"node_id":"%s","pubkey":"%s","addr":"%s"}\n' "${NODEIDB}" "${PUBB}" "127.0.0.1:${PORTB}" >> "${TMPA}/.web4mvp/peers.jsonl"
found=0
for _ in $(seq 1 20); do
	if grep -q "${NODEIDB}" "${TMPA}/.web4mvp/peers.jsonl" && grep -q "${PORTB}" "${TMPA}/.web4mvp/peers.jsonl"; then
		found=1
		break
	fi
	sleep 0.05
done
if [[ "${found}" -ne 1 ]]; then
	quic_fail "check 6 (gossip forward): peer seed missing on A"
fi

# Build peer mappings first so B learns C's pubkey+addr and vice versa
run_checked "check 6 (gossip forward): node hello (A->B)" --log "${server_log_b}" --quiet run_a node hello --devtls --addr "127.0.0.1:${PORTB}" --devtls-ca "${TMPB}/.web4mvp/devtls_ca.pem" --to-id "${NODEIDB}" --advertise-addr "127.0.0.1:${PORTA_HELLO}"
run_checked "check 6 (gossip forward): node hello (C->B)" --log "${server_log_b}" --quiet run_c node hello --devtls --addr "127.0.0.1:${PORTB}" --devtls-ca "${TMPB}/.web4mvp/devtls_ca.pem" --to-id "${NODEIDB}" --advertise-addr "127.0.0.1:${PORTC}"
run_checked "check 6 (gossip forward): node hello (B->C)" --log "${server_log_c}" --quiet run_b node hello --devtls --addr "127.0.0.1:${PORTC}" --devtls-ca "${TMPC}/.web4mvp/devtls_ca.pem" --to-id "${NODEIDC}"

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
	quic_fail "check 6 (gossip forward): peer hello missing on B"
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
	quic_fail "check 6 (gossip forward): peer hello missing on C"
fi
# Ensure B has C addr+pubkey so forward target resolves (membership alone is not enough)
found=0
for _ in $(seq 1 60); do
	if run_b node list | grep -q "${NODEIDC}" && grep -q "${PORTC}" "${TMPB}/.web4mvp/peers.jsonl"; then
		found=1
		break
	fi
	sleep 0.05
done
if [[ "${found}" -ne 1 ]]; then
	quic_fail "check 6 (gossip forward): B missing C addr/pubkey"
fi
# Ensure addr->node_id mapping points to C's identity based on latest JSONL entry
if ! tac "${TMPB}/.web4mvp/peers.jsonl" | awk -v addr="127.0.0.1:${PORTC}" -v id="${NODEIDC}" '
	$0 ~ addr {found=1; if ($0 ~ id) ok=1; exit}
	END {exit !(found && ok)}
'; then
	quic_fail "check 6 (gossip forward): B addr mapping mismatch for C"
	quic_fail "grep "127.0.0.1:${PORTC}" -n "${TMPB}/.web4mvp/peers.jsonl" | tail -n 20"
fi

# Club gate: membership must be set before gossip is accepted/forwarded
run_checked "check 6 (gossip forward): node join (B<-A)" --quiet run_b node join --node-id "${NODEIDA}"
run_checked "check 6 (gossip forward): node join (B<-C)" --quiet run_b node join --node-id "${NODEIDC}"
run_checked "check 6 (gossip forward): node join (B<-B)" --quiet run_b node join --node-id "${NODEIDB}"
run_checked "check 6 (gossip forward): node join (C<-B)" --quiet run_c node join --node-id "${NODEIDB}"
run_checked "check 6 (gossip forward): node join (C<-C)" --quiet run_c node join --node-id "${NODEIDC}"

run_b node members
run_c node members
run_b node list
gossip_hello="${TMPWORK}/gossip_hello.json"
forwarded=0
for attempt in $(seq 1 5); do
	run_checked "check 6 (gossip forward): node keygen (D) attempt ${attempt}" --quiet run_d keygen >/dev/null
	NODEIDD="$(run_d node id | awk '/node_id:/ {print $2}')"
	run_checked "check 6 (gossip forward): node join (B<-D) attempt ${attempt}" --quiet run_b node join --node-id "${NODEIDD}"
	joined=0
	for _ in $(seq 1 60); do
		if run_b node members | grep -q "${NODEIDD}"; then
			joined=1
			break
		fi
		sleep 0.05
	done
	if [[ "${joined}" -ne 1 ]]; then
		quic_fail "check 6 (gossip forward): B missing D membership"
	fi
	run_checked "check 6 (gossip forward): node hello (D) attempt ${attempt}" --quiet run_d node hello --devtls --addr "127.0.0.1:${PORTA_HELLO}" --devtls-ca "${TMPA}/.web4mvp/devtls_ca.pem" --to-id "${NODEIDA}" --advertise-addr "127.0.0.1:${PORTD}" --out "${gossip_hello}"
	if ! ( export WEB4_GOSSIP_TTL_HOPS=3; run_a gossip push --devtls --addr "127.0.0.1:${PORTB}" --devtls-ca "${TMPB}/.web4mvp/devtls_ca.pem" --in "${gossip_hello}" ); then
		echo "gossip push attempt ${attempt} failed"
		sleep 0.2
		continue
	fi
	server_log="${server_log_c}"
	for _ in $(seq 1 160); do
		if run_c node list | grep -q "${NODEIDD}"; then
			forwarded=1
			break
		fi
		sleep 0.1
	done
	if [[ "${forwarded}" -eq 1 ]]; then
		break
	fi
	sleep 0.2
done
if [[ "${forwarded}" -ne 1 ]]; then
	# club model: print full command and state for easier diagnostics
	echo "Command failed (check 6 (gossip forward): gossip push (A->B)): ( export WEB4_GOSSIP_TTL_HOPS=3; run_a gossip push --devtls --addr 127.0.0.1:${PORTB} --devtls-ca ${TMPB}/.web4mvp/devtls_ca.pem --in ${gossip_hello} )"
	for log in "${server_log_a}" "${server_log_b}" "${server_log_c}"; do
		if [[ -n "${log}" && -f "${log}" ]]; then
			echo "Log tail (${log}):"
			tail -n 80 "${log}" || true
			echo "Membership gate hints (${log}):"
			grep -E "unaccepted|unknown sender|unverified|member" "${log}" || true
		fi
	done
	echo "A members:"
	run_a node members || true
	echo "A peers file tail:"
	tail -n 5 "${TMPA}/.web4mvp/peers.jsonl" || true
	echo "B members:"
	run_b node members || true
	echo "B peers (list):"
	run_b node list || true
	echo "B peers file tail:"
	tail -n 5 "${TMPB}/.web4mvp/peers.jsonl" || true
	echo "gossip payload head:"
	head -n 30 "${gossip_hello}" || true
	echo "Log tail (${server_log_a}):"
	tail -n 80 "${server_log_a}" || true
	echo "Log tail (${server_log_b}):"
	tail -n 80 "${server_log_b}" || true
	echo "Log tail (${server_log_c}):"
	tail -n 80 "${server_log_c}" || true
	quic_fail "check 6 (gossip forward): peer not forwarded"
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
pass "check 6 (gossip forward)"

echo "ALL SMOKE CHECKS PASSED"
