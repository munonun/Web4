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

TMPA="$(mktemp -d)"
TMPB="$(mktemp -d)"
TMPWORK="$(mktemp -d)"
SERVER_PID=""

cleanup() {
	local status=$?
	if [[ -n "${SERVER_PID}" ]]; then
		kill "${SERVER_PID}" 2>/dev/null || true
		wait "${SERVER_PID}" 2>/dev/null || true
	fi
	rm -rf "${TMPA}" "${TMPB}" "${TMPWORK}"
	exit "${status}"
}
trap cleanup EXIT

WEB4_BIN="${TMPWORK}/web4"
go build -o "${WEB4_BIN}" ./cmd/web4

run_a() {
	HOME="${TMPA}" "${WEB4_BIN}" "$@"
}

run_b() {
	HOME="${TMPB}" "${WEB4_BIN}" "$@"
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
PUBA="$(cat "${TMPA}/.web4mvp/pub.hex")"

contracts_path="${TMPA}/.web4mvp/contracts.jsonl"
max_bytes=$((64 * 1024 * 1024))
headroom_bytes=$((64 * 1024))
prefill_jsonl "${contracts_path}" $((max_bytes - headroom_bytes))

open_msg="${TMPWORK}/open.json"
close_msg="${TMPWORK}/close.json"
rotated=0
max_iters=400

for i in $(seq 1 "${max_iters}"); do
	run_b open --to "${PUBA}" --amount 5 --nonce "${i}" --out "${open_msg}" >/dev/null
	run_a recv --in "${open_msg}" >/dev/null
	CID="$(run_b list | awk 'END{print $2}')"
	run_b close --id "${CID}" --reqnonce 1 --out "${close_msg}" >/dev/null
	run_a recv --in "${close_msg}" >/dev/null
	if ls "${TMPA}/.web4mvp"/*.jsonl.* >/dev/null 2>&1; then
		rotated=1
		break
	fi
done

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
	out="$(HOME="${TMPA}" "${WEB4_BIN}" recv --in "${file}" 2>&1 || true)"
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

if command -v python3 >/dev/null 2>&1; then
	PORT="$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"
else
	PORT="42424"
fi

quic_msg="${TMPWORK}/quic_open.json"
run_b open --to "${PUBA}" --amount 5 --nonce 9900 --out "${quic_msg}" >/dev/null

server_log="${TMPWORK}/quic_server.log"
echo "Starting QUIC server: env HOME=${TMPA} ${WEB4_BIN} quic-listen --devtls --addr 127.0.0.1:${PORT}"
env HOME="${TMPA}" "${WEB4_BIN}" quic-listen --devtls --addr "127.0.0.1:${PORT}" >"${server_log}" 2>&1 &
SERVER_PID=$!

ready=0
for _ in $(seq 1 50); do
	if grep -qE 'quic listen ready|QUIC LISTEN' "${server_log}"; then
		ready=1
		break
	fi
	sleep 0.05
done
if [[ "${ready}" -ne 1 ]]; then
	quic_fail "check 3 (QUIC limiter): server did not start"
fi

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
		if env HOME="${TMPB}" "${WEB4_BIN}" quic-send --devtls --addr "127.0.0.1:${PORT}" --in "${quic_msg}" >/dev/null 2>&1; then
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
total=$((cap + 2))
client_dir="${TMPWORK}/clients"
mkdir -p "${client_dir}"
pids=()
echo "QUIC client command: env HOME=${TMPB} ${WEB4_BIN} quic-send --devtls --addr 127.0.0.1:${PORT} --in ${quic_msg}"

for i in $(seq 1 "${total}"); do
	log="${client_dir}/client_${i}.log"
	(env HOME="${TMPB}" "${WEB4_BIN}" quic-send --devtls --addr "127.0.0.1:${PORT}" --in "${quic_msg}" >"${log}" 2>&1) &
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

echo "ALL SMOKE CHECKS PASSED"
