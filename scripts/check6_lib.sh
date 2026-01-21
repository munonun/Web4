#!/usr/bin/env bash
set -euo pipefail

check6_pick_port() {
	if command -v python3 >/dev/null 2>&1; then
		python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
		return $?
	fi
	if command -v python >/dev/null 2>&1; then
		python - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
		return $?
	fi
	return 1
}

check6_pick_ports() {
	local count="${1:-0}"
	if [[ "${count}" -le 0 ]]; then
		return 1
	fi
	local ports=()
	while [[ "${#ports[@]}" -lt "${count}" ]]; do
		local p
		p="$(check6_pick_port)" || return 1
		local dup=0
		for seen in "${ports[@]}"; do
			if [[ "${seen}" == "${p}" ]]; then
				dup=1
				break
			fi
		done
		if [[ "${dup}" -eq 0 ]]; then
			ports+=("${p}")
		fi
	done
	printf '%s\n' "${ports[@]}"
}

pick_free_udp_port() {
	if command -v python3 >/dev/null 2>&1; then
		python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
		return $?
	fi
	if command -v python >/dev/null 2>&1; then
		python - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
		return $?
	fi
	return 1
}

pick_n_ports() {
	local count="${1:-0}"
	if [[ "${count}" -le 0 ]]; then
		return 1
	fi
	local ports=()
	local attempts=0
	while [[ "${#ports[@]}" -lt "${count}" ]]; do
		attempts=$((attempts + 1))
		if [[ "${attempts}" -gt 100 ]]; then
			return 1
		fi
		local p
		p="$(pick_free_udp_port)" || continue
		local dup=0
		for seen in "${ports[@]}"; do
			if [[ "${seen}" == "${p}" ]]; then
				dup=1
				break
			fi
		done
		if [[ "${dup}" -eq 0 ]]; then
			ports+=("${p}")
		fi
	done
	printf '%s' "${ports[*]}"
}

check6_must_addr() {
	local addr="$1"
	if [[ "${addr}" != *:* ]]; then
		return 1
	fi
	local port="${addr##*:}"
	if [[ -z "${port}" ]]; then
		return 1
	fi
	return 0
}

check6_apply_env_defaults() {
	: "${WEB4_DEBUG:=0}"
	: "${WEB4_CHECK6_DEBUG:=0}"
	: "${WEB4_QUIC_KEEPALIVE_SEC:=2}"
	: "${WEB4_QUIC_IDLE_TIMEOUT_SEC:=60}"
	: "${WEB4_LIMITER_MAX_CONNS_PER_IP:=1000}"
	: "${WEB4_LIMITER_MAX_STREAMS_PER_IP:=1000}"
	if [[ "${WEB4_CHECK6_DEBUG}" == "1" ]]; then
		: "${WEB4_QUIC_STREAM_TIMEOUT_SEC:=30}"
		: "${WEB4_QUIC_ACCEPT_TIMEOUT_SEC:=30}"
		: "${WEB4_WIRE_DEBUG:=1}"
	else
		: "${WEB4_QUIC_STREAM_TIMEOUT_SEC:=10}"
		: "${WEB4_WIRE_DEBUG:=0}"
	fi
	export WEB4_DEBUG WEB4_CHECK6_DEBUG WEB4_WIRE_DEBUG
	export WEB4_QUIC_KEEPALIVE_SEC WEB4_QUIC_IDLE_TIMEOUT_SEC WEB4_QUIC_STREAM_TIMEOUT_SEC WEB4_QUIC_ACCEPT_TIMEOUT_SEC
	export WEB4_LIMITER_MAX_CONNS_PER_IP WEB4_LIMITER_MAX_STREAMS_PER_IP
}

# Readiness check avoids flaky startup races (ports not yet bound).
check6_wait_ready() {
	local log="$1"
	for _ in $(seq 1 100); do
		if grep -q "READY addr=" "${log}"; then
			return 0
		fi
		if grep -q "quic listen failed:" "${log}" || grep -q "quic listen error:" "${log}"; then
			return 2
		fi
		sleep 0.05
	done
	return 1
}

check6_extract_ready_addr() {
	local log="$1"
	awk 'match($0, /READY addr=/) {print substr($0, RSTART+11); exit}' "${log}" 2>/dev/null
}

check6_wait_ca_files() {
	local dir_a="$1"
	local dir_b="$2"
	local dir_c="$3"
	for _ in $(seq 1 100); do
		if [[ -f "${dir_a}/.web4mvp/devtls_ca.pem" && -f "${dir_b}/.web4mvp/devtls_ca.pem" && -f "${dir_c}/.web4mvp/devtls_ca.pem" ]]; then
			return 0
		fi
		sleep 0.05
	done
	return 1
}

check6_set_ca_paths() {
	local dir_a="$1"
	local dir_b="$2"
	local dir_c="$3"
	CA_A="${dir_a}/.web4mvp/devtls_ca.pem"
	CA_B="${dir_b}/.web4mvp/devtls_ca.pem"
	CA_C="${dir_c}/.web4mvp/devtls_ca.pem"
	export CA_A CA_B CA_C
}

check6_phase_mark() {
	local phase="$1"
	if [[ "${CHECK6_PHASE:-}" != "${phase}" ]]; then
		CHECK6_PHASE="${phase}"
		echo "PHASE=${CHECK6_PHASE}"
	fi
}

check6_env_summary() {
	echo "ENV_SUMMARY a_addr=${CHECK6_ADDR_A:-} b_addr=${CHECK6_ADDR_B:-} c_addr=${CHECK6_ADDR_C:-} ttl=${WEB4_GOSSIP_TTL_HOPS:-} stream_timeout=${WEB4_QUIC_STREAM_TIMEOUT_SEC:-} accept_timeout=${WEB4_QUIC_ACCEPT_TIMEOUT_SEC:-} keepalive=${WEB4_QUIC_KEEPALIVE_SEC:-} idle=${WEB4_QUIC_IDLE_TIMEOUT_SEC:-} ca_a=${CA_A:-} ca_b=${CA_B:-} ca_c=${CA_C:-}"
}

check6_fail() {
	local reason="$1"
	shift || true
	local details="${*:-}"
	echo "CHECK6_FAIL reason=${reason} phase=${CHECK6_PHASE:-} a_addr=${CHECK6_ADDR_A:-} b_addr=${CHECK6_ADDR_B:-} c_addr=${CHECK6_ADDR_C:-} details=${details}"
	if [[ "${CHECK6_SUMMARY_ON_FAIL:-0}" == "1" ]]; then
		check6_env_summary
	fi
	if [[ "${CHECK6_FAIL_EXIT:-0}" == "1" ]]; then
		exit 1
	fi
	return 1
}
