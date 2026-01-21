#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=check6_lib.sh
source "${SCRIPT_DIR}/check6_lib.sh"

check6_apply_env_defaults
export WEB4_CHECK6_ACK="${WEB4_CHECK6_ACK:-1}"
export WEB4_WIRE_CLOSE_CONN="${WEB4_WIRE_CLOSE_CONN:-1}"

CHECK6_FAIL_EXIT=1
CHECK6_SUMMARY_ON_FAIL="${WEB4_CHECK6_DEBUG}"
CHECK6_PHASE="init"
CHECK6_ADDR_A="unknown"
CHECK6_ADDR_B="unknown"
CHECK6_ADDR_C="unknown"

pass() {
	echo "PASS: $1"
}

extract_sha() {
	local file="$1"
	awk 'match($0, /sha256=[0-9a-f]+/) {sha=substr($0, RSTART+7, RLENGTH-7)} END {print sha}' "${file}" 2>/dev/null
}

extract_ack_sha() {
	local file="$1"
	awk 'match($0, /GOSSIP_ACK status=ok/) && match($0, /sha256=[0-9a-f]+/) {print substr($0, RSTART+7, RLENGTH-7); exit}' "${file}" 2>/dev/null
}

has_matching_sha() {
	local file="$1"
	local target="$2"
	awk -v target="${target}" 'match($0, /sha256=[0-9a-f]+/) {sha=substr($0, RSTART+7, RLENGTH-7); if (sha == target) {found=1; exit}} END {exit !found}' "${file}" 2>/dev/null
}

msg_id_from_sha() {
	local sha="$1"
	if [[ -z "${sha}" ]]; then
		echo ""
		return
	fi
	echo "${sha:0:12}"
}

has_phase_send_ok() {
	local file="$1"
	local msg_id="$2"
	grep -q "PHASE send_result msg_id=${msg_id} .* ok=1" "${file}" 2>/dev/null
}

has_phase_send_fail() {
	local file="$1"
	local msg_id="$2"
	grep -q "PHASE send_result msg_id=${msg_id} .* ok=0" "${file}" 2>/dev/null
}

has_wire_recv_sha() {
	local file="$1"
	local sha="$2"
	grep -q "sha256=${sha}" "${file}" 2>/dev/null
}

extract_forward_sha() {
	local file="$1"
	local msg_id="$2"
	awk -v msg_id="${msg_id}" '$0 ~ "FORWARD payload" && $0 ~ "msg_id="msg_id {if (match($0, /sha256=[0-9a-f]+/)) {print substr($0, RSTART+7, RLENGTH-7); exit}}' "${file}" 2>/dev/null
}

extract_forward_msg_id() {
	local file="$1"
	local msg_id="$2"
	awk -v msg_id="${msg_id}" '$0 ~ "FORWARD payload" && $0 ~ "msg_id="msg_id {if (match($0, /forward_msg_id=[0-9a-f]+/)) {print substr($0, RSTART+15, RLENGTH-15); exit}}' "${file}" 2>/dev/null
}

has_parse_ok() {
	local file="$1"
	local msg_id="$2"
	grep -q "PARSE_OK msg_id=${msg_id} " "${file}" 2>/dev/null
}

has_send_err_dial() {
	local file="$1"
	local msg_id="$2"
	grep -q "PHASE send_result msg_id=${msg_id} .* ok=0 .*dial" "${file}" 2>/dev/null
}

find_drop_reason() {
	local file="$1"
	awk '$0 ~ /type=gossip_push/ && match($0, /DROP reason=[^ ]+/) {print substr($0, RSTART+12, RLENGTH-12); exit}' "${file}" 2>/dev/null
}

TMPA="$(mktemp -d)"
TMPB="$(mktemp -d)"
TMPC="$(mktemp -d)"
TMPWORK="$(mktemp -d)"
LISTENER_PIDS=()

cleanup() {
	local status=$?
	for pid in "${LISTENER_PIDS[@]}"; do
		if [[ -n "${pid}" ]]; then
			kill "${pid}" 2>/dev/null || true
			wait "${pid}" 2>/dev/null || true
		fi
	done
	if [[ "${SMOKE_KEEP_TMP:-}" == "1" ]]; then
		echo "SMOKE_KEEP_TMP=1 leaving tmp dirs: ${TMPA} ${TMPB} ${TMPC} ${TMPWORK}" >&2
	else
		rm -rf "${TMPA}" "${TMPB}" "${TMPC}" "${TMPWORK}"
	fi
	exit "${status}"
}
trap cleanup EXIT

if [[ -n "${WEB4_BIN:-}" ]]; then
	if [[ ! -x "${WEB4_BIN}" ]]; then
		check6_fail "listen_error" "missing WEB4_BIN"
	fi
else
	WEB4_BIN="${TMPWORK}/web4"
	if ! go build -o "${WEB4_BIN}" ./cmd/web4; then
		check6_fail "listen_error" "build_failed"
	fi
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

run_a keygen >/dev/null 2>&1
run_b keygen >/dev/null 2>&1
run_c keygen >/dev/null 2>&1

ports="$(check6_pick_ports 3 || true)"
if [[ -z "${ports}" ]]; then
	check6_fail "listen_error" "port_pick_failed"
fi
read -r PORTA_HELLO PORTB PORTC <<<"${ports}"
a_addr="127.0.0.1:${PORTA_HELLO}"
b_addr="127.0.0.1:${PORTB}"
c_addr="127.0.0.1:${PORTC}"
CHECK6_ADDR_A="${a_addr}"
CHECK6_ADDR_B="${b_addr}"
CHECK6_ADDR_C="${c_addr}"

server_log_a="${TMPWORK}/quic_gossip_a.log"
server_log_b="${TMPWORK}/quic_gossip_b.log"
server_log_c="${TMPWORK}/quic_gossip_c.log"

env HOME="${TMPA}" "${WEB4_BIN}" quic-listen --devtls --addr "${a_addr}" >"${server_log_a}" 2>&1 &
LISTENER_PIDS+=("$!")

env HOME="${TMPB}" WEB4_GOSSIP_FANOUT=2 WEB4_GOSSIP_TTL_HOPS=3 "${WEB4_BIN}" quic-listen --devtls --addr "${b_addr}" >"${server_log_b}" 2>&1 &
LISTENER_PIDS+=("$!")

env HOME="${TMPC}" "${WEB4_BIN}" quic-listen --devtls --addr "${c_addr}" >"${server_log_c}" 2>&1 &
LISTENER_PIDS+=("$!")

check6_wait_ready "${server_log_a}" || check6_fail "listen_error" "server_a_not_ready"
check6_wait_ready "${server_log_b}" || check6_fail "listen_error" "server_b_not_ready"
check6_wait_ready "${server_log_c}" || check6_fail "listen_error" "server_c_not_ready"
a_addr="$(check6_extract_ready_addr "${server_log_a}")"
b_addr="$(check6_extract_ready_addr "${server_log_b}")"
c_addr="$(check6_extract_ready_addr "${server_log_c}")"
if [[ -z "${a_addr}" || -z "${b_addr}" || -z "${c_addr}" ]]; then
	check6_fail "listen_error" "missing_ready_addr"
fi
CHECK6_ADDR_A="${a_addr}"
CHECK6_ADDR_B="${b_addr}"
CHECK6_ADDR_C="${c_addr}"

for _ in $(seq 1 40); do
	if [[ -f "${TMPA}/.web4mvp/devtls_ca.pem" && -f "${TMPB}/.web4mvp/devtls_ca.pem" && -f "${TMPC}/.web4mvp/devtls_ca.pem" ]]; then
		break
	fi
	sleep 0.05
done
check6_wait_ca_files "${TMPA}" "${TMPB}" "${TMPC}" || check6_fail "listen_error" "missing_ca"
check6_set_ca_paths "${TMPA}" "${TMPB}" "${TMPC}"
if [[ "${CA_A}" == "${CA_B}" || "${CA_A}" == "${CA_C}" || "${CA_B}" == "${CA_C}" ]]; then
	check6_fail "listen_error" "ca_path_mismatch"
fi
check6_phase_mark "servers_ready"

NODEIDA="$(run_a node id | awk '/node_id:/ {print $2}')"
NODEIDB="$(run_b node id | awk '/node_id:/ {print $2}')"
NODEIDC="$(run_c node id | awk '/node_id:/ {print $2}')"
PUBB="$(cat "${TMPB}/.web4mvp/pub.hex")"
PUBC="$(cat "${TMPC}/.web4mvp/pub.hex")"

printf '{"node_id":"%s","pubkey":"%s","addr":"%s"}\n' "${NODEIDB}" "${PUBB}" "${b_addr}" >> "${TMPA}/.web4mvp/peers.jsonl"

if ! run_a node hello --devtls --addr "${b_addr}" --devtls-ca "${CA_B}" --to-id "${NODEIDB}" --advertise-addr "${a_addr}" >/dev/null 2>&1; then
	check6_fail "no_conn"
fi
if ! run_c node hello --devtls --addr "${b_addr}" --devtls-ca "${CA_B}" --to-id "${NODEIDB}" --advertise-addr "${c_addr}" >/dev/null 2>&1; then
	check6_fail "no_conn"
fi
if ! run_b node hello --devtls --addr "${c_addr}" --devtls-ca "${CA_C}" --to-id "${NODEIDC}" >/dev/null 2>&1; then
	check6_fail "no_conn"
fi

found=0
for _ in $(seq 1 80); do
	if run_b node list | grep -q "${NODEIDA}" && run_b node list | grep -q "${NODEIDC}"; then
		found=1
		break
	fi
	sleep 0.05
done
if [[ "${found}" -ne 1 ]]; then
	check6_fail "no_conn"
fi

found=0
for _ in $(seq 1 80); do
	if run_c node list | grep -q "${NODEIDB}"; then
		found=1
		break
	fi
	sleep 0.05
done
if [[ "${found}" -ne 1 ]]; then
	check6_fail "no_conn"
fi

printf '{"node_id":"%s","pubkey":"%s","addr":"%s"}\n' "${NODEIDC}" "${PUBC}" "${c_addr}" >> "${TMPB}/.web4mvp/peers.jsonl"

check6_phase_mark "hello_done"

if ! run_b node join --node-id "${NODEIDA}" >/dev/null 2>&1; then
	check6_fail "no_conn"
fi
if ! run_b node join --node-id "${NODEIDC}" >/dev/null 2>&1; then
	check6_fail "no_conn"
fi
if ! run_b node join --node-id "${NODEIDB}" >/dev/null 2>&1; then
	check6_fail "no_conn"
fi
if ! run_c node join --node-id "${NODEIDB}" >/dev/null 2>&1; then
	check6_fail "no_conn"
fi
if ! run_c node join --node-id "${NODEIDC}" >/dev/null 2>&1; then
	check6_fail "no_conn"
fi

gossip_hello="${TMPWORK}/gossip_hello.json"
if ! run_a node hello --devtls --addr "${b_addr}" --devtls-ca "${CA_B}" --to-id "${NODEIDB}" --advertise-addr "${a_addr}" --out "${gossip_hello}" >/dev/null 2>&1; then
	check6_fail "no_conn"
fi

gossip_log_a="${TMPWORK}/gossip_push_a.log"
if ! ( export WEB4_GOSSIP_TTL_HOPS=3; run_a gossip push --devtls --addr "${b_addr}" --devtls-ca "${CA_B}" --in "${gossip_hello}" ) >"${gossip_log_a}" 2>&1; then
	check6_fail "no_conn"
fi
check6_phase_mark "gossip_push_sent"

b_received=0
c_learned=0
for _ in $(seq 1 300); do
	if [[ "${b_received}" -eq 0 ]] && grep -q "type=gossip_push" "${server_log_b}"; then
		b_received=1
		check6_phase_mark "b_received_gossip_push"
	fi
	if run_c node list | grep -q "${NODEIDA}"; then
		c_learned=1
		check6_phase_mark "c_learned_a"
		pass "C learned A"
		exit 0
	fi
	sleep 0.1
done

a_sha="$(extract_sha "${gossip_log_a}")"
ack_sha="$(extract_ack_sha "${gossip_log_a}")"
ack_ok=0
if [[ -n "${ack_sha}" ]]; then
	if [[ "${ack_sha}" == "${a_sha}" ]]; then
		ack_ok=1
	else
		check6_fail "ack_mismatch"
	fi
fi
b_match=0
if [[ -n "${a_sha}" ]] && has_matching_sha "${server_log_b}" "${a_sha}"; then
	b_match=1
fi
drop_reason="$(find_drop_reason "${server_log_b}")"
msg_id="$(msg_id_from_sha "${a_sha}")"
forward_sha="$(extract_forward_sha "${server_log_b}" "${msg_id}")"
forward_msg_id="$(extract_forward_msg_id "${server_log_b}" "${msg_id}")"
c_raw=0
c_parse=0
if [[ -n "${forward_sha}" ]] && has_wire_recv_sha "${server_log_c}" "${forward_sha}"; then
	c_raw=1
fi
if [[ -n "${forward_msg_id}" ]] && has_parse_ok "${server_log_c}" "${forward_msg_id}"; then
	c_parse=1
fi

if [[ -z "${a_sha}" ]]; then
	check6_fail "no_conn"
fi
if [[ -n "${drop_reason}" ]]; then
	check6_fail "b_drop" "${drop_reason}"
fi
if [[ "${b_received}" -eq 1 && "${b_match}" -eq 0 ]]; then
	check6_fail "read_mismatch"
fi
if [[ "${ack_ok}" -eq 1 ]]; then
	if [[ "${c_raw}" -eq 1 ]]; then
		if [[ "${c_parse}" -eq 1 ]]; then
			check6_fail "forward_recv_ok_no_upsert"
		fi
		check6_fail "forward_recv_parse_error"
	fi
	if has_send_err_dial "${server_log_b}" "${msg_id}"; then
		check6_fail "dial_error"
	fi
	check6_fail "forward_write_ok_no_ack"
fi
if [[ "${ack_ok}" -eq 0 && "${b_match}" -eq 1 ]]; then
	check6_fail "read_ok_no_ack"
fi
if [[ "${ack_ok}" -eq 0 && "${b_match}" -eq 0 ]]; then
	check6_fail "write_ok_no_ack"
fi
check6_fail "c_learn_timeout"
