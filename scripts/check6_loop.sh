#!/usr/bin/env bash
set -euo pipefail

runs="${1:-30}"
pass=0
fail=0
declare -A reasons

for i in $(seq 1 "${runs}"); do
	out_file="$(mktemp)"
	if ./scripts/check6_min.sh >"${out_file}" 2>&1; then
		pass=$((pass + 1))
		echo "run ${i}: PASS"
	else
		fail=$((fail + 1))
		line="$(grep -m1 '^CHECK6_FAIL' "${out_file}" || true)"
		reason="unknown"
		if [[ -n "${line}" ]]; then
			reason="$(awk '{for (i=1;i<=NF;i++) if ($i ~ /^reason=/) {sub("reason=","",$i); print $i; exit}}' <<<"${line}")"
		fi
		reasons["${reason}"]=$(( ${reasons["${reason}"]:-0} + 1 ))
		echo "run ${i}: FAIL reason=${reason}"
	fi
	rm -f "${out_file}"
	jitter="$(awk -v r=${RANDOM} 'BEGIN {printf "%.2f", 0.2 + (r / 32767) * 0.6}')"
	sleep "${jitter}"
done

echo "CHECK6_LOOP_RESULT pass=${pass} fail=${fail}"
if [[ "${fail}" -gt 0 ]]; then
	echo "CHECK6_FAIL_HISTOGRAM"
	for reason in "${!reasons[@]}"; do
		echo "${reason} ${reasons[${reason}]}"
	done | sort -k2,2nr | awk '{printf "reason=%s count=%s\n", $1, $2}'
fi
