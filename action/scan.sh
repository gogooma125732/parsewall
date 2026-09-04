#!/usr/bin/env bash
set -euo pipefail

input_path="$PARSEWALL_INPUT"
if [[ "$input_path" != /* ]]; then
  input_path="$GITHUB_WORKSPACE/$input_path"
fi

if [[ ! -f "$input_path" ]]; then
  echo "Parsewall input file does not exist: $PARSEWALL_INPUT" >&2
  exit 2
fi

python3 -m pip install --disable-pip-version-check --quiet "$GITHUB_ACTION_PATH" 1>&2
result="$(parsewall scan --input "$input_path")"
risk_level="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["risk_level"])' <<<"$result")"

case "$risk_level" in
  low) risk_rank=0 ;;
  review) risk_rank=1 ;;
  quarantine) risk_rank=2 ;;
  *) echo "Parsewall returned an invalid risk level" >&2; exit 1 ;;
esac

case "$PARSEWALL_FAIL_ON" in
  low) fail_rank=0 ;;
  review) fail_rank=1 ;;
  quarantine) fail_rank=2 ;;
  *) echo "fail-on must be low, review, or quarantine" >&2; exit 2 ;;
esac

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "risk-level=$risk_level"
    echo 'result<<PARSEWALL_RESULT'
    echo "$result"
    echo 'PARSEWALL_RESULT'
  } >> "$GITHUB_OUTPUT"
fi

echo "Parsewall risk level: $risk_level"
if (( risk_rank >= fail_rank )); then
  echo "Parsewall threshold reached (fail-on=$PARSEWALL_FAIL_ON)." >&2
  exit 1
fi
