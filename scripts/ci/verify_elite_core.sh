#!/usr/bin/env bash
set -euo pipefail

ARTIFACT_DIR=".verification-artifacts"
SCENARIO="${ARTIFACT_DIR}/delegation-authority-scenario.json"
RECEIPT="${ARTIFACT_DIR}/delegation-authority-scenario.receipt.json"
mkdir -p "${ARTIFACT_DIR}"

python -m compileall -q src tests scripts
python -m unittest discover -s tests -v | tee "${ARTIFACT_DIR}/unittest.txt"
python scripts/delegation_probe.py \
  --output "${SCENARIO}" \
  --receipt "${RECEIPT}" \
  | tee "${ARTIFACT_DIR}/delegation-probe.txt"

python - <<'PY'
import hashlib
import json
from pathlib import Path

scenario_path = Path('.verification-artifacts/delegation-authority-scenario.json')
receipt_path = Path('.verification-artifacts/delegation-authority-scenario.receipt.json')
scenario = json.loads(scenario_path.read_text(encoding='utf-8'))
receipt = json.loads(receipt_path.read_text(encoding='utf-8'))

assert scenario['evidence_state'] == 'EXECUTABLE_LOCAL_DELEGATION_AUTHORITY'
assert scenario['child']['depth'] == scenario['root']['depth'] + 1
assert set(scenario['child']['allowed_fields']).issubset(scenario['root']['allowed_fields'])
assert scenario['child']['max_uses'] <= scenario['root']['max_uses']
assert scenario['child']['expires_at'] <= scenario['root']['expires_at']
assert scenario['decisions']['allowed']['status'] == 'ALLOW'
assert scenario['decisions']['replay']['reason'] == 'REPLAY'
assert scenario['decisions']['use_limit']['reason'] == 'USE_LIMIT_EXCEEDED'
assert scenario['decisions']['tamper']['reason'] == 'INVALID_SIGNATURE'
assert scenario['amplification_refusals'] == {
    'field': 'FIELD_AMPLIFICATION',
    'scope': 'SCOPE_AMPLIFICATION',
    'uses': 'USE_AMPLIFICATION',
    'expiry': 'EXPIRY_AMPLIFICATION',
}
actual = hashlib.sha256(scenario_path.read_bytes()).hexdigest()
assert receipt['artifact_sha256'] == actual
assert receipt['verified_state'] == 'DELEGATION_ATTENUATION_EXECUTED'
print(json.dumps({
    'elite_core': 'PASS',
    'root_token': scenario['root']['token_id'],
    'child_token': scenario['child']['token_id'],
    'amplification_refusals': scenario['amplification_refusals'],
    'artifact_sha256': actual,
}, indent=2))
PY
