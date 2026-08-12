#!/bin/sh
set -eu
python3 /tests/verify.py --workspace /workspace --protected /protected --result /logs/verifier/result.json
python3 -c 'import json; print(1 if json.load(open("/logs/verifier/result.json"))["passed"] else 0)' > /logs/verifier/reward.txt
