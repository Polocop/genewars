#!/usr/bin/env python3
"""Use the bounded W3-237 capture with the W3-239 instruction probe."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import w3_237_bx1_dynamic_pairing_runner as capture

capture.TASK_ID = "W3-239"
capture.RUN_ID = "w3-239-bx1-dynamic-pairing-20261009-01"
capture.TRACE = capture.MOUNT / "W3_239_BX1_PAIRING.jsonl"
capture.RESULT = capture.ROOT / "evidence/w3_239_bx1_dynamic_pairing.json"
capture.REPORT = capture.ROOT / "reports/coordination/w3_239_bx1_dynamic_pairing.md"


if __name__ == "__main__":
    try:
        raise SystemExit(capture.main())
    except Exception as exc:
        print(f"PREFLIGHT/REPLAY FAILED CLOSED: {exc}", file=sys.stderr)
        raise SystemExit(2)
