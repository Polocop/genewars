"""Run the W1-066 evidence validator; this is read-only and never starts the guest."""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.verify_w1_066_environment_replay import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
