"""Apply the versioned pcrecomp patch to a clean checkout of the pinned pcrecomp commit, verifying SHA-256 pre/post images.
usage: apply_pcrecomp_patch.py PCRECOMP_CHECKOUT PATCH_FILE PATCH_JSON
The checkout must use a CRLF working tree (core.autocrlf=true), as the patch images were taken that way. Exit code 2 on any mismatch."""
import hashlib, json, subprocess, sys
from pathlib import Path
def sha(b): return hashlib.sha256(b).hexdigest()
def die(m): print("FAIL:", m); sys.exit(2)
src, patch, js = Path(sys.argv[1]), Path(sys.argv[2]), json.loads(Path(sys.argv[3]).read_text())
if sha(patch.read_bytes()) != js["patch_sha256"]: die("pcrecomp patch content changed")
head = subprocess.run(["git", "-C", str(src), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
if head != js["base_commit"]: die(f"pcrecomp HEAD {head} != pinned {js['base_commit']}")
for c in js["changed_tracked_files"]:
    if sha((src / c["file"]).read_bytes()) != c["pre_sha256"]: die(f"pre-image mismatch {c['file']} (pinned commit or eol policy differs)")
r = subprocess.run(["git", "-C", str(src), "-c", "core.autocrlf=false", "-c", "core.safecrlf=false", "apply", "--whitespace=nowarn", "-p1", str(patch.resolve())], capture_output=True, text=True)
if r.returncode: die("git apply: " + r.stderr)
for c in js["changed_tracked_files"]:
    if sha((src / c["file"]).read_bytes()) != c["post_sha256"]: die(f"post-image mismatch {c['file']}")
print(f"OK pcrecomp patch: {len(js['changed_tracked_files'])} files verified against pinned {head[:7]}")
