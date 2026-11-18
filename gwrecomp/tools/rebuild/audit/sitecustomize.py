# Optional file-access audit for the build (enabled by PYTHONPATH=<this dir> and GW_AUDIT_LOG). Read-only observation; records
# open() paths/modes and subprocess commands for every Python process of the build (driver and lifter subprocess).
import os, sys, json
_log = os.environ.get("GW_AUDIT_LOG")
if _log:
    _pid = os.getpid()
    _busy = [False]
    def _hook(event, args):
        if _busy[0]: return
        _busy[0] = True
        try:
            if event == "open":
                p, mode, flags = args
                if isinstance(p, (str, bytes, os.PathLike)):
                    p = os.fsdecode(p)
                    if p.endswith((".pyc", ".pyd", ".dll")) or "\\Lib\\" in p or "/Lib/" in p: return
                    with open(_log, "a", encoding="utf-8") as f: f.write(json.dumps({"pid": _pid, "ev": "open", "path": p, "mode": mode, "flags": flags}) + "\n")
            elif event == "subprocess.Popen":
                exe, argv, cwd, env = args
                with open(_log, "a", encoding="utf-8") as f: f.write(json.dumps({"pid": _pid, "ev": "exec", "exe": str(exe), "argv": [str(a) for a in argv][:60], "cwd": str(cwd)}) + "\n")
        except Exception:
            pass
        finally:
            _busy[0] = False
    sys.addaudithook(_hook)
