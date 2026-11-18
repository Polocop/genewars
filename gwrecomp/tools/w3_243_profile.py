"""Resolve the bounded DOS overlay used by W3-243's guarded replay."""

from pathlib import Path


def resolve_profile_root(root: Path, configured: str | None, vhdx_mount: Path) -> Path:
    """Return a fresh profile under the verified VHDX mount, failing closed."""
    root = root.resolve()
    vhdx_mount = vhdx_mount.resolve()
    candidate = Path(configured) if configured else root / "build" / "dos_user_profile_w2_036"
    candidate = candidate.resolve()
    try:
        candidate.relative_to(vhdx_mount)
    except ValueError as exc:
        raise ValueError("W3-243 overlay must remain under the GWORACLE mount") from exc
    if candidate.exists():
        raise FileExistsError(f"W3-243 overlay already exists; refusing reuse: {candidate}")
    return candidate
