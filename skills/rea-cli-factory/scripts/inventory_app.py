#!/usr/bin/env python3
"""Read a selected macOS bundle's identity and hashes without executing it."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import sys


class InventoryError(Exception):
    def __init__(self, code, message, **details):
        super().__init__(message)
        self.code, self.details = code, details


def within(root, path):
    resolved = path.resolve()
    try:
        resolved.relative_to(root)
    except ValueError:
        raise InventoryError("OUTSIDE_BUNDLE", "Bundle member resolves outside the selected app")
    return resolved


def fingerprint(path):
    if not path.is_file():
        raise InventoryError("MISSING_ARTIFACT", "Expected bundle file is missing", path=str(path))
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
        after = os.fstat(stream.fileno())
    stable = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
    if stable(before) != stable(after) or stable(after) != stable(path.stat()):
        raise InventoryError("ARTIFACT_CHANGED", "Artifact changed while hashing; retry when update finishes")
    return {"path": str(path), "size_bytes": after.st_size, "sha256": digest.hexdigest()}


def find_by_name(name, roots=None):
    if not name or "/" in name or "\\" in name or name in {".", ".."}:
        raise InventoryError("INVALID_NAME", "Use an exact app name, or supply --app with a path")
    filename = name if name.lower().endswith(".app") else name + ".app"
    roots = roots or [Path("/Applications"), Path.home() / "Applications", Path("/System/Applications"), Path("/System/Applications/Utilities")]
    matches = set()
    for root in roots:
        if root.is_dir():
            for item in root.iterdir():
                if item.name.casefold() == filename.casefold() and item.is_dir():
                    matches.add(item.resolve())
    matches = sorted(matches, key=str)
    if len(matches) != 1:
        raise InventoryError("AMBIGUOUS_TARGET" if matches else "TARGET_NOT_FOUND", "Select one explicit --app path", candidates=[str(p) for p in matches])
    return matches[0]


def inventory(app):
    root = Path(app).expanduser().resolve()
    if root.suffix.lower() != ".app" or not root.is_dir():
        raise InventoryError("INVALID_APP", "Expected an existing .app directory")
    info_path = within(root, root / "Contents/Info.plist")
    info_hash = fingerprint(info_path)
    with info_path.open("rb") as stream:
        info = plistlib.load(stream)
    if not isinstance(info, dict):
        raise InventoryError("INVALID_PLIST", "Info.plist must contain a dictionary")
    if fingerprint(info_path) != info_hash:
        raise InventoryError("ARTIFACT_CHANGED", "Info.plist changed while reading")
    executable = info.get("CFBundleExecutable")
    if not isinstance(executable, str) or not executable or Path(executable).name != executable or executable in {".", ".."}:
        raise InventoryError("INVALID_EXECUTABLE", "Bundle executable must be a single filename")
    artifacts = {"info_plist": info_hash, "executable": fingerprint(within(root, root / "Contents/MacOS" / executable))}
    asar_path = within(root, root / "Contents/Resources/app.asar")
    if asar_path.exists():
        artifacts["app_asar"] = fingerprint(asar_path)
    identity = {key: info.get(key) for key in ["CFBundleIdentifier", "CFBundleName", "CFBundleShortVersionString", "CFBundleVersion", "CFBundleExecutable"]}
    if any(value is not None and not isinstance(value, str) for value in identity.values()):
        raise InventoryError("INVALID_IDENTITY", "Bundle identity fields must be strings")
    return {"schema": "rea-cli-factory.app-inventory.v1", "app_path": str(root), "identity": identity, "artifacts": artifacts, "analysis": {"kind": "bundle-inventory", "rea_executed": False, "runtime_observed": False, "code_signature_verified": False, "scope": "Info.plist, main executable, and app.asar when present; not a full bundle digest"}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--app", help="Explicit .app bundle path")
    choice.add_argument("--name", help="Exact app name in standard installation directories")
    args = parser.parse_args()
    try:
        result = inventory(args.app or find_by_name(args.name))
        print(json.dumps({"ok": True, "result": result}, ensure_ascii=False, indent=2))
        return 0
    except (InventoryError, OSError, plistlib.InvalidFileException, ValueError, TypeError) as exc:
        code = getattr(exc, "code", "READ_FAILED")
        print(json.dumps({"ok": False, "error": {"code": code, "message": str(exc), **getattr(exc, "details", {})}}, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    sys.exit(main())
