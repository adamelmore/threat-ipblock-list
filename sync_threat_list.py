#!/usr/bin/env python3
"""
Sync a source threat IP list into this repo's CURRENT_FILE, then optionally
git commit and push when content has changed.

Compare rule: SHA-256 of file contents. Missing CURRENT_FILE counts as changed.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union

DEFAULT_VAR_BASENAME = "sync_threat_list.default.var"
DEFAULT_CURRENT_FILE = "THREAT.txt"
DEFAULT_GIT_REMOTE = "origin"
DEFAULT_GIT_BRANCH = "main"
DEFAULT_GIT_COMMIT_MESSAGE = "Update THREAT.txt"


def script_directory() -> str:
    return os.path.dirname(os.path.abspath(__file__))


def default_var_file_path() -> str:
    return os.path.join(script_directory(), DEFAULT_VAR_BASENAME)


def _parse_bool_var(value: str) -> bool:
    v = value.strip().lower()
    return v in ("1", "true", "yes", "on")


def parse_var_file(path: str) -> Dict[str, Union[str, List[str]]]:
    """
    Load KEY=value lines. Blank lines and lines starting with # are ignored.
    Leading/trailing whitespace on keys and values is stripped.
    Duplicate keys: later line replaces.
    """
    out: Dict[str, Union[str, List[str]]] = {}
    if not os.path.isfile(path):
        return out
    with open(path, "r", encoding="utf-8", newline="") as f:
        for line in f:
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue
            if "=" not in raw:
                continue
            key, val = raw.split("=", 1)
            key_u = key.strip().upper()
            val_s = val.strip()
            if not key_u:
                continue
            out[key_u] = val_s
    return out


def merge_var_settings(
    default_path: str,
    custom_path: Optional[str],
) -> Dict[str, Union[str, List[str]]]:
    merged = dict(parse_var_file(default_path))
    if not custom_path:
        return merged
    merged.update(parse_var_file(custom_path))
    return merged


def var_settings_to_arg_defaults(
    var: Mapping[str, Union[str, List[str]]],
) -> Dict[str, Any]:
    d: Dict[str, Any] = {}
    if "SOURCE_FILE" in var and str(var["SOURCE_FILE"]).strip():
        d["source_file"] = str(var["SOURCE_FILE"]).strip()
    if "CURRENT_FILE" in var and str(var["CURRENT_FILE"]).strip():
        d["current_file"] = str(var["CURRENT_FILE"]).strip()
    if "REPO_DIR" in var and str(var["REPO_DIR"]).strip():
        d["repo_dir"] = str(var["REPO_DIR"]).strip()
    if "GIT_COMMIT" in var and str(var["GIT_COMMIT"]).strip():
        d["git_commit"] = _parse_bool_var(str(var["GIT_COMMIT"]))
    if "GIT_PUSH" in var and str(var["GIT_PUSH"]).strip():
        d["git_push"] = _parse_bool_var(str(var["GIT_PUSH"]))
    if "GIT_REMOTE" in var and str(var["GIT_REMOTE"]).strip():
        d["git_remote"] = str(var["GIT_REMOTE"]).strip()
    if "GIT_BRANCH" in var and str(var["GIT_BRANCH"]).strip():
        d["git_branch"] = str(var["GIT_BRANCH"]).strip()
    if "GIT_COMMIT_MESSAGE" in var and str(var["GIT_COMMIT_MESSAGE"]).strip():
        d["git_commit_message"] = str(var["GIT_COMMIT_MESSAGE"]).strip()
    if "VERBOSE" in var and str(var["VERBOSE"]).strip():
        d["verbose"] = _parse_bool_var(str(var["VERBOSE"]))
    if "DRY_RUN" in var and str(var["DRY_RUN"]).strip():
        d["dry_run"] = _parse_bool_var(str(var["DRY_RUN"]))
    return d


def extract_var_file_argv(argv: List[str]) -> Tuple[Optional[str], List[str]]:
    var_file: Optional[str] = None
    rest: List[str] = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--var-file":
            if i + 1 >= len(argv):
                raise ValueError("--var-file requires a path")
            var_file = argv[i + 1]
            i += 2
        elif a.startswith("--var-file="):
            var_file = a.split("=", 1)[1]
            i += 1
        else:
            rest.append(a)
            i += 1
    return var_file, rest


def file_sha256(path: str) -> bytes:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.digest()


def resolve_current_path(repo_dir: str, current_file: str) -> str:
    if os.path.isabs(current_file):
        return current_file
    return os.path.join(repo_dir, current_file)


def content_differs(source_path: str, current_path: str) -> bool:
    if not os.path.isfile(current_path):
        return True
    return file_sha256(source_path) != file_sha256(current_path)


def run_git(
    repo_dir: str,
    args: Sequence[str],
    *,
    check: bool = True,
    capture_output: bool = True,
) -> subprocess.CompletedProcess[str]:
    cmd = ["git", "-C", repo_dir, *args]
    return subprocess.run(
        cmd,
        check=check,
        capture_output=capture_output,
        text=True,
    )


def git_has_staged_changes(repo_dir: str) -> bool:
    proc = run_git(repo_dir, ["diff", "--cached", "--quiet"], check=False)
    return proc.returncode == 1


def copy_source_to_current(source_path: str, current_path: str) -> None:
    parent = os.path.dirname(current_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    shutil.copy2(source_path, current_path)


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    argv_list = list(sys.argv[1:] if argv is None else argv)
    try:
        var_path_opt, argv_rest = extract_var_file_argv(argv_list)
    except ValueError as exc:
        raise SystemExit(f"error: {exc}") from exc

    var = merge_var_settings(default_var_file_path(), var_path_opt)
    runtime_defaults = {
        "source_file": None,
        "current_file": DEFAULT_CURRENT_FILE,
        "repo_dir": script_directory(),
        "git_commit": True,
        "git_push": True,
        "git_remote": DEFAULT_GIT_REMOTE,
        "git_branch": DEFAULT_GIT_BRANCH,
        "git_commit_message": DEFAULT_GIT_COMMIT_MESSAGE,
        "verbose": False,
        "dry_run": False,
    }
    runtime_defaults.update(var_settings_to_arg_defaults(var))

    p = argparse.ArgumentParser(
        description=(
            "Compare SOURCE_FILE to CURRENT_FILE by content hash; "
            "copy, commit, and push when changed."
        )
    )
    p.set_defaults(**runtime_defaults)
    p.add_argument(
        "--var-file",
        dest="var_file",
        default=var_path_opt,
        help=(
            f"Optional VAR overrides (default {DEFAULT_VAR_BASENAME} "
            "beside this script always loads first)"
        ),
    )
    p.add_argument(
        "--source-file",
        dest="source_file",
        help="Incoming list file to compare/copy from (required unless set in VAR)",
    )
    p.add_argument(
        "--current-file",
        dest="current_file",
        help=f"Repo list path relative to REPO_DIR or absolute (default {DEFAULT_CURRENT_FILE})",
    )
    p.add_argument(
        "--repo-dir",
        dest="repo_dir",
        help="Git repository root (default: directory containing this script)",
    )
    p.add_argument(
        "--git-commit",
        dest="git_commit",
        action="store_true",
        help="Commit CURRENT_FILE after a successful copy",
    )
    p.add_argument(
        "--no-git-commit",
        dest="git_commit",
        action="store_false",
        help="Skip git commit",
    )
    p.add_argument(
        "--git-push",
        dest="git_push",
        action="store_true",
        help="Push after commit",
    )
    p.add_argument(
        "--no-git-push",
        dest="git_push",
        action="store_false",
        help="Skip git push",
    )
    p.add_argument(
        "--git-remote",
        dest="git_remote",
        help=f"Remote name for push (default {DEFAULT_GIT_REMOTE})",
    )
    p.add_argument(
        "--git-branch",
        dest="git_branch",
        help=f"Branch name for push (default {DEFAULT_GIT_BRANCH})",
    )
    p.add_argument(
        "--git-commit-message",
        dest="git_commit_message",
        help=f"Commit message (default {DEFAULT_GIT_COMMIT_MESSAGE!r})",
    )
    p.add_argument(
        "--verbose",
        dest="verbose",
        action="store_true",
        help="Extra progress on stderr",
    )
    p.add_argument(
        "--dry-run",
        dest="dry_run",
        action="store_true",
        help="Print intended actions without copying or mutating git",
    )
    return p.parse_args(argv_rest)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    source_file = (args.source_file or "").strip()
    if not source_file:
        print(
            "error: SOURCE_FILE is required (set in VAR or pass --source-file)",
            file=sys.stderr,
        )
        return 1

    repo_dir = os.path.abspath((args.repo_dir or script_directory()).strip())
    current_file = (args.current_file or DEFAULT_CURRENT_FILE).strip()
    current_path = resolve_current_path(repo_dir, current_file)
    source_path = os.path.abspath(source_file)

    if not os.path.isfile(source_path):
        print(f"error: source file not found: {source_path}", file=sys.stderr)
        return 1

    if args.verbose:
        print(f"source: {source_path}", file=sys.stderr)
        print(f"current: {current_path}", file=sys.stderr)
        print(f"repo_dir: {repo_dir}", file=sys.stderr)

    try:
        differs = content_differs(source_path, current_path)
    except OSError as exc:
        print(f"error: failed to compare files: {exc}", file=sys.stderr)
        return 1

    if not differs:
        print(f"unchanged: {current_path}", file=sys.stderr)
        return 0

    if args.dry_run:
        print(f"dry-run: would copy {source_path} -> {current_path}", file=sys.stderr)
        if args.git_commit:
            print(
                f"dry-run: would git add/commit in {repo_dir} "
                f"({args.git_commit_message!r})",
                file=sys.stderr,
            )
            if args.git_push:
                print(
                    f"dry-run: would git push {args.git_remote} {args.git_branch}",
                    file=sys.stderr,
                )
        return 0

    try:
        copy_source_to_current(source_path, current_path)
    except OSError as exc:
        print(f"error: copy failed: {exc}", file=sys.stderr)
        return 1
    print(f"updated: {current_path}", file=sys.stderr)

    if not args.git_commit:
        return 0

    if not os.path.isdir(os.path.join(repo_dir, ".git")):
        print(f"error: not a git repository: {repo_dir}", file=sys.stderr)
        return 1

    try:
        # Stage relative path when possible so git index matches repo layout.
        add_path = current_file if not os.path.isabs(current_file) else current_path
        run_git(repo_dir, ["add", "--", add_path])
        if not git_has_staged_changes(repo_dir):
            print("warning: nothing staged after copy; skipping commit", file=sys.stderr)
            return 0
        run_git(repo_dir, ["commit", "-m", str(args.git_commit_message)])
        print(f"committed: {args.git_commit_message}", file=sys.stderr)
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "").strip()
        if detail:
            print(f"error: git commit failed: {detail}", file=sys.stderr)
        else:
            print(f"error: git commit failed (exit {exc.returncode})", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: git commit failed: {exc}", file=sys.stderr)
        return 1

    if not args.git_push:
        return 0

    try:
        run_git(repo_dir, ["push", str(args.git_remote), str(args.git_branch)])
        print(
            f"pushed: {args.git_remote} {args.git_branch}",
            file=sys.stderr,
        )
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "").strip()
        if detail:
            print(f"error: git push failed: {detail}", file=sys.stderr)
        else:
            print(f"error: git push failed (exit {exc.returncode})", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: git push failed: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
