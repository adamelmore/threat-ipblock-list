"""Unit tests for sync_threat_list helpers and main flow."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import sync_threat_list as m


class TestParseVarFile(unittest.TestCase):
    def test_key_value_and_comments(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "t.var")
            Path(path).write_text(
                "# comment\n\nSOURCE_FILE=/tmp/a\nVERBOSE=true\n",
                encoding="utf-8",
            )
            got = m.parse_var_file(path)
            self.assertEqual(got["SOURCE_FILE"], "/tmp/a")
            self.assertEqual(got["VERBOSE"], "true")

    def test_missing_file_empty(self):
        self.assertEqual(m.parse_var_file("/no/such/file.var"), {})


class TestMergeVarSettings(unittest.TestCase):
    def test_custom_overrides_default(self):
        with tempfile.TemporaryDirectory() as d:
            default_path = os.path.join(d, "default.var")
            custom_path = os.path.join(d, "custom.var")
            Path(default_path).write_text(
                "CURRENT_FILE=THREAT.txt\nGIT_PUSH=true\n",
                encoding="utf-8",
            )
            Path(custom_path).write_text("GIT_PUSH=false\n", encoding="utf-8")
            merged = m.merge_var_settings(default_path, custom_path)
            self.assertEqual(merged["CURRENT_FILE"], "THREAT.txt")
            self.assertEqual(merged["GIT_PUSH"], "false")


class TestVarSettingsToArgDefaults(unittest.TestCase):
    def test_bool_and_paths(self):
        d = m.var_settings_to_arg_defaults(
            {
                "SOURCE_FILE": "/src/list.txt",
                "GIT_COMMIT": "yes",
                "GIT_PUSH": "0",
                "VERBOSE": "on",
                "DRY_RUN": "false",
            }
        )
        self.assertEqual(d["source_file"], "/src/list.txt")
        self.assertTrue(d["git_commit"])
        self.assertFalse(d["git_push"])
        self.assertTrue(d["verbose"])
        self.assertFalse(d["dry_run"])


class TestContentDiffers(unittest.TestCase):
    def test_missing_current_is_different(self):
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "src.txt")
            Path(src).write_text("a\n", encoding="utf-8")
            self.assertTrue(m.content_differs(src, os.path.join(d, "missing.txt")))

    def test_identical_content(self):
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "src.txt")
            cur = os.path.join(d, "cur.txt")
            Path(src).write_text("same\n", encoding="utf-8")
            Path(cur).write_text("same\n", encoding="utf-8")
            self.assertFalse(m.content_differs(src, cur))

    def test_different_content(self):
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "src.txt")
            cur = os.path.join(d, "cur.txt")
            Path(src).write_text("new\n", encoding="utf-8")
            Path(cur).write_text("old\n", encoding="utf-8")
            self.assertTrue(m.content_differs(src, cur))


class TestCopySourceToCurrent(unittest.TestCase):
    def test_overwrites_keeping_dest_name(self):
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "incoming.txt")
            cur = os.path.join(d, "THREAT.txt")
            Path(src).write_text("payload\n", encoding="utf-8")
            Path(cur).write_text("old\n", encoding="utf-8")
            m.copy_source_to_current(src, cur)
            self.assertEqual(Path(cur).read_text(encoding="utf-8"), "payload\n")
            self.assertTrue(os.path.isfile(src))


class TestMainFlow(unittest.TestCase):
    def test_unchanged_skips_git(self):
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "src.txt")
            cur = os.path.join(d, "THREAT.txt")
            Path(src).write_text("same\n", encoding="utf-8")
            Path(cur).write_text("same\n", encoding="utf-8")
            with mock.patch.object(m, "run_git") as run_git:
                rc = m.main(
                    [
                        "--source-file",
                        src,
                        "--current-file",
                        "THREAT.txt",
                        "--repo-dir",
                        d,
                    ]
                )
            self.assertEqual(rc, 0)
            run_git.assert_not_called()

    def test_dry_run_does_not_copy_or_git(self):
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "src.txt")
            cur = os.path.join(d, "THREAT.txt")
            Path(src).write_text("new\n", encoding="utf-8")
            Path(cur).write_text("old\n", encoding="utf-8")
            with mock.patch.object(m, "run_git") as run_git:
                rc = m.main(
                    [
                        "--source-file",
                        src,
                        "--current-file",
                        "THREAT.txt",
                        "--repo-dir",
                        d,
                        "--dry-run",
                    ]
                )
            self.assertEqual(rc, 0)
            self.assertEqual(Path(cur).read_text(encoding="utf-8"), "old\n")
            run_git.assert_not_called()

    def test_update_commit_push(self):
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "src.txt")
            cur = os.path.join(d, "THREAT.txt")
            Path(src).write_text("new\n", encoding="utf-8")
            Path(cur).write_text("old\n", encoding="utf-8")
            Path(d, ".git").mkdir()

            def fake_run_git(repo_dir, args, *, check=True, capture_output=True):
                if list(args[:2]) == ["diff", "--cached"]:
                    return subprocess.CompletedProcess(
                        args=["git", *args],
                        returncode=1,
                        stdout="",
                        stderr="",
                    )
                return subprocess.CompletedProcess(
                    args=["git", *args],
                    returncode=0,
                    stdout="",
                    stderr="",
                )

            with mock.patch.object(m, "run_git", side_effect=fake_run_git) as run_git:
                rc = m.main(
                    [
                        "--source-file",
                        src,
                        "--current-file",
                        "THREAT.txt",
                        "--repo-dir",
                        d,
                        "--git-commit-message",
                        "Update THREAT.txt",
                    ]
                )
            self.assertEqual(rc, 0)
            self.assertEqual(Path(cur).read_text(encoding="utf-8"), "new\n")
            calls = [list(c.args[1]) for c in run_git.call_args_list]
            self.assertIn(["add", "--", "THREAT.txt"], calls)
            self.assertIn(["commit", "-m", "Update THREAT.txt"], calls)
            self.assertIn(["push", "origin", "main"], calls)

    def test_missing_source_fails(self):
        with tempfile.TemporaryDirectory() as d:
            rc = m.main(
                [
                    "--source-file",
                    os.path.join(d, "missing.txt"),
                    "--repo-dir",
                    d,
                    "--no-git-commit",
                ]
            )
            self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
