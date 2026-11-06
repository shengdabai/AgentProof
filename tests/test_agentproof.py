import json
import os
import struct
import tempfile
import unittest
import sys
from pathlib import Path
from unittest.mock import patch

import agentproof


def tiny_png(width: int, height: int) -> bytes:
    return b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + struct.pack(">II", width, height) + b"\x08\x02\x00\x00\x00"


class AgentProofTests(unittest.TestCase):
    def restore_fixture(self, root):
        project = root / "project"
        project.mkdir()
        (project / "a.txt").write_text("baseline a")
        (project / "b.txt").write_text("baseline b")
        baseline = root / "snapshot"
        manifest_path = agentproof.snapshot_project(project, baseline)
        for name in ("a.txt", "b.txt"):
            (project / name).write_text("keep current")
        return project, baseline, manifest_path

    def test_restore_rejects_backup_path_substitution_before_reading(self):
        for backup in ("../outside.txt", "/outside.txt", "files/b.txt", "files/../outside.txt"):
            with self.subTest(backup=backup), tempfile.TemporaryDirectory() as temp:
                project, baseline, manifest_path = self.restore_fixture(Path(temp))
                manifest = json.loads(manifest_path.read_text())
                manifest["entries"]["a.txt"]["backup"] = backup
                manifest_path.write_text(json.dumps(manifest))
                with patch.object(agentproof, "sha256_file", side_effect=AssertionError("must not read")), \
                     patch.object(agentproof.shutil, "copy2", side_effect=AssertionError("must not copy")):
                    with self.assertRaises(agentproof.AgentProofError):
                        agentproof.restore_snapshot(project, baseline, selected=["a.txt"], yes=True)
                self.assertEqual((project / "a.txt").read_text(), "keep current")

    def test_restore_rejects_bad_digest_in_preview_and_apply(self):
        for digest in (None, "bad", "0" * 64):
            for yes in (False, True):
                with self.subTest(digest=digest, yes=yes), tempfile.TemporaryDirectory() as temp:
                    project, baseline, manifest_path = self.restore_fixture(Path(temp))
                    manifest = json.loads(manifest_path.read_text())
                    manifest["entries"]["a.txt"]["sha256"] = digest
                    manifest_path.write_text(json.dumps(manifest))
                    with self.assertRaises(agentproof.AgentProofError):
                        agentproof.restore_snapshot(project, baseline, yes=yes)
                    self.assertEqual((project / "a.txt").read_text(), "keep current")

    def test_restore_preflights_all_backups_before_writing(self):
        with tempfile.TemporaryDirectory() as temp:
            project, baseline, _ = self.restore_fixture(Path(temp))
            (baseline / "files/b.txt").write_text("tampered b")
            with self.assertRaises(agentproof.AgentProofError):
                agentproof.restore_snapshot(project, baseline, yes=True)
            for name in ("a.txt", "b.txt"):
                self.assertEqual((project / name).read_text(), "keep current")

    def test_restore_rejects_symlinked_backup_file_and_directory(self):
        for directory in (False, True):
            with self.subTest(directory=directory), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                project, baseline, _ = self.restore_fixture(root)
                if directory:
                    (baseline / "files").rename(root / "other-files")
                    (baseline / "files").symlink_to(root / "other-files", target_is_directory=True)
                else:
                    (baseline / "files/a.txt").unlink()
                    (baseline / "files/a.txt").symlink_to(baseline / "files/b.txt")
                with self.assertRaises(agentproof.AgentProofError):
                    agentproof.restore_snapshot(project, baseline, selected=["a.txt"], yes=True)

    def test_restore_rejects_symlinked_destination_even_inside_project(self):
        with tempfile.TemporaryDirectory() as temp:
            project, baseline, _ = self.restore_fixture(Path(temp))
            (project / "a.txt").unlink()
            (project / "a.txt").symlink_to(project / "b.txt")
            with self.assertRaises(agentproof.AgentProofError):
                agentproof.restore_snapshot(project, baseline, selected=["a.txt"], yes=True)
            self.assertEqual((project / "b.txt").read_text(), "keep current")

    def test_restore_replaces_hardlink_without_overwriting_other_file(self):
        with tempfile.TemporaryDirectory() as temp:
            project, baseline, _ = self.restore_fixture(Path(temp))
            (project / "a.txt").unlink()
            os.link(project / "b.txt", project / "a.txt")  # Path.hardlink_to needs Python 3.10+
            agentproof.restore_snapshot(project, baseline, selected=["a.txt"], yes=True)
            self.assertEqual((project / "a.txt").read_text(), "baseline a")
            self.assertEqual((project / "b.txt").read_text(), "keep current")

    def test_restore_recreates_missing_nested_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            project = root / "project"
            (project / "nested").mkdir(parents=True)
            target = project / "nested/file.txt"
            target.write_text("original")
            baseline = root / "snapshot"
            agentproof.snapshot_project(project, baseline)
            target.unlink()
            target.parent.rmdir()
            result = agentproof.restore_snapshot(project, baseline, yes=True)
            self.assertEqual(result["plan"], [{"path": "nested/file.txt", "action": "recreate"}])
            self.assertEqual(target.read_text(), "original")

    def test_restore_failure_leaves_target_and_cleans_own_tempfile(self):
        with tempfile.TemporaryDirectory() as temp:
            project, baseline, _ = self.restore_fixture(Path(temp))
            with patch.object(agentproof.shutil, "copy2", side_effect=OSError("fixture copy failure")):
                with self.assertRaises(agentproof.AgentProofError):
                    agentproof.restore_snapshot(project, baseline, selected=["a.txt"], yes=True)
            self.assertEqual((project / "a.txt").read_text(), "keep current")
            self.assertEqual(list(project.glob(".agentproof-*")), [])

    def test_restore_rejects_unknown_selection(self):
        with tempfile.TemporaryDirectory() as temp:
            project, baseline, _ = self.restore_fixture(Path(temp))
            with self.assertRaises(agentproof.AgentProofError):
                agentproof.restore_snapshot(project, baseline, selected=["typo.txt"], yes=True)

    def test_restore_refuses_backup_changed_after_preflight(self):
        with tempfile.TemporaryDirectory() as temp:
            project, baseline, _ = self.restore_fixture(Path(temp))
            original_copy = agentproof.shutil.copy2
            def changed_copy(source, target):
                source.write_text("changed after preflight")
                return original_copy(source, target)
            with patch.object(agentproof.shutil, "copy2", side_effect=changed_copy):
                with self.assertRaises(agentproof.AgentProofError):
                    agentproof.restore_snapshot(project, baseline, selected=["a.txt"], yes=True)
            self.assertEqual((project / "a.txt").read_text(), "keep current")
            self.assertEqual(list(project.glob(".agentproof-*")), [])

    def test_restore_does_not_trust_sensitive_flag_from_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            project, baseline, manifest_path = self.restore_fixture(Path(temp))
            manifest = json.loads(manifest_path.read_text())
            entry = manifest["entries"].pop("a.txt")
            entry["backup"] = "files/.env"
            manifest["entries"][".env"] = entry
            manifest["sensitive_patterns"] = []
            manifest_path.write_text(json.dumps(manifest))
            with patch.object(agentproof, "sha256_file", side_effect=AssertionError("must not read")):
                result = agentproof.restore_snapshot(project, baseline, selected=[".env"], yes=True)
            self.assertEqual(result["plan"][0]["action"], "skip")
            self.assertFalse((project / ".env").exists())

    def test_manifest_rejects_invalid_shapes_and_entry_paths(self):
        invalid = [[], None, {"schema_version": 1, "entries": {"ok.txt": None}}]
        for path in ("../escape.txt", "/outside.txt", "./file.txt", ".", "a/../file.txt"):
            invalid.append({"schema_version": 1, "entries": {path: {}}})
        invalid.append({"schema_version": 1, "entries": {}, "sensitive_patterns": "*.txt"})
        with tempfile.TemporaryDirectory() as temp:
            manifest = Path(temp) / "manifest.json"
            for data in invalid:
                with self.subTest(data=data):
                    manifest.write_text(json.dumps(data))
                    with self.assertRaises(agentproof.AgentProofError):
                        agentproof.load_manifest(manifest)

    def test_sensitive_artifact_checks_do_not_open_content(self):
        paths = (".env", "nested/.env.local", "nested/.ssh/config", "nested/.aws/credentials",
                 "credentials", "nested/secrets", ".npmrc", "auth.json", ".ENV.local", "nested/.SSH/config")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for relative in paths:
                with self.subTest(path=relative):
                    path = root / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("fixture only")
                    with patch.object(agentproof, "sha256_file", side_effect=AssertionError("must not hash")), \
                         patch.object(agentproof, "image_dimensions", side_effect=AssertionError("must not open")):
                        result = agentproof.check_artifact(root, {"path": relative, "sha256": "0" * 64, "image": {}})
                    self.assertFalse(result["passed"])
                    self.assertIn("sensitive", result["problems"][0])

    def test_sensitive_artifact_symlink_alias_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / ".env").write_text("fixture only")
            (root / "alias.txt").symlink_to(root / ".env")
            with patch.object(agentproof, "sha256_file", side_effect=AssertionError("must not hash")):
                result = agentproof.check_artifact(root, {"path": "alias.txt", "sha256": "0" * 64})
            self.assertFalse(result["passed"])

    def test_sensitive_word_prefix_documents_are_tracked_normally(self):
        for relative in ("docs/secrets-guide.md", "docs/credentials-guide.md"):
            with self.subTest(path=relative), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                project = root / "project"
                document = project / relative
                document.parent.mkdir(parents=True)
                document.write_text("original guide")
                baseline = root / "snapshot"
                manifest_path = agentproof.snapshot_project(project, baseline)
                entry = json.loads(manifest_path.read_text())["entries"][relative]
                self.assertFalse(entry["sensitive"])
                self.assertEqual(entry["sha256"], agentproof.sha256_file(document))
                self.assertEqual(entry["backup"], f"files/{relative}")
                self.assertEqual((baseline / entry["backup"]).read_text(), "original guide")

                document.write_text("updated guide with more detail")
                config = root / "config.json"
                config.write_text(json.dumps({"artifacts": [{"path": relative}]}))
                report = agentproof.verify_project(project, baseline, config, root / "report")
                self.assertTrue(report["passed"])
                self.assertEqual(report["changes"]["modified"], [relative])
                self.assertEqual(report["sensitive_changes"], [])

    def test_sensitive_exact_names_and_extensions_remain_metadata_only(self):
        paths = ("secrets", "credentials", "secrets.json", "credentials.yaml",
                 "nested/SECRETS.JSON", "nested/CREDENTIALS.YAML",
                 "nested/secrets/config.txt", "nested/credentials/config.txt",
                 "secrets_prod.json", "secrets-dev.yaml", "credentials_backup.json",
                 "nested/credentials-prod.json")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            project = root / "project"
            for relative in paths:
                path = project / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture only")
            with patch.object(agentproof, "sha256_file", side_effect=AssertionError("must not hash")), \
                 patch.object(agentproof.shutil, "copy2", side_effect=AssertionError("must not copy")):
                manifest_path = agentproof.snapshot_project(project, root / "snapshot")
            entries = json.loads(manifest_path.read_text())["entries"]
            self.assertEqual(set(entries), set(paths))
            for relative in paths:
                with self.subTest(path=relative):
                    self.assertTrue(entries[relative]["sensitive"])
                    self.assertIsNone(entries[relative]["sha256"])
                    self.assertIsNone(entries[relative]["backup"])

    def test_custom_patterns_extend_default_sensitive_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            project = root / "project"
            (project / "nested/.ssh").mkdir(parents=True)
            for relative in (".env", "custom.txt", "nested/.ssh/config"):
                (project / relative).write_text("fixture only")
            with patch.object(agentproof, "sha256_file", side_effect=AssertionError("must not hash")):
                path = agentproof.snapshot_project(project, root / "snapshot", sensitive_patterns=["custom.txt"])
            manifest = json.loads(path.read_text())
            self.assertTrue(all(entry["sensitive"] for entry in manifest["entries"].values()))
            self.assertTrue(all(entry["backup"] is None for entry in manifest["entries"].values()))

    def test_snapshot_does_not_open_named_pipes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            project = root / "project"
            project.mkdir()
            os.mkfifo(project / "pipe")
            with patch.object(agentproof, "sha256_file", side_effect=AssertionError("must not open FIFO")):
                path = agentproof.snapshot_project(project, root / "snapshot")
            entry = json.loads(path.read_text())["entries"]["pipe"]
            self.assertEqual(entry["type"], "special")
            self.assertIsNone(entry["backup"])

    def test_sensitive_permission_change_fails_verification_without_reading(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            project = root / "project"
            project.mkdir()
            target = project / ".env"
            target.write_text("fixture only")
            target.chmod(0o600)
            baseline = root / "snapshot"
            agentproof.snapshot_project(project, baseline)
            target.chmod(0o644)
            config = root / "config.json"
            config.write_text("{}")
            with patch.object(agentproof, "sha256_file", side_effect=AssertionError("must not hash")):
                report = agentproof.verify_project(project, baseline, config, root / "report")
            self.assertFalse(report["passed"])
            self.assertEqual(report["sensitive_changes"], [".env"])

    def test_verify_applies_custom_sensitive_patterns_to_artifacts(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            project = root / "project"
            project.mkdir()
            (project / "private.txt").write_text("fixture only")
            baseline = root / "snapshot"
            agentproof.snapshot_project(project, baseline, sensitive_patterns=["private.txt"])
            config = root / "config.json"
            config.write_text(json.dumps({"artifacts": [{"path": "private.txt", "sha256": "0" * 64}]}))
            with patch.object(agentproof, "sha256_file", side_effect=AssertionError("must not hash")):
                report = agentproof.verify_project(project, baseline, config, root / "report")
            self.assertFalse(report["passed"])
            self.assertIn("sensitive", report["artifacts"][0]["problems"][0])

    def test_timeout_with_partial_output_returns_failed_check(self):
        with tempfile.TemporaryDirectory() as temp:
            result = agentproof.run_command_check(Path(temp), {
                "argv": [sys.executable, "-c",
                         "import time; print('partial output', flush=True); time.sleep(5)"],
                "timeout": 1,
            })
            self.assertFalse(result["passed"])
            self.assertIn("timed out", result["error"])
            self.assertIn("partial output", result["stdout_tail"])

    def test_non_utf8_output_is_reported_without_crashing(self):
        with tempfile.TemporaryDirectory() as temp:
            result = agentproof.run_command_check(Path(temp), {
                "argv": [sys.executable, "-c", "import os; os.write(1, b'hello\\xff')"],
            })
            self.assertTrue(result["passed"])
            self.assertIn("hello", result["stdout_tail"])

    def test_config_rejects_non_object_checks(self):
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp) / "config.json"
            for field in ("commands", "artifacts"):
                for entry in (None, 42, "echo hello", []):
                    with self.subTest(field=field, entry=entry):
                        config.write_text(json.dumps({field: [entry]}))
                        with self.assertRaises(agentproof.AgentProofError):
                            agentproof.load_config(config)

    def test_snapshot_verify_detects_changes_and_passes_checks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            project = root / "project"
            project.mkdir()
            (project / "keep.txt").write_text("before", encoding="utf-8")
            (project / "delete.txt").write_text("delete me", encoding="utf-8")
            (project / "artifact.png").write_bytes(tiny_png(1242, 2600))
            baseline = root / "snapshot"
            agentproof.snapshot_project(project, baseline)

            (project / "keep.txt").write_text("after", encoding="utf-8")
            (project / "delete.txt").unlink()
            (project / "added.txt").write_text("new", encoding="utf-8")
            config = root / "config.json"
            config.write_text(
                json.dumps(
                    {
                        "commands": [{"name": "python", "argv": ["python3", "-c", "print('ok')"]}],
                        "artifacts": [
                            {
                                "name": "image",
                                "path": "artifact.png",
                                "min_bytes": 20,
                                "image": {"min_width": 1200, "min_height": 2000},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            report = agentproof.verify_project(project, baseline, config, root / "report")
            self.assertTrue(report["passed"])
            self.assertEqual(report["changes"]["modified"], ["keep.txt"])
            self.assertEqual(report["changes"]["deleted"], ["delete.txt"])
            self.assertEqual(report["changes"]["added"], ["added.txt"])
            self.assertTrue((root / "report" / "report.html").is_file())

    def test_sensitive_file_is_metadata_only(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            project = root / "project"
            project.mkdir()
            (project / ".env").write_text("API_KEY=dummy-test-only", encoding="utf-8")
            manifest_path = agentproof.snapshot_project(project, root / "snapshot")
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            entry = manifest["entries"][".env"]
            self.assertTrue(entry["sensitive"])
            self.assertIsNone(entry["sha256"])
            self.assertIsNone(entry["backup"])

    def test_restore_requires_explicit_yes_and_never_deletes_added_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            project = root / "project"
            project.mkdir()
            tracked = project / "tracked.txt"
            tracked.write_text("safe baseline", encoding="utf-8")
            baseline = root / "snapshot"
            agentproof.snapshot_project(project, baseline)
            tracked.write_text("broken", encoding="utf-8")
            added = project / "added.txt"
            added.write_text("keep me", encoding="utf-8")

            preview = agentproof.restore_snapshot(project, baseline, selected=["tracked.txt"])
            self.assertEqual(preview["mode"], "preview")
            self.assertEqual(tracked.read_text(encoding="utf-8"), "broken")
            applied = agentproof.restore_snapshot(project, baseline, selected=["tracked.txt"], yes=True)
            self.assertEqual(applied["mode"], "applied")
            self.assertEqual(tracked.read_text(encoding="utf-8"), "safe baseline")
            self.assertEqual(added.read_text(encoding="utf-8"), "keep me")

    def test_sensitive_change_fails_verification(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            project = root / "project"
            project.mkdir()
            secret = project / ".env"
            secret.write_text("A=one", encoding="utf-8")
            baseline = root / "snapshot"
            agentproof.snapshot_project(project, baseline)
            secret.write_text("A=two", encoding="utf-8")
            config = root / "config.json"
            config.write_text('{"commands": [], "artifacts": []}', encoding="utf-8")
            report = agentproof.verify_project(project, baseline, config, root / "report")
            self.assertFalse(report["passed"])
            self.assertEqual(report["sensitive_changes"], [".env"])

    def test_failed_command_and_missing_artifact_fail_report(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            project = root / "project"
            project.mkdir()
            (project / "source.txt").write_text("baseline", encoding="utf-8")
            baseline = root / "snapshot"
            agentproof.snapshot_project(project, baseline)
            config = root / "config.json"
            config.write_text(
                json.dumps(
                    {
                        "commands": [
                            {"name": "intentional failure", "argv": ["python3", "-c", "raise SystemExit(7)"]}
                        ],
                        "artifacts": [{"name": "missing output", "path": "missing.html"}],
                    }
                ),
                encoding="utf-8",
            )
            report = agentproof.verify_project(project, baseline, config, root / "report")
            self.assertFalse(report["passed"])
            self.assertEqual(report["commands"][0]["exit_code"], 7)
            self.assertEqual(report["artifacts"][0]["problems"], ["file does not exist"])

    def test_artifact_path_cannot_escape_project(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            project = root / "project"
            project.mkdir()
            result = agentproof.check_artifact(project, {"name": "escape", "path": "../outside.txt"})
            self.assertFalse(result["passed"])
            self.assertIn("escapes project", result["problems"][0])


if __name__ == "__main__":
    unittest.main()
