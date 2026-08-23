import hashlib
import importlib.util
import base64
import io
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest


MODULE_PATH = Path(__file__).resolve().parents[1] / "gate_h_source.py"
SPEC = importlib.util.spec_from_file_location("aster_gate_h_source", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
source = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = source
SPEC.loader.exec_module(source)


COMMIT = "c" * 40
PRINCIPAL = "gate-h@example.test"
FINGERPRINT = "SHA256:fixturefp"
SOURCE_FILES = {
    ".dockerignore": ("100644", b"target\n"),
    "Cargo.toml": ("100644", b"[workspace]\nmembers=[]\n"),
    "lab/Dockerfile": ("100644", b"FROM scratch\n"),
    "script.sh": ("100755", b"#!/bin/sh\nexit 0\n"),
}


def complete_stream(value: bytes) -> dict:
    return {
        "bytes": len(value),
        "complete": True,
        "base64": base64.b64encode(value).decode("ascii"),
    }


def file_bindings() -> list[dict]:
    return [
        {
            "path": path,
            "mode": mode,
            "git_blob": source._git_blob_id(value),
            "size_bytes": len(value),
            "sha256": hashlib.sha256(value).hexdigest(),
        }
        for path, (mode, value) in sorted(SOURCE_FILES.items())
    ]


TREE = source._tree_id(file_bindings())


def write_archive(
    path: Path,
    *,
    unsafe: bool = False,
    wrong_mode: bool = False,
    extra_pax: bool = False,
    nonregular: bool = False,
) -> None:
    pax_headers = {"comment": COMMIT}
    if extra_pax:
        pax_headers["attacker"] = "true"
    with tarfile.open(
        path,
        mode="w",
        format=tarfile.PAX_FORMAT,
        pax_headers=pax_headers,
    ) as archive:
        directory = tarfile.TarInfo("lab/")
        directory.type = tarfile.DIRTYPE
        directory.mode = 0o755
        archive.addfile(directory)
        for index, (relative, (mode, value)) in enumerate(
            sorted(SOURCE_FILES.items())
        ):
            member = tarfile.TarInfo(relative)
            member.size = len(value)
            member.mode = (
                0o666
                if wrong_mode and index == 0
                else (0o755 if mode == "100755" else 0o644)
            )
            archive.addfile(member, io.BytesIO(value))
        if unsafe:
            member = tarfile.TarInfo("../escape")
            member.size = 1
            archive.addfile(member, io.BytesIO(b"x"))
        if nonregular:
            member = tarfile.TarInfo("special")
            member.type = tarfile.SYMTYPE
            member.linkname = "/tmp/escape"
            member.mode = 0o777
            archive.addfile(member)


def make_runner(
    workspace: Path,
    *,
    unsafe_archive: bool = False,
    wrong_mode: bool = False,
    extra_pax: bool = False,
    nonregular: bool = False,
    ls_tree_size_delta: int = 0,
    local_config: bytes = b"core.repositoryformatversion\n0\0",
):
    def run(argv, *, environment, stdin_value, timeout_seconds, context):
        del timeout_seconds
        if argv[-1:] == ["-V"]:
            stdout, stderr = b"", b"OpenSSH_9.9\n"
        elif "-lf" in argv:
            stdout = f"256 {FINGERPRINT} fixture (ED25519)\n".encode()
            stderr = b""
        elif "for-each-ref" in argv:
            stdout, stderr = b"", b""
        elif "config" in argv:
            stdout, stderr = local_config, b""
        elif context == "signed-source:tree":
            stdout, stderr = (TREE + "\n").encode(), b""
        elif context == "signed-source:ls-tree":
            stdout = b"".join(
                (
                    f"{binding['mode']} blob {binding['git_blob']} "
                    f"{binding['size_bytes'] + (ls_tree_size_delta if index == 0 else 0):7d}"
                    f"\t{binding['path']}\0"
                ).encode("utf-8")
                for index, binding in enumerate(file_bindings())
            )
            stderr = b""
        elif context == "signed-source:archive":
            output = next(
                argument.removeprefix("--output=")
                for argument in argv
                if argument.startswith("--output=")
            )
            write_archive(
                Path(output),
                unsafe=unsafe_archive,
                wrong_mode=wrong_mode,
                extra_pax=extra_pax,
                nonregular=nonregular,
            )
            stdout, stderr = b"", b""
        else:
            raise AssertionError(f"unexpected command: {context}: {argv}")
        stdin_bytes = b"" if stdin_value is None else stdin_value
        receipt = {
            "context": context,
            "argv": list(argv),
            "cwd": str(workspace),
            "environment": dict(environment),
            "stdin_mode": "devnull" if stdin_value is None else "bytes",
            "stdin_sha256": hashlib.sha256(stdin_bytes).hexdigest(),
            "stdin": complete_stream(stdin_bytes),
            "started_utc": "2026-08-21T00:00:00Z",
            "completed_utc": "2026-08-21T00:00:00Z",
            "duration_ms": 0,
            "timed_out": False,
            "returncode": 0,
            "terminal_returncode": 0,
            "process_group_reaped": True,
            "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
            "stdout": complete_stream(stdout),
            "stderr": complete_stream(stderr),
            "execution_error": None,
            "interrupted": False,
        }
        return receipt, stdout, stderr

    return run


def make_trust(root: Path, workspace: Path, runner):
    inputs = root / "inputs"
    inputs.mkdir()
    tools = {}
    for name in ("git", "ssh-keygen", "ssh"):
        path = inputs / name
        path.write_bytes(name.encode())
        path.chmod(0o700)
        tools[name] = path
    allowed = inputs / "allowed-signers"
    allowed.write_text(
        f"{PRINCIPAL} ssh-ed25519 AAAATEST fixture\n", encoding="utf-8"
    )
    frozen = root / "trust"
    frozen.mkdir()
    base = {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"}
    request = source.gate_h_signature.SignatureRequest(
        git=tools["git"],
        ssh_keygen=tools["ssh-keygen"],
        ssh=tools["ssh"],
        allowed_signers=allowed,
        principal=PRINCIPAL,
    )
    trust = source.gate_h_signature.prepare_signature_trust(
        request,
        workspace=workspace,
        frozen_directory=frozen,
        base_environment=base,
        run_command=runner,
    )
    return trust, base


class GateHSignedSourceTests(unittest.TestCase):
    def test_materialize_validate_and_rematerialize_exact_signed_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            workspace = root / "workspace"
            workspace.mkdir()
            (workspace / ".git/info").mkdir(parents=True)
            runner = make_runner(workspace)
            trust, base = make_trust(root, workspace, runner)
            archive = root / "signed-source.tar"
            export = root / "signed-source"
            receipt = source.materialize_signed_tree(
                COMMIT,
                TREE,
                trust,
                workspace=workspace,
                archive_path=archive,
                export_root=export,
                base_environment=base,
                run_command=runner,
            )
            self.assertEqual(receipt["tree"], TREE)
            self.assertEqual(oct(archive.stat().st_mode & 0o777), "0o444")
            self.assertEqual(
                source.validate_signed_tree_receipt(
                    receipt, workspace=workspace, trust=trust
                ),
                export,
            )
            rebound = source.rematerialize_signed_tree(
                receipt,
                workspace=workspace,
                trust=trust,
                archive_path=archive,
                export_root=root / "rebound",
            )
            self.assertEqual(
                (Path(rebound["export"]["path"]) / "lab/Dockerfile").read_bytes(),
                SOURCE_FILES["lab/Dockerfile"][1],
            )
            rebound_root = Path(rebound["export"]["path"])
            for path in (rebound_root, *rebound_root.rglob("*")):
                expected_mode = (
                    0o555
                    if path.is_dir()
                    or path.relative_to(rebound_root).as_posix() == "script.sh"
                    else 0o444
                )
                self.assertEqual(path.stat().st_mode & 0o777, expected_mode)

            candidate = export / "Cargo.toml"
            candidate.chmod(0o644)
            candidate.write_bytes(b"ambient tamper")
            with self.assertRaisesRegex(source.SignedSourceError, "export file"):
                source.validate_signed_tree_receipt(
                    receipt, workspace=workspace, trust=trust
                )

    def test_unsafe_archive_path_is_rejected_without_escape(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            workspace = root / "workspace"
            workspace.mkdir()
            (workspace / ".git/info").mkdir(parents=True)
            clean_runner = make_runner(workspace)
            trust, base = make_trust(root, workspace, clean_runner)
            with self.assertRaisesRegex(
                source.SignedSourceError, "escapes its export root"
            ):
                source.materialize_signed_tree(
                    COMMIT,
                    TREE,
                    trust,
                    workspace=workspace,
                    archive_path=root / "unsafe.tar",
                    export_root=root / "unsafe-export",
                    base_environment=base,
                    run_command=make_runner(workspace, unsafe_archive=True),
                )
            self.assertFalse((root.parent / "escape").exists())

    def test_ls_tree_mode_pax_and_nonregular_archive_tampering_is_rejected(self):
        cases = (
            ({"ls_tree_size_delta": 1}, "exact ls-tree"),
            ({"wrong_mode": True}, "file mode"),
            ({"extra_pax": True}, "PAX headers"),
            ({"nonregular": True}, "non-regular"),
        )
        for options, message in cases:
            with self.subTest(options=options), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                workspace = root / "workspace"
                (workspace / ".git/info").mkdir(parents=True)
                clean_runner = make_runner(workspace)
                trust, base = make_trust(root, workspace, clean_runner)
                with self.assertRaisesRegex(source.SignedSourceError, message):
                    source.materialize_signed_tree(
                        COMMIT,
                        TREE,
                        trust,
                        workspace=workspace,
                        archive_path=root / "source.tar",
                        export_root=root / "source",
                        base_environment=base,
                        run_command=make_runner(workspace, **options),
                    )

    def test_info_attributes_and_local_archive_config_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            workspace = root / "workspace"
            (workspace / ".git/info").mkdir(parents=True)
            runner = make_runner(workspace)
            trust, base = make_trust(root, workspace, runner)
            (workspace / ".git/info/attributes").write_text(
                "* export-ignore\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(source.SignedSourceError, "absent or empty"):
                source.materialize_signed_tree(
                    COMMIT,
                    TREE,
                    trust,
                    workspace=workspace,
                    archive_path=root / "attributes.tar",
                    export_root=root / "attributes",
                    base_environment=base,
                    run_command=runner,
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            workspace = root / "workspace"
            (workspace / ".git/info").mkdir(parents=True)
            controlled = make_runner(
                workspace,
                local_config=(
                    b"core.repositoryformatversion\n0\0"
                    b"tar.fixture.command\n/bin/false\0"
                ),
            )
            trust, base = make_trust(root, workspace, controlled)
            with self.assertRaisesRegex(source.SignedSourceError, "controls archive"):
                source.materialize_signed_tree(
                    COMMIT,
                    TREE,
                    trust,
                    workspace=workspace,
                    archive_path=root / "config.tar",
                    export_root=root / "config",
                    base_environment=base,
                    run_command=controlled,
                )

    def test_export_extra_and_missing_files_are_rejected(self):
        for mutation, message in (("extra", "files differ"), ("missing", "files differ")):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                workspace = root / "workspace"
                (workspace / ".git/info").mkdir(parents=True)
                runner = make_runner(workspace)
                trust, base = make_trust(root, workspace, runner)
                receipt = source.materialize_signed_tree(
                    COMMIT,
                    TREE,
                    trust,
                    workspace=workspace,
                    archive_path=root / "source.tar",
                    export_root=root / "source",
                    base_environment=base,
                    run_command=runner,
                )
                export = root / "source"
                if mutation == "extra":
                    export.chmod(0o755)
                    (export / "ambient").write_bytes(b"ambient")
                    (export / "ambient").chmod(0o444)
                    export.chmod(0o555)
                else:
                    target = export / "lab/Dockerfile"
                    target.parent.chmod(0o755)
                    target.unlink()
                    target.parent.chmod(0o555)
                with self.assertRaisesRegex(source.SignedSourceError, message):
                    source.validate_signed_tree_receipt(
                        receipt, workspace=workspace, trust=trust
                    )


if __name__ == "__main__":
    unittest.main()
