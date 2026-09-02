"""APK 存放入口：目录扫描与 CLI 批量调度。"""
from __future__ import annotations

from pathlib import Path

from auto_unpack.flow.cli import _normalize_argv, main
from auto_unpack.runtime.product import (
    APK_INBOX_ROOT,
    default_apk_inbox,
    list_apk_files,
    resolve_apk_input,
)


def _ok_report() -> dict:
    return {
        "status": "COMPLETED",
        "urls": [{"url": "http://example.com", "rank": "biz", "value": "http://example.com"}],
        "packer": {"packed": False, "packer": "无壳", "name": "无壳"},
        "unpack": {"status": "SKIPPED", "adapter": "static"},
        "extraction": {"status": "ok", "url_count": 1},
        "sample": {},
        "route": "static",
    }


def test_normalize_argv_empty_defaults_to_analyze():
    assert _normalize_argv([]) == ["analyze"]


def test_normalize_argv_flags_only_preprend_analyze():
    assert _normalize_argv(["--skip-apkid"]) == ["analyze", "--skip-apkid"]


def test_normalize_argv_keeps_detect():
    assert _normalize_argv(["detect", "--skip-apkid"]) == ["detect", "--skip-apkid"]


def test_normalize_argv_file_becomes_analyze():
    assert _normalize_argv(["foo.apk"]) == ["analyze", "foo.apk"]


def test_list_apk_files_empty(tmp_path: Path):
    assert list_apk_files(tmp_path) == []
    assert list_apk_files(tmp_path / "missing") == []


def test_list_apk_files_finds_apk_ignores_other(tmp_path: Path):
    (tmp_path / "a.apk").write_bytes(b"PK")
    (tmp_path / "B.APK").write_bytes(b"PK")
    (tmp_path / "notes.txt").write_text("x", encoding="utf-8")
    (tmp_path / ".hidden.apk").write_bytes(b"PK")
    nested = tmp_path / "sub"
    nested.mkdir()
    (nested / "nested.apk").write_bytes(b"PK")

    names = [p.name for p in list_apk_files(tmp_path)]
    assert names == [".hidden.apk", "a.apk", "B.APK"]

    rec = {p.name for p in list_apk_files(tmp_path, recursive=True)}
    assert rec == {".hidden.apk", "a.apk", "B.APK", "nested.apk"}


def test_default_inbox_env_override(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("AUTO_UNPACK_APK_INBOX", str(tmp_path))
    assert default_apk_inbox() == tmp_path


def test_default_inbox_is_project_apk_dir(monkeypatch):
    monkeypatch.delenv("AUTO_UNPACK_APK_INBOX", raising=False)
    inbox = default_apk_inbox()
    assert inbox.name == APK_INBOX_ROOT


def test_resolve_missing_path(tmp_path: Path):
    try:
        resolve_apk_input(tmp_path / "nope.apk")
    except FileNotFoundError:
        return
    raise AssertionError("expected FileNotFoundError")


def test_resolve_file_and_dir(tmp_path: Path):
    apk = tmp_path / "one.apk"
    apk.write_bytes(b"PK")
    src, targets = resolve_apk_input(apk)
    assert src == apk
    assert targets == [apk]

    src, targets = resolve_apk_input(tmp_path)
    assert src == tmp_path
    assert [p.name for p in targets] == ["one.apk"]


def test_resolve_inbox_override(tmp_path: Path):
    other = tmp_path / "other"
    other.mkdir()
    (other / "x.apk").write_bytes(b"PK")
    src, targets = resolve_apk_input(None, inbox=other)
    assert src == other
    assert [p.name for p in targets] == ["x.apk"]


def test_resolve_inbox_missing(tmp_path: Path):
    try:
        resolve_apk_input(None, inbox=tmp_path / "no-such-dir")
    except FileNotFoundError:
        return
    raise AssertionError("expected FileNotFoundError")


def test_cli_empty_inbox(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("AUTO_UNPACK_APK_INBOX", str(tmp_path))
    assert main(["analyze"]) == 2


def test_cli_missing_file(tmp_path: Path):
    assert main(["analyze", str(tmp_path / "missing.apk")]) == 2


def test_cli_batch_calls_run_for_each_apk(monkeypatch, tmp_path: Path):
    (tmp_path / "one.apk").write_bytes(b"PK")
    (tmp_path / "two.apk").write_bytes(b"PK")
    (tmp_path / "skip.txt").write_text("x", encoding="utf-8")
    monkeypatch.setenv("AUTO_UNPACK_APK_INBOX", str(tmp_path))

    called: list[str] = []

    def fake_run(apk, **kwargs):
        called.append(Path(apk).name)
        return _ok_report()

    monkeypatch.setattr("auto_unpack.flow.pipeline.run", fake_run)
    assert main(["analyze"]) == 0
    assert called == ["one.apk", "two.apk"]


def test_cli_batch_isolates_failure(monkeypatch, tmp_path: Path):
    (tmp_path / "a.apk").write_bytes(b"PK")
    (tmp_path / "b.apk").write_bytes(b"PK")
    monkeypatch.setenv("AUTO_UNPACK_APK_INBOX", str(tmp_path))
    called: list[str] = []

    def fake_run(apk, **kwargs):
        called.append(Path(apk).name)
        if Path(apk).name == "a.apk":
            raise RuntimeError("boom")
        return _ok_report()

    monkeypatch.setattr("auto_unpack.flow.pipeline.run", fake_run)
    assert main(["analyze"]) == 5
    assert called == ["a.apk", "b.apk"]


def test_cli_detect_sets_detect_only(monkeypatch, tmp_path: Path):
    (tmp_path / "one.apk").write_bytes(b"PK")
    monkeypatch.setenv("AUTO_UNPACK_APK_INBOX", str(tmp_path))
    seen: dict = {}

    def fake_run(apk, **kwargs):
        seen.update(kwargs)
        return _ok_report()

    monkeypatch.setattr("auto_unpack.flow.pipeline.run", fake_run)
    assert main(["detect"]) == 0
    assert seen.get("detect_only") is True


def test_cli_inbox_flag(monkeypatch, tmp_path: Path):
    drop = tmp_path / "drop"
    drop.mkdir()
    (drop / "x.apk").write_bytes(b"PK")
    empty = tmp_path / "empty-default"
    empty.mkdir()
    monkeypatch.setenv("AUTO_UNPACK_APK_INBOX", str(empty))
    called: list[str] = []

    def fake_run(apk, **kwargs):
        called.append(Path(apk).name)
        return _ok_report()

    monkeypatch.setattr("auto_unpack.flow.pipeline.run", fake_run)
    assert main(["analyze", "--inbox", str(drop)]) == 0
    assert called == ["x.apk"]


def test_cli_dir_recursive(monkeypatch, tmp_path: Path):
    nested = tmp_path / "sub"
    nested.mkdir()
    (nested / "n.apk").write_bytes(b"PK")
    called: list[str] = []

    def fake_run(apk, **kwargs):
        called.append(Path(apk).name)
        return _ok_report()

    monkeypatch.setattr("auto_unpack.flow.pipeline.run", fake_run)
    assert main(["analyze", str(tmp_path)]) == 2
    assert called == []
    assert main(["analyze", str(tmp_path), "-r"]) == 0
    assert called == ["n.apk"]
