"""流水线生命周期：归档后清理源文件 / 脱壳后卸载 app 的行为锁定。"""
from __future__ import annotations

from auto_unpack.extraction.report import failed_report
from auto_unpack.flow.pipeline import _cleanup_inbox_source, _maybe_uninstall


class FakeTask:
    """只暴露 pipeline 辅助函数用到的字段。"""

    def __init__(self, sample: dict | None = None):
        self.sample = sample if sample is not None else {}
        self.warnings: list[str] = []

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)


# ---------------------------------------------------------------------------
# _cleanup_inbox_source：归档成功后清理 APK/ 源文件
# ---------------------------------------------------------------------------
def test_cleanup_removes_source_when_archived(monkeypatch, tmp_path):
    inbox = tmp_path / "APK"
    inbox.mkdir()
    monkeypatch.setenv("AUTO_UNPACK_APK_INBOX", str(inbox))

    src = inbox / "a.apk"
    src.write_bytes(b"PK")
    arch = tmp_path / "packer_detection" / "dpt-shell" / "a.apk"
    arch.parent.mkdir(parents=True)
    arch.write_bytes(b"PK")

    _cleanup_inbox_source(str(src), FakeTask({"detect_archive": str(arch)}))
    assert not src.exists()
    assert arch.exists()


def test_cleanup_skips_when_archive_disabled(monkeypatch, tmp_path):
    """归档被禁用时 detect_archive == 源路径（未复制）：不删。"""
    inbox = tmp_path / "APK"
    inbox.mkdir()
    monkeypatch.setenv("AUTO_UNPACK_APK_INBOX", str(inbox))
    src = inbox / "b.apk"
    src.write_bytes(b"PK")

    _cleanup_inbox_source(str(src), FakeTask({"detect_archive": str(src)}))
    assert src.exists()


def test_cleanup_skips_external_source(monkeypatch, tmp_path):
    """源文件在默认 APK/ 目录之外（--inbox / 直接传）：不删。"""
    inbox = tmp_path / "APK"
    inbox.mkdir()
    monkeypatch.setenv("AUTO_UNPACK_APK_INBOX", str(inbox))
    ext = tmp_path / "external"
    ext.mkdir()
    src = ext / "c.apk"
    src.write_bytes(b"PK")
    arch = tmp_path / "packer_detection" / "dpt-shell" / "c.apk"
    arch.parent.mkdir(parents=True)
    arch.write_bytes(b"PK")

    _cleanup_inbox_source(str(src), FakeTask({"detect_archive": str(arch)}))
    assert src.exists()


def test_cleanup_skips_valid_task_when_not_archived(monkeypatch, tmp_path):
    """已接入的任务没有成功归档时不删。"""
    inbox = tmp_path / "APK"
    inbox.mkdir()
    monkeypatch.setenv("AUTO_UNPACK_APK_INBOX", str(inbox))
    src = inbox / "d.apk"
    src.write_bytes(b"PK")

    _cleanup_inbox_source(str(src), FakeTask({}))
    assert src.exists()


def test_cleanup_removes_rejected_non_apk_from_inbox(monkeypatch, tmp_path):
    inbox = tmp_path / "APK"
    inbox.mkdir()
    monkeypatch.setenv("AUTO_UNPACK_APK_INBOX", str(inbox))
    src = inbox / "download.apk"
    src.write_text("<!DOCTYPE html>", encoding="utf-8")

    report = failed_report(apk=str(src), code="E_NOT_ZIP", message="HTML")
    _cleanup_inbox_source(str(src), report)
    assert not src.exists()


def test_cleanup_keeps_other_validation_failures(monkeypatch, tmp_path):
    inbox = tmp_path / "APK"
    inbox.mkdir()
    monkeypatch.setenv("AUTO_UNPACK_APK_INBOX", str(inbox))
    src = inbox / "locked.apk"
    src.write_bytes(b"PK")

    report = failed_report(apk=str(src), code="E_VALIDATE", message="locked")
    _cleanup_inbox_source(str(src), report)
    assert src.exists()


def test_cleanup_keeps_rejected_external_source(monkeypatch, tmp_path):
    inbox = tmp_path / "APK"
    inbox.mkdir()
    monkeypatch.setenv("AUTO_UNPACK_APK_INBOX", str(inbox))
    src = tmp_path / "external.apk"
    src.write_text("<!DOCTYPE html>", encoding="utf-8")

    report = failed_report(apk=str(src), code="E_NOT_ZIP", message="HTML")
    _cleanup_inbox_source(str(src), report)
    assert src.exists()


def test_cleanup_skips_none_task():
    _cleanup_inbox_source("D:/x.apk", None)  # 不抛异常即可


# ---------------------------------------------------------------------------
# _maybe_uninstall：脱壳后卸载本次安装的 app
# ---------------------------------------------------------------------------
def _fake_uninstall(calls: list):
    def fn(pkg, device=None):
        calls.append((pkg, device))
        return True
    return fn


def test_uninstall_calls_when_installed(monkeypatch):
    calls: list = []
    monkeypatch.setattr("auto_unpack.runtime.adb.uninstall", _fake_uninstall(calls))
    task = FakeTask({"installed_pkg": "com.example"})
    _maybe_uninstall(task, {"uninstall": True, "device": None})
    assert calls == [("com.example", None)]


def test_uninstall_skips_when_disabled(monkeypatch):
    calls: list = []
    monkeypatch.setattr("auto_unpack.runtime.adb.uninstall", _fake_uninstall(calls))
    task = FakeTask({"installed_pkg": "com.example"})
    _maybe_uninstall(task, {"uninstall": False, "device": None})
    assert calls == []


def test_uninstall_skips_when_not_installed(monkeypatch):
    """设备已有包（installed_pkg 为空）→ 不卸载。"""
    calls: list = []
    monkeypatch.setattr("auto_unpack.runtime.adb.uninstall", _fake_uninstall(calls))
    _maybe_uninstall(FakeTask({}), {"uninstall": True, "device": None})
    assert calls == []


def test_confirmed_vendor_not_unknown_when_dpt_suspected():
    """绘本：360 确认 + dpt suspected + JDog。主壳是 360，应允许动态脱壳。"""
    from auto_unpack.extraction.report import packed_flag
    from auto_unpack.flow.pipeline import _packer_status

    sig = {
        "vmp": False,
        "dpt_shell": True,
        "dpt_type": "suspected",
        "custom_family": "jdog_native_dex_loader",
        "matched": [{
            "vendor": "360加固", "key": "qihoo360", "score": 0.9,
        }],
    }
    st = _packer_status("vendor", sig)
    assert st == "PACKER_IDENTIFIED"
    assert packed_flag("vendor", st) is True


def test_dpt_suspected_alone_still_unknown():
    """没有厂商身份、主壳只是 suspected dpt 时，仍禁止强行脱壳。"""
    from auto_unpack.extraction.report import packed_flag
    from auto_unpack.flow.pipeline import _packer_status

    sig = {
        "vmp": False,
        "dpt_shell": True,
        "dpt_type": "suspected",
        "matched": [],
    }
    st = _packer_status("dpt", sig)
    assert st == "PACKER_SUSPECTED"
    assert packed_flag("dpt", st) == "unknown"


def test_uninstall_swallows_error(monkeypatch):
    """uninstall 抛异常不中断流程，记 warning。"""

    def boom(pkg, device=None):
        raise RuntimeError("adb gone")

    monkeypatch.setattr("auto_unpack.runtime.adb.uninstall", boom)
    task = FakeTask({"installed_pkg": "com.example"})
    _maybe_uninstall(task, {"uninstall": True, "device": None})
    assert task.warnings == ["卸载失败: adb gone"]
