# tests

回归测试目录（PRD 3.1：壳识别 / 脱壳 / 提取 / 报告不许回退）。

运行（仓库根执行，无需 pip install -e）：

    C:/Users/Administrator/.workbuddy/binaries/python/envs/default/Scripts/python.exe -m pytest

## 现有测试

- `test_apk_inbox.py`：`APK/` 入口扫描 + CLI 默认读目录、批量失败隔离。
- `test_packer_sigs.py`：壳识别**核心判定函数的纯单元测试**（45 个用例，~0.4s）。
  覆盖 `suggest_route` / `_judge_dpt` / `_stub_like` / `has_payload_dex` /
  `dex_unreadable` / `class_shortfall` / `_is_dpt_native` / `_looks_random_lib` /
  `_find_hex_packer_pairs`。不依赖 androguard（dex_utils 顶层仅 stdlib），离线可跑。
  断言值取自真实样本实测（DUokHB 的 dpt modified、360 的 vendor、随机 lib 指纹等）。
  **这些是行为锁定测试：改判定逻辑/阈值导致行为变化时测试会红，须人工确认是有意变更。**

约定：

- 跑任何测试前设置环境变量，避免写进正式产物目录：
  - `AUTO_UNPACK_PRODUCT_ROOT=<临时目录>`
  - `AUTO_UNPACK_DISABLE_ARCHIVE=1`
  - `AUTO_UNPACK_APK_INBOX=<临时目录>`（避免扫描正式 `APK/`）
- 壳识别回归：用仓库根 `outputs/packer_detection/` 里已归档的样本，断言
  `auto_unpack.packer.packer_sigs.detect()` 的 `route` / `dpt_type` /
  `matched` 与归档目录标签一致（无壳 → static、dpt-shell → dpt、
  360加固 → vendor、自研保护 → unknown）。
- 脱壳回归需要设备 + frida（`pip install -e .[dump]`），单独标记跳过。
