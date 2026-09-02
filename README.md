# auto-unpack

Android APK 壳识别 + 脱壳 + 后端 URL 提取的自动化流水线。

对输入 APK 做静态特征分析，识别加固壳（14 家厂商 + dpt-shell + 自研保护），无壳样本直接抽取后端 URL，带壳样本分流到动态脱壳（当前仅 dpt-shell 实现）或转人工，最终产出分级 URL 清单。

## 安装

```bash
# 基础（壳识别 + 静态提取）
pip install -e .

# 含动态脱壳（需要 frida + 真机/模拟器）
pip install -e ".[dump]"
```

要求 Python ≥ 3.10。动态脱壳需设备上运行 frida-server。

## 用法

```bash
# 单个 APK 完整分析（识别 → 提取）
auto-unpack analyze <app.apk>

# 只做壳识别（不提取 URL）
auto-unpack detect <app.apk>

# 批量：分析 APK/ 下所有 APK
auto-unpack analyze

# 动态脱壳（dpt-shell 样本，需 --unpack 显式启用）
auto-unpack analyze <app.apk> --unpack --package com.example.app
```

退出码：`0` 成功 / `1` 无 URL / `2` 输入非法 / `3` 识别失败 / `4` 脱壳失败 / `5` 其它失败。

配置见 `env.example.json`（复制为 `env.json` 后按需修改）。

## 目录结构

```
├── src/auto_unpack/
│   ├── flow/          状态机编排（ingest → detect → route → unpack → extract）
│   ├── packer/        静态特征库 + APKiD 补强 + 分流决策
│   ├── extraction/    URL 指标规则 + 提取编排
│   ├── unpacker/      适配器路由 + dpt-shell 动态 dump
│   ├── runtime/       产物目录布局、adb、包名解析、env 配置
│   ├── constants.py   跨层契约（状态、错误码）
│   └── dex_utils.py   DEX 基础设施（头校验、校验和修复）
├── tests/             行为锁定测试（纯函数，离线可跑）
├── scripts/           辅助脚本（APKiD 批量扫描等）
├── outputs/           产物目录（运行时生成，不入库）
│   ├── packer_detection/  按壳名归档
│   ├── unpacked_dex/      动态脱壳 dex
│   └── extracted_urls/    urls_by_rank.txt
├── APK/               待分析 APK 入口（运行时，不入库）
├── 项目文档/          PRD、项目总览等长期文档
└── pyproject.toml
```

## 测试

```bash
pytest
```

行为锁定测试覆盖壳识别核心判定函数（`suggest_route` / `_judge_dpt` 等），离线可跑，不依赖设备。

## 产物路径约定

产物统一落在 `outputs/` 下。测试可设环境变量隔离：

- `AUTO_UNPACK_PRODUCT_ROOT=<临时目录>` — 产物根目录
- `AUTO_UNPACK_DISABLE_ARCHIVE=1` — 禁止壳识别归档
- `AUTO_UNPACK_APK_INBOX=<临时目录>` — 覆盖 APK 存放入口
