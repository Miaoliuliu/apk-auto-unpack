# auto-unpack

Android APK 壳识别 + 脱壳 + 后端 URL 提取的自动化流水线。

对输入 APK 做静态特征分析，识别加固壳（14 家厂商 + dpt-shell + 自研保护），无壳样本直接抽取后端 URL，dpt-shell、360、腾讯乐固、网易易盾自动动态脱壳后抽取，其余转人工，最终产出分级 URL 清单。跑完自动卸载本次安装的 app、清理输入目录源文件。

## 快速开始（一键启动）

把 APK 丢进 `APK/` 目录，在 PyCharm 里运行项目根目录的 `run.py`（或终端 `python run.py`）。参数已内嵌，自动完成：

```
识别壳 → dpt-shell 自动脱壳 → 提取 URL
       → 360 / 腾讯乐固 / 网易易盾 frida-dexdump -f -d 深度脱壳 → 提取 URL
       → 无壳直接提取 URL
       → 其余厂商壳 / 自研保护 / 360付费版 / VMP 转人工（不抽 URL）
```

前提：

- 解释器用系统 Python 3.10：`C:/Program Files/Python310/python.exe`（唯一同时装了 frida + androguard + frida-dexdump 的环境）
- 真机 USB 连着，frida-server 以 root 运行（dpt / 360 / 乐固 / 易盾脱壳需要）

## 安装

```bash
pip install -e .            # 基础（壳识别 + 静态提取）
pip install -e ".[dump]"    # 含动态脱壳（frida + 真机）
```

要求 Python ≥ 3.10。

## CLI 用法

```bash
auto-unpack analyze <app.apk>                      # 单个完整分析
auto-unpack detect <app.apk>                       # 只识别壳（不脱壳不抽 URL）
auto-unpack analyze                                 # 批量分析 APK/ 下全部
auto-unpack analyze <app.apk> --unpack --package com.example.app
auto-unpack analyze <app.apk> --validate-dns        # 可选 DNS 验证
auto-unpack analyze <app.apk> --validate-http       # 可选 HTTP HEAD（默认不探测私网）
```

退出码：`0` 成功 / `1` 无 URL / `2` 输入非法 / `3` 识别失败 / `4` 脱壳失败 / `5` 其它失败。

## 配置

复制 `env.example.json` 为 `env.json` 后按需修改（`env.json` 是本地配置，不入库）：

| 键 | 默认 | 说明 |
|---|---|---|
| `device` | `null` | 空 = USB 第一台；多设备填 adb/frida 设备 ID |
| `install` | `when_needed` | never / when_needed / always |
| `sleep` | `10` | spawn 后等待秒数（360 / 乐固 / 易盾：等主页面加载再 dump） |
| `unpack` | `false` | 是否自动动态脱壳（dpt-shell） |
| `uninstall` | `true` | 脱壳后卸载本次 adb install 装的 app（设备原有的不动） |
| `timeout` | `300` | 有壳分析超时秒数 |

## 目录结构

```
├── run.py              一键启动入口（参数内嵌）
├── src/auto_unpack/
│   ├── flow/           状态机编排（ingest → detect → route → unpack → extract）
│   ├── packer/         静态特征库 + APKiD 补强 + 分流决策
│   ├── extraction/     URL 指标规则 + 提取编排
│   ├── unpacker/       适配器路由 + dpt-shell 动态 dump
│   ├── runtime/        产物目录布局、adb、包名解析、env 配置
│   ├── constants.py    跨层契约（状态、错误码）
│   └── dex_utils.py    DEX 基础设施（头校验、校验和修复）
├── tests/              行为锁定测试（本地，不入库）
├── outputs/            产物目录（运行时生成，不入库）
│   ├── packer_detection/  按壳名归档
│   ├── unpacked_dex/      动态脱壳 dex
│   └── extracted_urls/    urls_by_rank.txt + urls.txt + indicators.jsonl + meta.json
├── APK/                待分析 APK 入口（运行时，不入库）
├── 项目文档/           PRD、项目总览等长期文档
└── pyproject.toml
```

## 测试

```bash
pytest
```

行为锁定测试覆盖壳识别核心判定函数 + 产物命名 / 归档清理 / 卸载等运行时逻辑，离线可跑，不依赖设备。

## 产物路径约定

产物统一落在 `outputs/` 下。`unpacked_dex/<样本>/` 只留修复后的 `*.dex`（`raw/`、`_invalid_dex/` 会删掉）。测试可设环境变量隔离：

- `AUTO_UNPACK_PRODUCT_ROOT=<临时目录>` — 产物根目录
- `AUTO_UNPACK_DISABLE_ARCHIVE=1` — 禁止壳识别归档
- `AUTO_UNPACK_APK_INBOX=<临时目录>` — 覆盖 APK 存放入口
