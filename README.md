# auto-unpack

Android APK **壳识别 → 可自动则脱壳 → 抽后端 URL**。

静态特征覆盖 14 家厂商壳、dpt-shell 和自研保护。无壳样本直接抽 URL；**dpt-shell / 360 / 腾讯乐固 / 网易易盾** 会动态 dump 后再抽；其余厂商壳、自研保护、360 付费版、带 VMP 的样本转人工（不抽 URL）。跑完会卸载本次 `adb install` 装上的 app，并清理输入目录里的源 APK。

## 快速开始

1. Python ≥ 3.10，建议单独环境：

   ```bash
   pip install -e .            # 壳识别 + 静态提取
   pip install -e ".[dump]"    # 动态脱壳（frida + frida-dexdump）
   ```

2. 复制 `env.example.json` 为 `env.json`（本地文件，不入库），按需改设备 ID 等。

3. 把 `.apk` 放进项目根目录 `APK/`，运行：

   ```bash
   python run.py
   ```

`run.py` 已打开 `--unpack`。流程：

```
识别壳 → dpt-shell 自动脱壳 → 提取 URL
       → 360 / 腾讯乐固 / 网易易盾：frida-dexdump -f -d → 提取 URL
       → 无壳直接提取 URL
       → 其余转人工
```

动态脱壳需要：USB 真机、`adb`、以 **root** 运行的 `frida-server`。缺 Frida / dexdump 时这些样本会转人工，无壳样本不受影响。

## CLI

```bash
auto-unpack analyze <app.apk>                 # 单个完整分析
auto-unpack detect <app.apk>                  # 只识别壳
auto-unpack analyze                           # 批量：APK/ 下全部
auto-unpack analyze <app.apk> --unpack --package com.example.app
auto-unpack analyze <app.apk> --validate-dns
auto-unpack analyze <app.apk> --validate-http   # HTTP HEAD；默认不探测私网
```

退出码：`0` 成功 / `1` 无 URL / `2` 输入非法 / `3` 识别失败 / `4` 脱壳失败 / `5` 其它失败。

畸形 Manifest 不要猜包名，用 `--package`（或先 `adb install` 再读设备上的包名）。

## 配置（`env.json`）

| 键 | 默认 | 说明 |
|---|---|---|
| `device` | `null` | 空 = USB 第一台；多设备填 adb/frida 设备 ID |
| `install` | `when_needed` | `never` / `when_needed` / `always` |
| `sleep` | `10` | spawn 后等待秒数（等主界面再 dump） |
| `unpack` | `false` | CLI 默认不脱壳；`run.py` 会打开 |
| `uninstall` | `true` | 只卸本次安装的包，设备原有的不动 |
| `timeout` | `300` | 有壳分析超时（秒） |

## 仓库里有什么

```
├── run.py                 一键入口（unpack 已打开）
├── env.example.json       配置模板
├── pyproject.toml
└── src/auto_unpack/
    ├── flow/              ingest → detect → route → unpack → extract
    ├── packer/            静态特征 + APKiD 补强 + 分流
    ├── extraction/        URL 规则与提取
    ├── unpacker/          dpt-shell dump.js；360 / 乐固 / 易盾走 frida-dexdump
    ├── runtime/           产物目录、adb、包名、env
    ├── constants.py
    └── dex_utils.py       DEX 头校验与 checksum 修复
```

`APK/`、`outputs/`、`env.json` 只在本地生成，不入库。

## 产物（`outputs/`）

| 目录 | 内容 |
|---|---|
| `packer_detection/<壳名>/` | 壳识别归档 |
| `extracted_urls/<样本>/` | `urls_by_rank.txt`（biz + 有信号的 weak）、`urls.txt`（全部绝对 URL）、`indicators.jsonl`、`meta.json` |
| `unpacked_dex/<样本>/` | 修复 checksum 后的顶层 `*.dex` |

脱壳目录**只留能用的 dex**：无效头、`class_data` 越界的截断 dump、同源边界副本会删掉，不再保留 `raw/`、`_invalid_dex/`。JADX 打开**单个**业务 dex，不要把整个文件夹丢进去。

环境变量（测试或隔离产物时用）：

- `AUTO_UNPACK_PRODUCT_ROOT` — 产物根目录
- `AUTO_UNPACK_DISABLE_ARCHIVE=1` — 禁止壳识别归档
- `AUTO_UNPACK_APK_INBOX` — 覆盖 APK 入口目录
