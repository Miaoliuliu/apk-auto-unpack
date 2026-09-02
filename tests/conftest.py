"""pytest 公共配置：把项目 src/ 加入 import 路径。

壳识别纯函数测试不依赖 androguard（dex_utils 顶层只 import stdlib），
本 conftest 让 pytest 从仓库根直接跑即可（无需 pip install -e）。
"""
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
