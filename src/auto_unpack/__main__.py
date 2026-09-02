"""python -m auto_unpack [analyze|detect] [app.apk|目录]

省略路径时读取项目根 APK/ 下全部 .apk。
"""

from .flow.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
