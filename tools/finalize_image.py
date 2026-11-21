"""发布镜像后处理：清除 ESP-IDF 默认注入的版本号，并重算镜像校验。

ESP-IDF 构建时会把 PROJECT_VER（默认 "1"）写入 app 描述符，
elf2image 生成的镜像因此带有 "App version: 1"。
发布固件不内置版本号（版本以 git tag 为准），所以这里在合并镜像前
把描述符中的 version 清零，并把 project_name 固定为 esp32c3-sm-asf。

用法：
    python tools/finalize_image.py <app.bin>

处理内容：
    offset 0x30..0x50  esp_app_desc_t.version        -> 全 0
    offset 0x50..0x70  esp_app_desc_t.project_name   -> "esp32c3-sm-asf"
    末尾 1 字节        镜像校验和                      -> 按字段差异重算
    末尾 32 字节       SHA256                         -> 重新计算
"""

import hashlib
import sys

VERSION_OFF = 0x30
PROJECT_OFF = 0x50
PROJECT_NAME = b"esp32c3-sm-asf"
FIELD_LEN = 32


def xor_delta(old: bytes, new: bytes) -> int:
    """计算两段等长字节的逐字节异或差值（用于增量修正镜像校验和）。"""
    delta = 0
    for a, b in zip(old, new):
        delta ^= a ^ b
    return delta


def main(path: str) -> None:
    img = bytearray(open(path, "rb").read())
    if img[0] != 0xE9:
        raise SystemExit("不是 ESP 应用镜像")
    if img[23] != 1:
        raise SystemExit("镜像未附加 SHA256，无法处理")

    delta = xor_delta(bytes(img[VERSION_OFF:VERSION_OFF + FIELD_LEN]), b"\x00" * FIELD_LEN)
    img[VERSION_OFF:VERSION_OFF + FIELD_LEN] = b"\x00" * FIELD_LEN

    name = PROJECT_NAME.ljust(FIELD_LEN, b"\x00")
    delta ^= xor_delta(bytes(img[PROJECT_OFF:PROJECT_OFF + FIELD_LEN]), name)
    img[PROJECT_OFF:PROJECT_OFF + FIELD_LEN] = name

    if delta:
        img[len(img) - 33] ^= delta
    img[-32:] = hashlib.sha256(bytes(img[:-32])).digest()

    open(path, "wb").write(img)
    print("finalized: {}".format(path))


if __name__ == "__main__":
    main(sys.argv[1])
