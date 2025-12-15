import secrets


def andcryption(message: bytes, key: bytes) -> bytes:
    assert len(message) == len(key)
    n = len(message)
    m, k = int.from_bytes(message, "big"), int.from_bytes(key, "big")
    return int.to_bytes(m & k, n, "big")


def orcryption(message: bytes, key: bytes) -> bytes:
    assert len(message) == len(key)
    n = len(message)
    m, k = int.from_bytes(message, "big"), int.from_bytes(key, "big")
    return int.to_bytes(m | k, n, "big")


def schrodingers_cat(message: str) -> str:
    key = secrets.token_bytes(len(message))
    encrypted = secrets.choice([andcryption, orcryption])(message.encode(), key)
    return f"0x{bytes.hex(encrypted)}"
