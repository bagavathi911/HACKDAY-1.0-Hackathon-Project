import hashlib
import os

import cv2
import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    from argon2.low_level import Type, hash_secret_raw
except ImportError:
    Type = None
    hash_secret_raw = None

MAGIC = b"AILSB2"
VERSION = b"\x02"
SALT_LEN = 16
NONCE_LEN = 12
LENGTH_LEN = 4
HEADER_LEN = len(MAGIC) + len(VERSION) + SALT_LEN + NONCE_LEN + LENGTH_LEN


# ---------------- KEY / CRYPTO HELPERS ----------------
def _derive_key(password: str, salt: bytes) -> bytes:
    if hash_secret_raw is not None and Type is not None:
        return hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=2,
            hash_len=32,
            type=Type.ID,
        )
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 1_000_000, dklen=32)


def _keyed_order(indices: np.ndarray, password: str, image_shape: tuple) -> np.ndarray:
    if not password or len(indices) < 2:
        return indices

    seed_source = f"{password}:{image_shape[0]}:{image_shape[1]}:{len(indices)}".encode("utf-8")
    seed = int.from_bytes(hashlib.sha256(seed_source).digest()[:8], byteorder="big", signed=False)
    rng = np.random.default_rng(seed)
    order = np.arange(len(indices))
    rng.shuffle(order)
    return indices[order]


def _keystream(password: str, image_shape: tuple, length: int) -> str:
    seed = f"{password}:{image_shape[0]}:{image_shape[1]}:{image_shape[2] if len(image_shape) > 2 else 1}".encode("utf-8")
    bits = []
    counter = 0
    while len(bits) < length:
        digest = hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        for byte in digest:
            bits.extend(f"{byte:08b}")
            if len(bits) >= length:
                break
        counter += 1
    return "".join(bits[:length])


# ---------------- PASSWORD ENCODE / DECODE ----------------
def encode_msg(message, password):
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, message.encode("utf-8"), None)
    return MAGIC + VERSION + salt + nonce + len(ciphertext).to_bytes(LENGTH_LEN, "big") + ciphertext


def decode_msg(data, password):
    if not isinstance(data, (bytes, bytearray)):
        return None

    if len(data) < HEADER_LEN:
        return None

    if data[:len(MAGIC)] != MAGIC:
        return None

    version = bytes(data[len(MAGIC):len(MAGIC) + len(VERSION)])
    if version not in (VERSION, b"\x01"):
        return None

    salt = bytes(data[len(MAGIC) + len(VERSION):len(MAGIC) + len(VERSION) + SALT_LEN])
    nonce = bytes(data[len(MAGIC) + len(VERSION) + SALT_LEN:len(MAGIC) + len(VERSION) + SALT_LEN + NONCE_LEN])
    cipher_len = int.from_bytes(
        data[len(MAGIC) + len(VERSION) + SALT_LEN + NONCE_LEN:len(MAGIC) + len(VERSION) + SALT_LEN + NONCE_LEN + LENGTH_LEN],
        byteorder="big"
    )

    start = HEADER_LEN
    end = start + cipher_len
    if len(data) < end:
        return None

    ciphertext = bytes(data[start:end])
    try:
        plaintext = AESGCM(_derive_key(password, salt)).decrypt(nonce, ciphertext, None)
        return plaintext.decode("utf-8")
    except Exception:
        return None


# ---------------- BIT CONVERSIONS ----------------
def message_to_bits(data: bytes) -> str:
    return "".join(f"{byte:08b}" for byte in data)


def bits_to_bytes(bits: str) -> bytes:
    padded = bits
    if len(padded) % 8 != 0:
        padded = padded[:-(len(padded) % 8)]

    return bytes(int(padded[i:i + 8], 2) for i in range(0, len(padded), 8))


# ---------------- SAFE PIXEL SELECTION ----------------
def get_safe_pixel_indices(image: np.ndarray, password: str = "") -> np.ndarray:
    """
    Adaptive safe-pixel selection with keyed ordering.
    Different passwords produce different embedding orders while preserving the
    same high-security pixel scoring logic.
    """
    img = image.astype(np.uint8)
    img_clean = img & 0xFE
    gray = cv2.cvtColor(img_clean, cv2.COLOR_BGR2GRAY)

    # Edge detection
    edges = cv2.Canny(gray, 120, 250)
    edges_norm = edges / 255.0

    # Local variance
    kernel = np.ones((3, 3), np.float32) / 9
    gray_f = gray.astype(np.float32)
    mean = cv2.filter2D(gray_f, -1, kernel)
    variance = cv2.filter2D((gray_f - mean) ** 2, -1, kernel)
    variance_norm = cv2.normalize(variance, None, 0, 1, cv2.NORM_MINMAX)

    # Entropy map
    def entropy(block):
        hist = np.histogram(block, bins=256, range=(0, 255))[0]
        prob = hist / np.sum(hist)
        prob = prob[prob > 0]
        return -np.sum(prob * np.log2(prob))

    block_size = 8
    entropy_map = np.zeros_like(gray_f)

    for i in range(0, gray.shape[0], block_size):
        for j in range(0, gray.shape[1], block_size):
            block = gray[i:i + block_size, j:j + block_size]
            h, w = block.shape
            entropy_map[i:i + h, j:j + w] = entropy(block)

    entropy_norm = cv2.normalize(entropy_map, None, 0, 1, cv2.NORM_MINMAX)

    security_score = (
        0.5 * edges_norm +
        0.3 * variance_norm +
        0.2 * entropy_norm
    )

    threshold = 0.6
    safe_mask = security_score > threshold
    safe_indices = np.where(safe_mask.flatten())[0]

    if safe_indices.size == 0:
        safe_indices = np.arange(image.shape[0] * image.shape[1], dtype=np.int64)

    return _keyed_order(safe_indices, password, image.shape)


# ---------------- CAPACITY CALCULATION ----------------
def calculate_capacity(image: np.ndarray, password: str):
    safe_indices = get_safe_pixel_indices(image, password)

    total_bits = len(safe_indices) * 3
    header_bits = (HEADER_LEN + 16) * 8
    usable_bits = max(0, total_bits - header_bits)
    max_chars = usable_bits // 8

    return {
        "safe_pixels": len(safe_indices),
        "total_bits": total_bits,
        "usable_bits": usable_bits,
        "max_chars": max_chars
    }


# ---------------- HIDE MESSAGE ----------------
def hide_message(image: np.ndarray, message: str, password: str) -> np.ndarray:
    data = image.copy()
    flat_pixels = data.reshape(-1, 3)

    safe_indices = get_safe_pixel_indices(image, password)
    payload = encode_msg(message, password)
    bits = message_to_bits(payload)
    if len(bits) > len(safe_indices) * 3:
        raise ValueError("Message too large for this image.")

    # Stronger version: XOR the payload bits with a password-derived keystream before embedding.
    # This makes the embedded LSB pattern look random rather than matching the raw message.
    mask = _keystream(password, data.shape, len(bits))
    masked_bits = "".join(str(int(bit) ^ int(mask[i])) for i, bit in enumerate(bits))

    bit_idx = 0
    for idx in safe_indices:
        for channel in range(3):
            if bit_idx < len(masked_bits):
                flat_pixels[idx][channel] = (
                    flat_pixels[idx][channel] & 0xFE
                ) | int(masked_bits[bit_idx])
                bit_idx += 1

    return flat_pixels.reshape(data.shape)


# ---------------- REVEAL MESSAGE ----------------
def reveal_message(image: np.ndarray, password: str) -> str:
    data = image.copy()
    flat_pixels = data.reshape(-1, 3)

    safe_indices = get_safe_pixel_indices(image, password)
    bits = ""
    for idx in safe_indices:
        for channel in range(3):
            bits += str(flat_pixels[idx][channel] & 1)

    if len(bits) < HEADER_LEN * 8:
        return None

    mask = _keystream(password, data.shape, len(bits))
    recovered_bits = "".join(str(int(bit) ^ int(mask[i])) for i, bit in enumerate(bits))

    header_bits = recovered_bits[:HEADER_LEN * 8]
    header_bytes = bits_to_bytes(header_bits)

    if len(header_bytes) < HEADER_LEN or header_bytes[:len(MAGIC)] != MAGIC:
        return None

    version = header_bytes[len(MAGIC):len(MAGIC) + len(VERSION)]
    if version not in (VERSION, b"\x01"):
        return None

    salt = header_bytes[len(MAGIC) + len(VERSION):len(MAGIC) + len(VERSION) + SALT_LEN]
    nonce = header_bytes[len(MAGIC) + len(VERSION) + SALT_LEN:len(MAGIC) + len(VERSION) + SALT_LEN + NONCE_LEN]
    cipher_len = int.from_bytes(
        header_bytes[len(MAGIC) + len(VERSION) + SALT_LEN + NONCE_LEN:len(MAGIC) + len(VERSION) + SALT_LEN + NONCE_LEN + LENGTH_LEN],
        byteorder="big"
    )

    if cipher_len <= 0 or cipher_len > 1_000_000:
        return None

    required_bits = (HEADER_LEN + cipher_len) * 8
    if len(recovered_bits) < required_bits:
        return None

    ciphertext = bits_to_bytes(recovered_bits[HEADER_LEN * 8:required_bits])

    try:
        plaintext = AESGCM(_derive_key(password, salt)).decrypt(nonce, ciphertext, None)
        return plaintext.decode("utf-8")
    except Exception:
        return None
