import os
import hashlib
import hmac as hmac_module
from Crypto.Cipher import AES


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """
    Padding data using PKCS#7 scheme.

        data: Raw bytes to pad
        block_size: Block size (16 for AES)

    Returns:
        Padded data

    Example:
        b'hello' = 5 bytes, needs (16-(5%16))=11 bytes to reach 16-bytes
        11 = 0x0b (hex), so we add 11 bytes of value 0x0b for rest of the message block

        b'hello' -> b'hello\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
        (adds 11 bytes of padding, each with value 0x0b)
    """

    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")

    # Calculate many bytes needed to reach next block boundary
    padding_length = block_size - (len(data) % block_size)

    # PKCS#7: Each padding byte contains the padding length
    padding = bytes([padding_length] * padding_length)

    return data + padding


def pkcs7_unpad(padded_data: bytes, block_size: int = 16) -> bytes:
    """
    Manually remove PKCS#7 padding and validate it.

    Args:
        padded_data: Padded bytes
        block_size: Block size (16 for AES)

    Returns:
        Unpadded data

    Raises:
        ValueError: If padding is invalid (indicates tampering)
    """
    if not isinstance(padded_data, bytes):
        raise TypeError("Data must be bytes")

    if len(padded_data) == 0:
        raise ValueError("Cannot unpad empty data")

    if len(padded_data) % block_size != 0:
        raise ValueError("Padded data length must be multiple of block size")

    # Last byte tells us the padding length
    padding_length = padded_data[-1]

    # Validation checks (critical for security)
    if padding_length == 0 or padding_length > block_size:
        raise ValueError("Invalid padding length - possible tampering detected")

    # Verify all padding bytes have the correct value
    padding = padded_data[-padding_length:]
    if not all(byte == padding_length for byte in padding):
        raise ValueError("Invalid padding bytes - possible tampering detected")

    # Remove padding and return original data
    return padded_data[:-padding_length]


def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes = None) -> tuple:
    """
    Encrypt plaintext using AES-128-CBC with manual padding.

    Args:
        plaintext: Data to encrypt (will be padded)
        key: 16-byte AES key
        iv: 16-byte initialization vector (generated if None)

    Returns:
        (ciphertext, iv) tuple
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires 16-byte key")

    # Generate random IV if not provided
    if iv is None:
        iv = os.urandom(16)

    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")

    # Manual PKCS#7 padding
    padded_plaintext = pkcs7_pad(plaintext)

    # Create AES cipher in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Encrypt
    ciphertext = cipher.encrypt(padded_plaintext)

    return ciphertext, iv


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Decrypt ciphertext using AES-128-CBC and remove padding.

    Args:
        ciphertext: Encrypted data
        key: 16-byte AES key
        iv: 16-byte initialization vector

    Returns:
        Decrypted plaintext (unpadded)

    Raises:
        ValueError: If padding is invalid (tampering detected)
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires 16-byte key")

    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")

    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length must be multiple of block size")

    # Create AES cipher in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt
    padded_plaintext = cipher.decrypt(ciphertext)

    # Remove padding (will raise ValueError if invalid)
    plaintext = pkcs7_unpad(padded_plaintext)

    return plaintext


def compute_hmac(key: bytes, message: bytes) -> bytes:
    """
    Compute HMAC-SHA256 over a message.

    Args:
        key: HMAC key
        message: Data to authenticate

    Returns:
        32-byte HMAC tag
    """
    return hmac_module.new(key, message, hashlib.sha256).digest()


def verify_hmac(key: bytes, message: bytes, expected_hmac: bytes) -> bool:
    """
    Verify HMAC-SHA256 tag (constant-time comparison).

    Args:
        key: HMAC key
        message: Data to verify
        expected_hmac: Expected HMAC tag

    Returns:
        True if HMAC is valid, False otherwise
    """
    computed_hmac = compute_hmac(key, message)

    # Constant-time comparison (prevents timing attacks)
    return hmac_module.compare_digest(computed_hmac, expected_hmac)


def encrypt_and_mac(
    plaintext: bytes, enc_key: bytes, mac_key: bytes, header: bytes
) -> tuple:
    """
    Complete encryption procedure Sender Side:

    1. Construct plaintext payload
    2. Apply PKCS#7 padding manually
    3. Generate a fresh random IV (16 bytes)
    4. Encrypt padded plaintext using AES-128-CBC
    5. Construct message header fields (passed in)
    6. Compute HMAC over (Header || Ciphertext)
    7. Return (Ciphertext, IV, HMAC)

    Args:
        plaintext: Raw plaintext payload
        enc_key: 16-byte encryption key
        mac_key: MAC key (for HMAC)
        header: Message header bytes (opcode, client_id, round, direction)

    Returns:
        (ciphertext, iv, hmac_tag) tuple
    """
    # Step 2-4: Pad, generate IV, encrypt
    ciphertext, iv = aes_cbc_encrypt(plaintext, enc_key)

    # Step 6: Compute HMAC over (Header || IV || Ciphertext)
    mac_input = header + iv + ciphertext
    hmac_tag = compute_hmac(mac_key, mac_input)

    # Step 7: Return components
    return ciphertext, iv, hmac_tag


def verify_mac_and_decrypt(
    header: bytes,
    iv: bytes,
    ciphertext: bytes,
    hmac_tag: bytes,
    enc_key: bytes,
    mac_key: bytes,
) -> bytes:
    """
    Complete decryption procedure from assignment (Receiver Side):

    1. Verify round number and direction (caller's responsibility)
    2. Verify HMAC before decryption
    3. If HMAC fails, raise exception (session should terminate)
    4. Decrypt ciphertext using AES-128-CBC
    5. Remove PKCS#7 padding
    6. Return plaintext (caller validates format)

    Args:
        header: Message header bytes
        iv: 16-byte IV
        ciphertext: Encrypted data
        hmac_tag: 32-byte HMAC tag
        enc_key: 16-byte encryption key
        mac_key: MAC key

    Returns:
        Decrypted plaintext

    Raises:
        ValueError: If HMAC verification fails (MUST terminate session)
    """

    # In protocol_fsm.py - uniform error handling
    # try:
    #     plaintext = verify_mac_and_decrypt(...)
    # except ValueError as e:
    #     # Don't leak which check failed!
    #     self.terminate_session()  # Same action for ALL failures
    #     return None  # Or raise generic ProtocolError

    # Step 2: Verify HMAC BEFORE decryption
    mac_input = header + iv + ciphertext
    if not verify_hmac(mac_key, mac_input, hmac_tag):
        raise ValueError("HMAC verification failed - session MUST terminate")

    # Step 4-5: Decrypt and unpad
    try:
        plaintext = aes_cbc_decrypt(ciphertext, enc_key, iv)
    except ValueError as e:
        # Invalid padding is treated as tampering
        raise ValueError(f"Decryption failed - possible tampering: {e}")

    # Step 6: Return plaintext
    return plaintext


def generate_random_bytes(length: int) -> bytes:
    """
    Generate cryptographically secure random bytes using OS-level RNG.

    Args:
        length: Number of bytes to generate

    Returns:
        Random bytes
    """
    return os.urandom(length)


def generate_iv() -> bytes:
    """
    Generate a fresh random 16-byte IV for AES.

    Returns:
        16-byte IV
    """
    return os.urandom(16)


def generate_nonce(length: int = 16) -> bytes:
    """
    Generate a random nonce for key evolution.

    Args:
        length: Nonce length in bytes (default 16)

    Returns:
        Random nonce
    """
    return os.urandom(length)


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Constant-time comparison to prevent timing attacks.

    Args:
        a: First byte string
        b: Second byte string

    Returns:
        True if equal, False otherwise
    """
    return hmac_module.compare_digest(a, b)
