# Security Analysis

## Protocol Overview

This secure multi-client communication protocol uses **AES-128-CBC encryption** with **HMAC-SHA256 authentication** in an Encrypt-then-MAC construction.  Each message includes a 7-byte header, 16-byte IV, variable-length ciphertext, and 32-byte HMAC tag.

## Defense Against Attack Scenarios

### 1. Replay Attack
**Defense**: Sequential round numbers prevent replay. Each message header contains a round number that must match the current session state. When an adversary replays an old packet with round number 5 while the session is at round 10, the server immediately rejects it due to round mismatch. The model enforces strict incrementing (0→1→2→3) with no backwards movement allowed, making replayed messages instantly detectable.

### 2. Integrity/Bit-Flipping Attack  
**Defense**: Encrypt-then-MAC construction detects tampering before decryption. The HMAC-SHA256 tag covers the entire message (header + IV + ciphertext). Any bit modification changes the ciphertext, producing a completely different HMAC. The protocol verifies HMAC **before** attempting decryption, preventing padding oracle attacks. The probability of forging a valid HMAC without the key is 2^-256, making forgery computationally infeasible.

### 3. Message Reordering Attack
**Defense**: FSM state enforcement prevents out-of-order messages. The protocol operates in distinct phases (INIT→ACTIVE→TERMINATED) with strict sequencing rules. Attempting to send round 5 data when expecting round 0 causes immediate session termination. There is no recovery mechanism—any ordering violation permanently ends the session, preventing state confusion attacks.

### 4. Key Desynchronization Attack
**Defense**: Key ratcheting automatically detects desynchronization. After each message, both encryption and MAC keys evolve using `new_key = MD5(old_key || message_data)`. If an adversary blocks a server response, the server evolves its keys while the client retains old keys. The next client message will use old MAC keys to compute its HMAC, which fails verification with the server's evolved keys, immediately terminating the session.

## Security Properties

- **Confidentiality**: AES-128-CBC with random IVs prevents eavesdropping
- **Integrity**: HMAC-SHA256 detects any message tampering  
- **Authenticity**: Pre-shared keys with HMAC provide mutual authentication
- **Freshness**: Sequential rounds block replay attacks
- **Forward Secrecy**: Key ratcheting protects past communications if current keys compromised

## Verification

All attack defenses verified using `attacks.py` simulation script:
```bash
python server.py    # Start server
python attacks.py   # Run attack simulations
```

Each attack is successfully detected and mitigated through the described defense mechanisms.

---
