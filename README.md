# SNS Lab 1 - Secure Multi-Client Communication Protocol

## Overview

This project implements a secure multi-client communication protocol with the following features:
- **AES-128-CBC encryption** with HMAC-SHA256 authentication (Encrypt-then-MAC)
- **Stateful protocol FSM** with key evolution using MD5-based ratcheting
- **Multi-threaded server** handling concurrent client connections
- **Round-based aggregation** with configurable timeout
- **Pre-shared symmetric master keys** provisioned per client

## Project Structure

```
sns-assignment-1/
├── crypto_utils.py          # Phase 1: Cryptographic primitives
├── protocol_fsm.py           # Phase 2: Protocol state machine
├── server.py                 # Phase 3: Multi-threaded server
├── client.py                 # Phase 3: Client implementation
├── .env                      # Pre-shared master keys
├── test_comms.py            # Communication tests
├── test_protocol_fsm.py     # Protocol tests
└── README.md                # This file
```

## Prerequisites

- **Python 3.8+**
- **PyCryptodome** library

## Setup Instructions

### 1. Install Dependencies

```powershell
pip install pycryptodome
```

Verify installation:
```powershell
python -c "from Crypto.Cipher import AES; print('PyCryptodome installed successfully')"
```

### 2. Configure Master Keys

The `.env` file contains pre-shared symmetric master keys (32 bytes / 256 bits each) for each client:

```env
CLIENT_1_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
CLIENT_2_KEY=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
CLIENT_3_KEY=1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff
```

**Note:** These keys are loaded automatically by both server and clients. Each client must have a matching key configured.

## Running the System

### Step 1: Start the Server

Open a PowerShell terminal and run:

```powershell
python server.py
```

**Expected Output:**
```
============================================================
Secure Multi-Client Server Started
Listening on 0.0.0.0:9999
Aggregation timeout: 2.0s
============================================================
```

The server will:
- Load master keys from `.env`
- Listen on port 9999
- Wait for client connections

### Step 2: Start Client 1

Open a **new** PowerShell terminal and run:

```powershell
python client.py 1
```

**Expected Output:**
```
Starting Secure Client 1
Server: localhost:9999
Master Key: 0123456789abcdef0123456789abcdef...

Connected to server at localhost:9999

=== HANDSHAKE PHASE ===
[+] Sending CLIENT_HELLO...
[+] CLIENT_HELLO sent (55 bytes)
[+] Waiting for SERVER_CHALLENGE...
[+] Received SERVER_CHALLENGE
[+] Handshake complete! Entering ACTIVE phase.

=== ACTIVE PHASE ===
Enter messages to send (or 'quit' to exit):
>
```

### Step 3: Start Client 2

Open another **new** PowerShell terminal:

```powershell
python client.py 2
```

### Step 4: Start Client 3

Open another **new** PowerShell terminal:

```powershell
python client.py 3
```

## Using the System

### Sending Messages

1. In each client terminal, you'll see a prompt: `>`
2. Type a message and press Enter
3. The client encrypts and sends the message to the server

**Example:**

**Client 1:**
```
> Hello from Client 1
[+] Sending message for Round 0...
[+] Message sent (103 bytes)
```

**Client 2:**
```
> Hello from Client 2
[+] Sending message for Round 0...
[+] Message sent (103 bytes)
```

**Client 3:**
```
> Hello from Client 3
[+] Sending message for Round 0...
[+] Message sent (103 bytes)
```

### Server Aggregation

After all clients send messages for a round (or after 2-second timeout):

**Server Output:**
```
[Aggregation] Round 0 complete!
[Aggregation] Clients participated: [1, 2, 3]
[Aggregation] Aggregated data: Hello from Client 1 | Hello from Client 2 | Hello from Client 3
[Client 1] Sent SERVER_AGGR_RESPONSE for Round 0
[Client 2] Sent SERVER_AGGR_RESPONSE for Round 0
[Client 3] Sent SERVER_AGGR_RESPONSE for Round 0
```

**Client Output (all clients):**
```
[+] Received SERVER_AGGR_RESPONSE for Round 0
[+] Aggregated result: Hello from Client 1 | Hello from Client 2 | Hello from Client 3
[+] Advanced to Round 1
>
```

### Exiting

Type `quit` in any client terminal to gracefully disconnect:

```
> quit
[+] Closing connection...
Connection closed
```

## Protocol Details

### Message Format

All messages follow this binary structure:

```
┌─────────────┬───────────┬─────────┬───────────┬────────┬────────────┬──────────┐
│ Opcode (1B) │ ClientID  │ Round   │ Direction │ IV     │ Ciphertext │ HMAC     │
│             │ (1B)      │ (4B)    │ (1B)      │ (16B)  │ (variable) │ (32B)    │
└─────────────┴───────────┴─────────┴───────────┴────────┴────────────┴──────────┘
```

### Protocol Phases

1. **INIT Phase**: Handshake
   - Client sends `CLIENT_HELLO` (opcode 10)
   - Server responds with `SERVER_CHALLENGE` (opcode 20)
   - Both parties transition to ACTIVE phase

2. **ACTIVE Phase**: Data exchange
   - Client sends `CLIENT_DATA` (opcode 30) with encrypted payload
   - Server aggregates messages by round number
   - Server sends `SERVER_AGGR_RESPONSE` (opcode 40) with aggregated data
   - Keys evolve after each message using MD5-based ratcheting

3. **TERMINATED Phase**: Connection closed

### Key Evolution

After each message, keys are ratcheted using:
```
new_key = MD5(old_key)[:16]  # For encryption
new_key = MD5(old_key)        # For HMAC
```

This ensures forward secrecy - compromising current keys doesn't expose past communications.

## Troubleshooting

### "Error: .env file not found"
- Ensure `.env` exists in the project directory
- Check that you're running from the correct directory

### "Error: CLIENT_X_KEY not found in .env file"
- Verify the client ID matches an entry in `.env`
- Check the key format (must be 64 hexadecimal characters)

### Server doesn't respond
- Ensure server is running before starting clients
- Check that port 9999 is not blocked by firewall
- Verify all 3 clients are sending messages for the same round

### Connection refused
- Confirm server is listening on the correct port
- Check network connectivity
- Try using `localhost` instead of IP address

## Testing

Run unit tests:

```powershell
# Test cryptographic utilities
python -m pytest test_comms.py -v

# Test protocol FSM
python -m pytest test_protocol_fsm.py -v
```

## Architecture

### Multi-Threading Model

- **Main Server Thread**: Accepts incoming connections
- **ClientHandler Threads**: One thread per client connection
- **AggregationManager**: Thread-safe round buffer management

### Thread Safety

- Each client has isolated `ProtocolSession` state
- Aggregation uses locks for concurrent access to round buffers
- No shared state between client handlers

### Security Features

-  Encrypt-then-MAC construction
-  PKCS#7 padding for AES-CBC
-  Random IV generation per message
-  HMAC verification with constant-time comparison
-  Key ratcheting for forward secrecy
-  Pre-shared keys from secure storage

## Phase 4: Attack Simulation

### Running Attack Simulations

The `attacks.py` script demonstrates that the protocol successfully defends against common security threats.

**Prerequisites:**
1. Server must be running: `python server.py`
2. Run the attack simulator: `python attacks.py`

**Simulated Attacks:**

#### 1. Replay Attack
```
Threat: Adversary captures and replays a valid encrypted packet
Defense: Sequential round numbers in FSM reject old packets
Result: ✅ Server rejects replayed packet (round mismatch)
```

#### 2. Integrity/Bit-Flipping Attack
```
Threat: Adversary modifies ciphertext bits to alter message
Defense: Encrypt-then-MAC with HMAC-SHA256 detects tampering
Result: ✅ Server rejects tampered packet (HMAC verification fails)
```

#### 3. Message Reordering Attack
```
Threat: Adversary sends Round 2 data before Round 1
Defense: FSM enforces strict sequential round numbers
Result: ✅ Server terminates session (out-of-order round detected)
```

#### 4. Key Desynchronization Attack
```
Threat: Block server response to cause key state mismatch
Defense: Key ratcheting causes HMAC failure on desynced keys
Result: ✅ Server rejects message (HMAC fails with evolved keys)
```

**Expected Output:**
```
╔════════════════════════════════════════════════════════════════════╗
║               PHASE 4: ATTACK SIMULATION SUITE                     ║
╚════════════════════════════════════════════════════════════════════╝

[Attacker] Initialized with Client ID 1
...
✅ All attacks were successfully detected and mitigated!
```

### Security Properties Verified

| Property | Mechanism | Attack Mitigated |
|----------|-----------|------------------|
| **Authenticity** | HMAC-SHA256 | Bit-flipping, Forgery |
| **Confidentiality** | AES-128-CBC | Eavesdropping |
| **Integrity** | Encrypt-then-MAC | Tampering detection before decryption |
| **Freshness** | Sequential rounds | Replay attacks |
| **Ordering** | FSM state enforcement | Message reordering |
| **Forward Secrecy** | Key ratcheting | Key compromise mitigation |

## Team Contributions

- **Phase 1** (crypto_utils.py): Cryptographic primitives
- **Phase 2** (protocol_fsm.py): Protocol state machine
- **Phase 3** (server.py, client.py): Network implementation
- **Phase 4** (attacks.py): Attack simulation and security verification

## Notes

- The default aggregation timeout is **2 seconds**
- Server runs on **0.0.0.0:9999** (all interfaces)
- Client IDs must be unique integers (1, 2, 3, ...)
- The `.env` file should be kept secure (not committed in production)

## Advanced Usage

### Custom Server Port

```powershell
# Modify server.py line ~463 to change default port
python server.py
```

### Connecting to Remote Server

```powershell
python client.py 1 192.168.1.100 9999
```

### Adjusting Aggregation Timeout

Modify `server.py` line ~463:
```python
server = SecureServer(aggregation_timeout=5.0)  # 5 seconds
```

---

**For questions or issues, contact the development team.**
