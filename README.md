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
├── protocol_fsm.py          # Phase 2: Protocol state machine
├── server.py                # Phase 3: Multi-threaded server
├── client.py                # Phase 3: Client implementation
├── .env                     # Pre-shared master keys
├── test_comms.py            # Communication tests
├── test_protocol_fsm.py     # Protocol tests
├── SECURITY.md              # Shows why the attacks fail
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

## Running the System

### Step 1: Start the Server

Open a terminal and run:

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


### Security Features

-  Encrypt-then-MAC construction
-  PKCS#7 padding for AES-CBC
-  Random IV generation per message
-  HMAC verification with constant-time comparison
-  Key ratcheting for forward secrecy
-  Pre-shared keys from secure storage

## Attack Simulation

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
Result: Server rejects replayed packet (round mismatch)
```

#### 2. Integrity/Bit-Flipping Attack
```
Threat: Adversary modifies ciphertext bits to alter message
Defense: Encrypt-then-MAC with HMAC-SHA256 detects tampering
Result: Server rejects tampered packet (HMAC verification fails)
```

#### 3. Message Reordering Attack
```
Threat: Adversary sends Round 2 data before Round 1
Defense: FSM enforces strict sequential round numbers
Result: Server terminates session (out-of-order round detected)
```

#### 4. Key Desynchronization Attack
```
Threat: Block server response to cause key state mismatch
Defense: Key ratcheting causes HMAC failure on desynced keys
Result: Server rejects message (HMAC fails with evolved keys)
```
