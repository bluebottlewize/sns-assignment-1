import struct

from crypto_utils import (
    aes_cbc_encrypt,
    aes_cbc_decrypt,
    pkcs7_pad,
    pkcs7_unpad,
    compute_hmac,
    verify_hmac,
    generate_iv,
    generate_random_bytes
)
import hashlib

# =========================
# Protocol Constants
# =========================

# Opcodes
OP_CLIENT_HELLO = 10
OP_SERVER_CHALLENGE = 20
OP_CLIENT_DATA = 30
OP_SERVER_AGGR_RESPONSE = 40
OP_KEY_DESYNC_ERROR = 50
OP_TERMINATE = 60

# Directions
DIR_C2S = 0
DIR_S2C = 1

# Phases
PHASE_INIT = "INIT"
PHASE_ACTIVE = "ACTIVE"
PHASE_TERMINATED = "TERMINATED"

HMAC_LEN = 32
IV_LEN = 16


# =========================
# Helper: Hash
# =========================

def H(data: bytes) -> bytes:
    return hashlib.md5(data).digest()

class DesyncError(Exception):
    """Triggered when cryptographic or logical synchronization is lost."""
    pass

# =========================
# Protocol Session FSM
# =========================

class ProtocolSession:
    """
    Role-agnostic FSM for both client and server.
    """

    def __init__(self, role: str, client_id: int, master_key: bytes):
        assert role in ("client", "server")

        self.role = role
        self.client_id = client_id
        self.master_key = master_key

        self.phase = PHASE_INIT
        self.round = 0
        self.terminated = False

        # Initial key derivation
        self.C2S_Enc = H(master_key + b"C2S-ENC")
        self.C2S_Mac = H(master_key + b"C2S-MAC")
        self.S2C_Enc = H(master_key + b"S2C-ENC")
        self.S2C_Mac = H(master_key + b"S2C-MAC")

        # Server-side aggregation storage
        self.pending_value = None

    # =========================
    # Entry Point
    # =========================

    def process_incoming(self, raw: bytes):
        """
        Core entry point. Processes raw bytes, handles cryptographic errors,
        and manages automatic session termination on failure.
        """
        if self.terminated:
            return {"response": None, "data": "ERROR_SESSION_TERMINATED"}

        try:
            # 1. Parse the basic structure (Header, IV, Ciphertext, HMAC)
            parsed = self._parse_message(raw)

            # 2. FAIL-SAFE PEEK:
            # If the peer is signaling a crash/exit, we process it immediately.
            # We don't verify HMAC because they likely already wiped their keys.
            # if parsed["opcode"] in (OP_KEY_DESYNC_ERROR, OP_TERMINATE):
            #     return self._dispatch(parsed, b"PEER_SIGNALED_EXIT")

            # 3. Standard Security Checks
            # These will raise exceptions if the round, ID, or HMAC are wrong.
            self._verify_header(parsed)
            self._verify_hmac(parsed)


            # 4. Decryption
            # This will raise an exception if padding is invalid (key mismatch)
            plaintext = self._decrypt(parsed)

            # 5. Logical Dispatch
            return self._dispatch(parsed, plaintext)

        except DesyncError as e:
            # Generate the error packet for the peer BEFORE zeroizing
            error_packet = self.make_desync_error(str(e))

            # Note: make_desync_error calls self._terminate() internally,
            # so keys are wiped immediately after the packet is built.
            return {
                "response": error_packet,
                "data": f"LOCAL_DESYNC_DETECTION: {e}"
            }
        except Exception as e:
            # Handle other non-desync errors (e.g., protocol violations)
            self._terminate(str(e))
            return {"response": None, "data": f"FATAL_ERROR: {e}"}

    # =========================
    # Parsing
    # =========================

    def _parse_message(self, raw: bytes) -> dict:
        header_fmt = "!B B I B"
        header_len = struct.calcsize(header_fmt)

        opcode, cid, rnd, direction = struct.unpack(
            header_fmt, raw[:header_len]
        )

        hmac_val = raw[-HMAC_LEN:]
        payload = raw[header_len:-HMAC_LEN]

        iv = payload[:IV_LEN]
        ciphertext = payload[IV_LEN:]

        return {
            "opcode": opcode,
            "client_id": cid,
            "round": rnd,
            "direction": direction,
            "iv": iv,
            "ciphertext": ciphertext,
            "hmac": hmac_val,
            "header": raw[:header_len + IV_LEN],
        }

    # =========================
    # Verification Logic
    # =========================

    def _verify_header(self, msg):
        """
        Checks if the packet metadata matches our internal state machine.
        """
        # 1. Basic sanity checks (ID, Round, Direction)
        if msg["client_id"] != self.client_id:
            raise DesyncError("Client ID mismatch")

        if msg["round"] != self.round:
            raise DesyncError(f"Round mismatch: expected {self.round}, got {msg['round']}")

        # Check directionality
        expected_dir = DIR_C2S if self.role == "server" else DIR_S2C
        if msg["direction"] != expected_dir:
            raise DesyncError("Invalid packet direction")

        # 2. Phase-specific Opcode validation
        if self.phase == PHASE_INIT:
            allowed = OP_CLIENT_HELLO if self.role == "server" else OP_SERVER_CHALLENGE
            if msg["opcode"] != allowed:
                raise DesyncError(f"Invalid opcode {msg['opcode']} for INIT phase")

        elif self.phase == PHASE_ACTIVE:
            # Include administrative opcodes in the allowed list for ACTIVE phase
            valid_opcodes = (
                OP_CLIENT_DATA,
                OP_SERVER_AGGR_RESPONSE,
                OP_KEY_DESYNC_ERROR,
                OP_TERMINATE
            )
            if msg["opcode"] not in valid_opcodes:
                raise DesyncError(f"Invalid opcode {msg['opcode']} in ACTIVE")

        elif self.phase == PHASE_TERMINATED:
            raise Exception("Session already terminated")

    def _verify_hmac(self, msg):
        """
        Verifies message integrity. Failure here implies keys have drifted.
        """
        mac_key = self.C2S_Mac if msg["direction"] == DIR_C2S else self.S2C_Mac

        # Authenticate the header (including IV) and the ciphertext
        data = msg["header"] + msg["ciphertext"]

        if not verify_hmac(mac_key, data, msg["hmac"]):
            raise DesyncError("HMAC verification failed (Keys desynchronized)")

    def _decrypt(self, msg) -> bytes:
        """
        Decrypts the payload. Padding errors usually mean the wrong AES key was used.
        """
        enc_key = self.C2S_Enc if msg["direction"] == DIR_C2S else self.S2C_Enc

        try:
            return aes_cbc_decrypt(msg["ciphertext"], enc_key, msg["iv"])
        except Exception:
            # Decryption failure is almost always a desync (wrong key/IV)
            raise DesyncError("Decryption failed / Invalid padding")

    # =========================
    # Update keys
    # =========================

    def _ratchet_keys(self, direction, enc_input, mac_input):
        """
        Modularly updates the encryption and MAC keys for a specific direction.

        :param direction: DIR_C2S or DIR_S2C
        :param enc_input: The data used to evolve the Encryption key (usually Ciphertext)
        :param mac_input: The data used to evolve the MAC key (usually Plaintext/Opcode)
        """
        if direction == DIR_C2S:
            # Client -> Server Ratchet
            self.C2S_Enc = H(self.C2S_Enc + enc_input)
            self.C2S_Mac = H(self.C2S_Mac + mac_input)
        else:
            # Server -> Client Ratchet
            self.S2C_Enc = H(self.S2C_Enc + enc_input)
            self.S2C_Mac = H(self.S2C_Mac + mac_input)

    # =========================
    # Opcode Dispatch
    # =========================

    def _dispatch(self, msg, plaintext):
        op = msg["opcode"]

        if op == OP_CLIENT_HELLO:
            return self._handle_client_hello(plaintext)

        elif op == OP_SERVER_CHALLENGE:
            return self._handle_server_challenge(plaintext)

        elif op == OP_CLIENT_DATA:
            return self._handle_client_data(msg, plaintext)

        elif op == OP_SERVER_AGGR_RESPONSE:
            return self._handle_server_response(msg, plaintext)

        elif op == OP_KEY_DESYNC_ERROR:
            return self._handle_desync_error(msg, plaintext)

        elif op == OP_TERMINATE:
            return self._handle_terminate(msg, plaintext)

        self._terminate(f"Unknown opcode: {op}")

    # =========================
    # Handlers
    # =========================

    def _handle_client_hello(self, plaintext):
        if self.role != "server":
            self._terminate("Client received CLIENT_HELLO")

        # Server transition to ACTIVE happens inside make_server_challenge
        return {
            "response": self.make_server_challenge(),
            "data": plaintext  # The client nonce
        }

    def _handle_server_challenge(self, plaintext):
        if self.role != "client":
            self._terminate("Server received SERVER_CHALLENGE")

        self.phase = PHASE_ACTIVE
        return {
            "response": None,
            "data": plaintext  # The server nonce
        }

    def _handle_client_data(self, msg, plaintext):
        if self.role != "server":
            self._terminate("Client received CLIENT_DATA")

        # 1. Evolution
        self._ratchet_keys(DIR_C2S, msg["ciphertext"], plaintext)

        # 2. Extract Value
        value = struct.unpack("!I", plaintext)[0]

        # Consistent return: No immediate response (waiting for aggregation)
        return {
            "response": None,
            "data": value
        }

    def _handle_server_response(self, msg, plaintext):
        if self.role != "client":
            self._terminate("Server received AGGR_RESPONSE")

        # 1. Evolution
        opcode_byte = struct.pack("!B", msg["opcode"])
        self._ratchet_keys(DIR_S2C, plaintext, opcode_byte)

        # 2. Complete Round
        self.round += 1
        value = struct.unpack("!I", plaintext)[0]

        return {
            "response": None,
            "data": value
        }

    def _handle_desync_error(self, msg, plaintext):
        """
        Handles an incoming OP_KEY_DESYNC_ERROR.
        Even if decryption failed, the dispatcher brings us here via the 'peek' logic.
        """
        # Attempt to read the reason if decryption was successful, otherwise indicate desync
        reason = plaintext.decode('utf-8', errors='ignore') if plaintext else "Crypto Mismatch"

        # We must terminate locally because the peer has already given up on our keys
        self._terminate(f"Peer reported desynchronization: {reason}")

        return {
            "response": None,
            "data": f"TERMINATED_DESYNC: {reason}"
        }

    def _handle_terminate(self, msg, plaintext):
        """
        Handles an incoming OP_TERMINATE signal for a graceful exit.
        """
        reason = plaintext.decode('utf-8', errors='ignore') if plaintext else "Graceful Shutdown"

        # Close the session locally
        self._terminate(f"Peer requested termination: {reason}")

        return {
            "response": None,
            "data": f"TERMINATED_GRACEFUL: {reason}"
        }

    # =========================
    # Message Construction
    # =========================

    def _build_message(self, opcode, plaintext, direction):
        """
        Pure message construction: Encrypts, signs, and frames.
        DOES NOT update state or evolve keys.
        """
        # 0. Safety Check
        if self.phase == PHASE_TERMINATED:
            raise Exception("Cannot send messages from a terminated session")

        # 1. State Guard: Verify this opcode is allowed to be SENT right now
        if self.phase == PHASE_INIT:
            # During INIT, we only allow HELLO (Client) or CHALLENGE (Server)
            allowed_init = (OP_CLIENT_HELLO, OP_SERVER_CHALLENGE)
            if opcode not in allowed_init:
                self._terminate(f"Illegal opcode {opcode} for INIT phase")

        elif self.phase == PHASE_ACTIVE:
            # During ACTIVE, we allow Data, Aggr Responses, and Admin signals
            allowed_active = (
                OP_CLIENT_DATA,
                OP_SERVER_AGGR_RESPONSE,
                OP_KEY_DESYNC_ERROR,
                OP_TERMINATE
            )
            if opcode not in allowed_active:
                self._terminate(f"Illegal opcode {opcode} for ACTIVE phase")

        # 2. Cryptographic Prep
        iv = generate_iv()
        # Determine which key set to use based on direction
        enc_key = self.C2S_Enc if direction == DIR_C2S else self.S2C_Enc
        mac_key = self.C2S_Mac if direction == DIR_C2S else self.S2C_Mac

        # 3. Encrypt & Sign
        # The header is included in the HMAC to prevent tampering with ID/Round/Opcode
        ciphertext, iv = aes_cbc_encrypt(plaintext, enc_key, iv)
        header = struct.pack("!B B I B", opcode, self.client_id, self.round, direction)

        # Sign: Header + IV + Ciphertext
        mac = compute_hmac(mac_key, header + iv + ciphertext)

        return header + iv + ciphertext + mac

    # =========================
    # Modular Action Helpers
    # =========================

    def make_client_hello(self):
        """Step 1 (Client): Create Hello. No evolution yet."""
        payload = generate_random_bytes(16)
        return self._build_message(OP_CLIENT_HELLO, payload, DIR_C2S)

    def make_server_challenge(self):
        """Step 2 (Server): Create Challenge. Server phase moves to ACTIVE."""
        payload = generate_random_bytes(16)
        msg = self._build_message(OP_SERVER_CHALLENGE, payload, DIR_S2C)
        self.phase = PHASE_ACTIVE  # Server is ready for data
        return msg

    def make_client_data(self, value: int):
        """Step 3 (Client): Create Data & Evolve C2S keys."""
        payload = struct.pack("!I", value)
        msg_bytes = self._build_message(OP_CLIENT_DATA, payload, DIR_C2S)

        # SENDER EVOLUTION: Client evolves C2S keys after successful build
        # We parse the message back briefly to get the ciphertext for the ratchet
        parsed = self._parse_message(msg_bytes)
        self._ratchet_keys(DIR_C2S, parsed["ciphertext"], payload)

        return msg_bytes

    def make_aggr_response(self, aggregated_value: int):
        """Step 4 (Server): Create Response & Evolve S2C keys."""
        payload = struct.pack("!I", aggregated_value)
        msg_bytes = self._build_message(OP_SERVER_AGGR_RESPONSE, payload, DIR_S2C)

        # SENDER EVOLUTION: Server evolves S2C keys after sending
        status_code = struct.pack("!B", OP_SERVER_AGGR_RESPONSE)
        self._ratchet_keys(DIR_S2C, payload, status_code)

        self.round += 1  # Server completes its round
        return msg_bytes

    def make_desync_error(self, reason: str = "Key Desynchronization"):
        """
        Step 5 (Fault): Send Desync Error & Kill Session.
        Sent when a local crypto/round check fails.
        """
        payload = reason.encode('utf-8')
        direction = DIR_S2C if self.role == "server" else DIR_C2S

        # 1. Build message using current (potentially broken) keys
        msg_bytes = self._build_message(OP_KEY_DESYNC_ERROR, payload, direction)

        # 2. Immediately kill local session
        # We do NOT ratchet here; we destroy the state.
        self._terminate(f"Sent Desync Error: {reason}")

        return msg_bytes

    def make_terminate_msg(self, reason: str = "Graceful Termination"):
        """
        Step 6 (Exit): Send Termination & Kill Session.
        Sent when the application wants to end the session securely.
        """
        payload = reason.encode('utf-8')
        direction = DIR_S2C if self.role == "server" else DIR_C2S

        # 1. Build message using current keys
        msg_bytes = self._build_message(OP_TERMINATE, payload, direction)

        # 2. Immediately kill local session
        # This prevents any further messages from being sent or received.
        self._terminate(f"Sent Termination: {reason}")

        return msg_bytes

    # =========================
    # Termination
    # =========================

    def _terminate(self, reason):
        print(f"[!] Session terminating: {reason}")

        self.phase = PHASE_TERMINATED
        self.terminated = True
        self._zeroize()
        # raise Exception(f"Session terminated: {reason}")

    def _zeroize(self):
        self.C2S_Enc = b"\x00" * 32
        self.C2S_Mac = b"\x00" * 32
        self.S2C_Enc = b"\x00" * 32
        self.S2C_Mac = b"\x00" * 32
