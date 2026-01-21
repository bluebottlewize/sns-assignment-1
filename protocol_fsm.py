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
        if self.terminated:
            raise Exception("Session terminated")

        parsed = self._parse_message(raw)

        print(parsed)

        self._verify_header(parsed)
        self._verify_hmac(parsed)
        plaintext = self._decrypt(parsed)

        return self._dispatch(parsed, plaintext)

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
        # 1. Basic sanity checks (ID, Round, Direction)
        if msg["client_id"] != self.client_id:
            self._terminate("Client ID mismatch")

        if msg["round"] != self.round:
            self._terminate("Round mismatch")

        if self.role == "server" and msg["direction"] != DIR_C2S:
            self._terminate("Invalid direction")

        if self.role == "client" and msg["direction"] != DIR_S2C:
            self._terminate("Invalid direction")

        # 2. Phase-specific Opcode validation
        if self.phase == PHASE_INIT:
            if self.role == "server":
                # Server only accepts HELLO to start the session
                if msg["opcode"] != OP_CLIENT_HELLO:
                    self._terminate("Invalid opcode in INIT (Server)")
            else:
                # Client only accepts CHALLENGE while in INIT
                if msg["opcode"] != OP_SERVER_CHALLENGE:
                    self._terminate("Invalid opcode in INIT (Client)")

        elif self.phase == PHASE_ACTIVE:
            # Once ACTIVE, we only expect Data or Aggregated Responses
            valid_opcodes = (OP_CLIENT_DATA, OP_SERVER_AGGR_RESPONSE)

            if msg["opcode"] not in valid_opcodes:
                self._terminate(f"Invalid opcode {msg['opcode']} in ACTIVE")

        elif self.phase == PHASE_TERMINATED:
            self._terminate("Session already terminated")


    def _verify_hmac(self, msg):
        mac_key = (
            self.C2S_Mac if msg["direction"] == DIR_C2S else self.S2C_Mac
        )

        data = msg["header"] + msg["ciphertext"]

        if not verify_hmac(mac_key, data, msg["hmac"]):
            self._terminate("HMAC verification failed")

    def _decrypt(self, msg) -> bytes:
        enc_key = (
            self.C2S_Enc if msg["direction"] == DIR_C2S else self.S2C_Enc
        )

        try:
            return aes_cbc_decrypt(msg["ciphertext"], enc_key, msg["iv"])
        except Exception:
            self._terminate("Invalid padding")

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

        if op == OP_SERVER_CHALLENGE:
            return self._handle_server_challenge(plaintext)

        if op == OP_CLIENT_DATA:
            return self._handle_client_data(msg, plaintext)

        if op == OP_SERVER_AGGR_RESPONSE:
            return self._handle_server_response(msg, plaintext)

        self._terminate("Unknown opcode")

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

    # =========================
    # Message Construction
    # =========================

    def _build_message(self, opcode, plaintext, direction):
        """
        Pure message construction: Encrypts, signs, and frames.
        DOES NOT update state or evolve keys.
        """
        # 1. State Guard: Verify this opcode is allowed to be SENT right now
        if self.phase == PHASE_INIT:
            if self.role == "client" and opcode != OP_CLIENT_HELLO:
                self._terminate(f"Cannot send {opcode} during INIT")
            if self.role == "server" and opcode != OP_SERVER_CHALLENGE:
                self._terminate(f"Cannot send {opcode} during INIT")
        elif self.phase == PHASE_ACTIVE:
            if opcode not in (OP_CLIENT_DATA, OP_SERVER_AGGR_RESPONSE):
                self._terminate(f"Illegal opcode {opcode} for ACTIVE phase")

        # 2. Cryptographic Prep
        iv = generate_iv()
        enc_key = self.C2S_Enc if direction == DIR_C2S else self.S2C_Enc
        mac_key = self.C2S_Mac if direction == DIR_C2S else self.S2C_Mac

        # 3. Encrypt & Sign
        ciphertext, iv = aes_cbc_encrypt(plaintext, enc_key, iv)
        header = struct.pack("!B B I B", opcode, self.client_id, self.round, direction)
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

    # =========================
    # Termination
    # =========================

    def _terminate(self, reason):
        self.phase = PHASE_TERMINATED
        self.terminated = True
        self._zeroize()
        raise Exception(f"Session terminated: {reason}")

    def _zeroize(self):
        self.C2S_Enc = b"\x00" * 32
        self.C2S_Mac = b"\x00" * 32
        self.S2C_Enc = b"\x00" * 32
        self.S2C_Mac = b"\x00" * 32
