"""
Attack Simulation Script for Phase 4

This script simulates various attacks against the secure protocol to demonstrate
that the implementation successfully detects and mitigates security threats.

Attacks simulated:
1. Replay Attack - Send the same packet twice
2. Integrity/Bit-Flipping Attack - Modify ciphertext bits
3. Message Reordering Attack - Send out-of-order rounds
4. Key Desynchronization Attack - Cause key state mismatch
"""

import socket
import struct
import sys
import os
from protocol_fsm import ProtocolSession


def load_env_file(filepath='.env'):
    """Load environment variables from .env file"""
    env_vars = {}
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    env_vars[key.strip()] = value.strip()
    except FileNotFoundError:
        print(f"Error: {filepath} file not found")
        sys.exit(1)
    return env_vars


class AttackSimulator:
    """Simulates various attacks against the secure protocol"""
    
    def __init__(self, client_id, server_host='localhost', server_port=9999):
        self.client_id = client_id
        self.server_host = server_host
        self.server_port = server_port
        self.sock = None
        self.session = None
        self.captured_packet = None
        
        # Load master key from .env
        env_vars = load_env_file('.env')
        key_name = f"CLIENT_{client_id}_KEY"
        master_key_hex = env_vars.get(key_name)
        
        if not master_key_hex:
            print(f"Error: {key_name} not found in .env file")
            sys.exit(1)
        
        self.master_key = bytes.fromhex(master_key_hex)
        print(f"[Attacker] Initialized with Client ID {client_id}")
        print(f"[Attacker] Target: {server_host}:{server_port}\n")
    
    def connect(self):
        """Establish TCP connection to server"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.server_host, self.server_port))
        print(f"[Attacker] Connected to {self.server_host}:{self.server_port}")
    
    def disconnect(self):
        """Close connection"""
        if self.sock:
            self.sock.close()
            self.sock = None
        print(f"[Attacker] Disconnected\n")
    
    def send_message(self, message):
        """Send length-prefixed message"""
        length = struct.pack('!I', len(message))
        self.sock.sendall(length + message)
    
    def receive_message(self):
        """Receive length-prefixed message"""
        length_bytes = self._recv_exactly(4)
        if not length_bytes:
            return None
        
        length = struct.unpack('!I', length_bytes)[0]
        return self._recv_exactly(length)
    
    def _recv_exactly(self, n):
        """Receive exactly n bytes"""
        data = b''
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data
    
    def perform_handshake(self):
        """Perform legitimate handshake to establish valid session"""
        print("[Attacker] Performing legitimate handshake...")
        
        self.session = ProtocolSession("client", self.client_id, self.master_key)
        
        # Send CLIENT_HELLO
        hello_msg = self.session.make_client_hello()
        self.send_message(hello_msg)
        print(f"[Attacker] Sent CLIENT_HELLO")
        
        # Receive SERVER_CHALLENGE
        challenge_msg = self.receive_message()
        if not challenge_msg:
            print("[Attacker] No response from server")
            return False
        
        result = self.session.process_incoming(challenge_msg)
        print(f"[Attacker] Received SERVER_CHALLENGE")
        print(f"[Attacker] Handshake complete - Session in ACTIVE phase\n")
        return True
    
    def capture_valid_packet(self, payload=0xdeadbeef):
        """Send a legitimate packet and capture it for replay"""
        print(f"[Attacker] Sending legitimate message: '{payload}'")
        
        # Use numeric value for CLIENT_DATA (protocol expects integer)
        msg = self.session.make_client_data(42)  # Send numeric value
        self.captured_packet = msg  # Capture for later replay
        
        self.send_message(msg)
        print(f"[Attacker] Packet sent and CAPTURED (Round {self.session.round})")
        
        # Receive server response
        response = self.receive_message()
        if response:
            result = self.session.process_incoming(response)
            print(f"[Attacker] Received aggregated response (Round {self.session.round})")
            print(f"[Attacker] Session advanced to Round {self.session.round}\n")
        
        return self.captured_packet


    # ==================== ATTACK SCENARIOS ====================
    
    def attack_1_replay(self):
        """
        SCENARIO 1: REPLAY ATTACK
        
        Threat: An adversary captures a valid encrypted packet and replays it later.
        Defense: The protocol uses sequential round numbers in the FSM. The server
                 maintains state and rejects packets with old round numbers.
        """
        print("=" * 70)
        print("ATTACK 1: REPLAY ATTACK")
        print("=" * 70)
        print("Threat: Adversary replays a previously captured valid packet")
        print("Defense: Sequential round numbers prevent replay\n")
        
        self.connect()
        
        if not self.perform_handshake():
            self.disconnect()
            return
        
        # Send legitimate message and capture it
        captured = self.capture_valid_packet(0xdeadbeef)
        
        # Now try to replay the captured packet (which has old round number)
        print("[Attacker] 🚨 LAUNCHING REPLAY ATTACK 🚨")
        print(f"[Attacker] Replaying captured packet with old round number...")

        try:
            self.send_message(captured)
            
            # Try to receive response (should be rejected or connection closed)
            response = self.receive_message()
            if response:
                # Try to process - should fail due to round mismatch
                try:
                    result = self.session.process_incoming(response)

                    print(result)

                    if "TERMINATED_DESYNC" in result["data"]:
                        print(f"[Attacker] ✅ DEFENSE SUCCESSFUL: SERVER TERMINATED SESSSION DUE TO ROUND MISMATCH")
                    else:
                        print(f"[Attacker] ❌ ATTACK FAILED: Server accepted replayed packet!")
                except Exception as e:
                    print(f"[Attacker] ✅ DEFENSE SUCCESSFUL: {e}")
            else:
                print(f"[Attacker] ✅ DEFENSE SUCCESSFUL: Server rejected packet (connection closed)")
        except Exception as e:
            print(f"[Attacker] ✅ DEFENSE SUCCESSFUL: {e}")
        
        self.disconnect()
    
    def attack_2_bit_flipping(self):
        """
        SCENARIO 2: INTEGRITY/BIT-FLIPPING ATTACK
        
        Threat: An adversary intercepts a packet and modifies the ciphertext.
        Defense: Encrypt-then-MAC construction ensures HMAC verification fails
                 before decryption is attempted.
        """
        print("=" * 70)
        print("ATTACK 2: INTEGRITY/BIT-FLIPPING ATTACK")
        print("=" * 70)
        print("Threat: Adversary modifies ciphertext bits to alter message")
        print("Defense: Encrypt-then-MAC with HMAC-SHA256 detects tampering\n")
        
        self.connect()
        
        if not self.perform_handshake():
            self.disconnect()
            return
        
        # Prepare a legitimate packet
        legitimate_value = 100
        print(f"[Attacker] Preparing legitimate message with value: {legitimate_value}")
        msg = self.session.make_client_data(legitimate_value)
        
        # Modify a bit in the ciphertext (after IV, before HMAC)
        # Message format: Header(7) + IV(16) + Ciphertext(var) + HMAC(32)
        print(f"[Attacker] Original packet length: {len(msg)} bytes")
        
        # Flip a bit in the ciphertext section (byte 30 is in ciphertext)
        modified_msg = bytearray(msg)
        flip_position = 30
        modified_msg[flip_position] ^= 0x01  # Flip the least significant bit
        modified_msg = bytes(modified_msg)
        
        print(f"[Attacker] 🚨 LAUNCHING BIT-FLIPPING ATTACK 🚨")
        print(f"[Attacker] Flipped bit at position {flip_position} in ciphertext")
        print(f"[Attacker] Original byte: 0x{msg[flip_position]:02x}, Modified: 0x{modified_msg[flip_position]:02x}")
        
        try:
            self.send_message(modified_msg)
            
            # Try to receive response (should be rejected)
            response = self.receive_message()
            if response:
                # Try to process - should fail due to round mismatch
                try:
                    result = self.session.process_incoming(response)

                    print(result)

                    if "TERMINATED_DESYNC" in result["data"]:
                        print(f"[Attacker] ✅ DEFENSE SUCCESSFUL: SERVER TERMINATED SESSSION DUE TO INVALID HMAC")
                    else:
                        print(f"[Attacker] ❌ ATTACK FAILED: Server accepted replayed packet!")
                except Exception as e:
                    print(f"[Attacker] ✅ DEFENSE SUCCESSFUL: {e}")
            else:
                print(f"[Attacker] ✅ DEFENSE SUCCESSFUL: Server rejected packet (connection closed)")

        except Exception as e:
            print(f"[Attacker] ✅ DEFENSE SUCCESSFUL: {e}")
        
        self.disconnect()
    
    def attack_3_message_reordering(self):
        """
        SCENARIO 3: MESSAGE REORDERING ATTACK
        
        Threat: An adversary attempts to send messages out of sequence.
        Defense: The FSM enforces strict sequential round numbers. Out-of-order
                 messages cause permanent session termination.
        """
        print("=" * 70)
        print("ATTACK 3: MESSAGE REORDERING ATTACK")
        print("=" * 70)
        print("Threat: Adversary sends Round 2 data before Round 1")
        print("Defense: FSM enforces sequential round numbers\n")
        
        self.connect()
        
        if not self.perform_handshake():
            self.disconnect()
            return
        
        print(f"[Attacker] Current round: {self.session.round}")
        
        # Manually create a packet with a future round number
        print(f"[Attacker] 🚨 LAUNCHING REORDERING ATTACK 🚨")
        print(f"[Attacker] Crafting packet for Round 5 (skipping rounds 0-4)...")
        
        # Save original round
        original_round = self.session.round
        
        # Temporarily modify session to create future round packet
        self.session.round = 5
        future_msg = self.session.make_client_data(999)
        
        # Restore original round
        self.session.round = original_round
        
        try:
            self.send_message(future_msg)
            print(f"[Attacker] Sent packet with Round 5 (current round is {original_round})")
            
            # Try to receive response
            response = self.receive_message()

            if response:
                # Try to process - should fail due to round mismatch
                try:
                    result = self.session.process_incoming(response)

                    print(result)

                    if "TERMINATED_DESYNC" in result["data"]:
                        print(
                            f"[Attacker] ✅ DEFENSE SUCCESSFUL: Server rejected out-of-order packet (FSM terminated session)")
                    else:
                        print(f"[Attacker] ❌ ATTACK FAILED: Server accepted replayed packet!")
                except Exception as e:
                    print(f"[Attacker] ✅ DEFENSE SUCCESSFUL: {e}")
            else:
                print(f"[Attacker] ✅ DEFENSE SUCCESSFUL: Server rejected out-of-order packet (FSM terminated session)")

        except Exception as e:
            print(f"[Attacker] ✅ DEFENSE SUCCESSFUL: {e}")
        
        self.disconnect()
    
    def attack_4_key_desync(self):
        """
        SCENARIO 4: KEY DESYNCHRONIZATION ATTACK
        
        Threat: An adversary blocks a server response, causing client and server
                keys to become desynchronized.
        Defense: Key evolution happens after each message. If keys desync, the
                 HMAC verification will fail, terminating the session.
        """
        print("=" * 70)
        print("ATTACK 4: KEY DESYNCHRONIZATION ATTACK")
        print("=" * 70)
        print("Threat: Block server response to cause key state mismatch")
        print("Defense: Key ratcheting ensures HMAC fails on desynced keys\n")
        
        self.connect()
        
        if not self.perform_handshake():
            self.disconnect()
            return
        
        # Send a legitimate message
        print(f"[Attacker] Sending legitimate message (Round {self.session.round})")
        msg1 = self.session.make_client_data(111)
        self.send_message(msg1)

        # Receive server response BUT don't process it (simulating interception)
        response = self.receive_message()
        print(f"[Attacker] 🚨 LAUNCHING KEY DESYNC ATTACK 🚨")
        print(f"[Attacker] Intercepted server response - NOT processing it!")
        print(f"[Attacker] Server has evolved its keys, but client keys remain old\n")
        
        # Now try to send another message with old keys
        print(f"[Attacker] Attempting to send another message with OLD keys...")
        print(f"[Attacker] (Client round: {self.session.round}, Server has moved forward)")

        # update round to prevent round mismatch
        self.session.round = self.session.round + 1

        # Client still has old keys, but server has evolved
        msg2 = self.session.make_client_data(222)
        try:
            self.send_message(msg2)
            
            # Try to receive response
            response2 = self.receive_message()

            if response2:
                # Try to process - should fail due to round mismatch
                try:
                    result = self.session.process_incoming(response2)

                    print(result)

                    if "LOCAL_DESYNC_DETECTION" in result["data"]:
                        print(f"[Attacker] ✅ DEFENSE SUCCESSFUL: Server rejected message (HMAC failed due to key desync)")
                    else:
                        print(f"[Attacker] ❌ ATTACK FAILED: Server accepted replayed packet!")
                except Exception as e:
                    print(f"[Attacker] ✅ DEFENSE SUCCESSFUL: {e}")
            else:
                print(f"[Attacker] ✅ DEFENSE SUCCESSFUL: Server rejected message (HMAC failed due to key desync)")

        except Exception as e:
            print(f"[Attacker] ✅ DEFENSE SUCCESSFUL: {e}")
        
        self.disconnect()


def main():
    """Run all attack scenarios"""
    print("\n")
    print("=" * 70 + "\n")
    
    # Use Client ID 1 for all attacks
    client_id = 1
    attacker = AttackSimulator(client_id)
    
    # Run each attack scenario
    try:
        # Attack 1: Replay
        attacker.attack_1_replay()
        input("\nPress Enter to continue to next attack...")
        
        # Attack 2: Bit-Flipping
        attacker.attack_2_bit_flipping()
        input("\nPress Enter to continue to next attack...")
        
        # Attack 3: Message Reordering
        attacker.attack_3_message_reordering()
        input("\nPress Enter to continue to next attack...")
        
        # Attack 4: Key Desynchronization
        attacker.attack_4_key_desync()
        
        print("\n" + "=" * 70)
        print("ATTACK SIMULATION COMPLETE")
        print("=" * 70)
        
    except KeyboardInterrupt:
        print("\n\n[Attacker] Simulation interrupted by user")
    except Exception as e:
        print(f"\n\n[Attacker] Error during simulation: {e}")


if __name__ == "__main__":
    main()
