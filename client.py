"""
Client-Side Implementation for Secure Multi-Client Communication Protocol

This client follows a sequential, state-dependent flow:
1. INIT Phase: Generate keys from master key, send CLIENT_HELLO
2. Receive SERVER_CHALLENGE and transition to ACTIVE
3. Send CLIENT_DATA with numeric values
4. Receive SERVER_AGGR_RESPONSE with aggregated results
5. Key evolution after each successful message exchange

All messages follow Encrypt-then-MAC with strict validation order.
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


class SecureClient:
    """
    Secure client implementation with state management and protocol handling.
    """
    
    def __init__(self, client_id: int, master_key: bytes, server_host: str = 'localhost', server_port: int = 9999):
        """
        Initialize the secure client.
        
        Args:
            client_id: Unique client identifier (1-255)
            master_key: Pre-shared master key for key derivation
            server_host: Server hostname or IP address
            server_port: Server port number
        """
        self.client_id = client_id
        self.master_key = master_key
        self.server_host = server_host
        self.server_port = server_port
        
        # Initialize protocol FSM
        self.session = ProtocolSession("client", client_id, master_key)
        
        # Socket connection
        self.sock = None
        self.connected = False
        
    def connect(self):
        """
        Establish TCP connection to the server.
        
        Raises:
            ConnectionError: If connection fails
        """
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.server_host, self.server_port))
            self.connected = True
            print(f"[Client {self.client_id}] Connected to {self.server_host}:{self.server_port}")
        except Exception as e:
            raise ConnectionError(f"Failed to connect to server: {e}")
    
    def disconnect(self):
        """Close the connection to the server."""
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            finally:
                self.connected = False
                print(f"[Client {self.client_id}] Disconnected from server")
    
    def send_message(self, message: bytes):
        """
        Send a message to the server.
        
        Args:
            message: Complete protocol message bytes
            
        Raises:
            ConnectionError: If not connected or send fails
        """
        if not self.connected:
            raise ConnectionError("Not connected to server")
        
        try:
            # Send message length first (4 bytes, big-endian)
            msg_len = struct.pack("!I", len(message))
            self.sock.sendall(msg_len + message)
            print(f"[Client {self.client_id}] Sent {len(message)} bytes")
        except Exception as e:
            self.disconnect()
            raise ConnectionError(f"Failed to send message: {e}")
    
    def receive_message(self) -> bytes:
        """
        Receive a message from the server.
        
        Returns:
            Complete protocol message bytes
            
        Raises:
            ConnectionError: If not connected or receive fails
        """
        if not self.connected:
            raise ConnectionError("Not connected to server")
        
        try:
            # Receive message length first (4 bytes)
            len_data = self._recv_exact(4)
            if not len_data:
                raise ConnectionError("Connection closed by server")
            
            msg_len = struct.unpack("!I", len_data)[0]
            
            # Receive the actual message
            message = self._recv_exact(msg_len)
            if not message:
                raise ConnectionError("Connection closed by server")
            
            print(f"[Client {self.client_id}] Received {len(message)} bytes")
            return message
            
        except Exception as e:
            self.disconnect()
            raise ConnectionError(f"Failed to receive message: {e}")
    
    def _recv_exact(self, n: int) -> bytes:
        """
        Receive exactly n bytes from the socket.
        
        Args:
            n: Number of bytes to receive
            
        Returns:
            Exactly n bytes
        """
        data = b''
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                return data
            data += chunk
        return data
    
    def handshake(self):
        """
        Perform the INIT phase handshake with the server.
        
        This involves:
        1. Send CLIENT_HELLO (Opcode 10)
        2. Receive SERVER_CHALLENGE (Opcode 20)
        3. Transition to ACTIVE phase
        
        The protocol_fsm handles:
        - Manual PKCS#7 padding
        - AES-128-CBC encryption with fresh IV
        - HMAC-SHA256 calculation over header + IV + ciphertext
        - Header verification (Round, Direction)
        - HMAC verification before decryption
        - Decryption and padding removal
        
        Raises:
            Exception: If handshake fails
        """
        print(f"[Client {self.client_id}] Starting handshake...")
        
        # Step 1: Send CLIENT_HELLO
        hello_msg = self.session.make_client_hello()
        self.send_message(hello_msg)
        print(f"[Client {self.client_id}] Sent CLIENT_HELLO (Round {self.session.round})")
        
        # Step 2: Receive SERVER_CHALLENGE
        challenge_msg = self.receive_message()
        
        # Step 3: Process SERVER_CHALLENGE (strict validation order)
        # The session.process_incoming() performs:
        #   1. Parse message
        #   2. Verify header (Round, Direction=S2C)
        #   3. Verify HMAC (before decryption)
        #   4. Decrypt and unpad
        #   5. Validate plaintext format
        #   6. Transition to ACTIVE phase
        result = self.session.process_incoming(challenge_msg)
        
        print(f"[Client {self.client_id}] Received SERVER_CHALLENGE")
        print(f"[Client {self.client_id}] Handshake complete - Now in {self.session.phase} phase")
    
    def send_data(self, value: int) -> int:
        """
        Send numeric data to the server and receive aggregated result.
        
        Args:
            value: Integer value to send
            
        Returns:
            Aggregated result from server
            
        Raises:
            Exception: If communication fails
        """
        print(f"[Client {self.client_id}] Sending data: {value} (Round {self.session.round})")
        
        # Step 1: Send CLIENT_DATA (Opcode 30)
        # The session.make_client_data() performs:
        #   1. Pack value as 4-byte unsigned int
        #   2. Manual PKCS#7 padding
        #   3. Generate fresh 16-byte IV
        #   4. AES-128-CBC encryption
        #   5. HMAC-SHA256 over header + IV + ciphertext
        #   6. Key evolution (C2S keys updated)
        data_msg = self.session.make_client_data(value)
        self.send_message(data_msg)
        
        # Step 2: Receive SERVER_AGGR_RESPONSE (Opcode 40)
        response_msg = self.receive_message()
        
        # Step 3: Process response (strict validation order)
        # The session.process_incoming() performs:
        #   1. Verify header (Round, Direction=S2C)
        #   2. Verify HMAC (before decryption)
        #   3. Decrypt and unpad
        #   4. Extract aggregated value
        #   5. Key evolution (S2C keys updated)
        #   6. Increment round number
        result = self.session.process_incoming(response_msg)
        
        aggregated_value = result["data"]
        print(f"[Client {self.client_id}] Received aggregated result: {aggregated_value} (Round {self.session.round})")
        
        return aggregated_value

    def terminate(self, reason: str = "Client Logout"):
        """
        Gracefully notifies the server and shuts down the local session.

        Args:
            reason: String explaining why the session is ending
        """
        if self.session.terminated:
            print(f"[Client {self.client_id}] Session already terminated.")
            return

        print(f"[Client {self.client_id}] Initiating termination: {reason}")

        # Step 1: Create the TERMINATE packet (Opcode 60)
        try:
            term_msg = self.session.make_terminate_msg(reason)
            # Step 2: Send the packet
            # Even though our keys are now wiped, the bytes are already in 'term_msg'
            self.send_message(term_msg)

            print(f"[Client {self.client_id}] Termination signal sent. Keys zeroized.")

        except Exception as e:
            # If sending fails, we still ensure the session is dead locally
            self.session._terminate(f"Failed to send termination packet: {e}")
            print(f"[Client {self.client_id}] Force closed session due to: {e}")
    
    def run_interactive(self):
        """
        Run the client in interactive mode.
        
        User can input values to send to the server.
        """
        try:
            # Connect and handshake
            self.connect()
            self.handshake()
            
            print("\n" + "=" * 50)
            print(f"Client {self.client_id} is ready!")
            print("Enter numeric values to send to the server.")
            print("Type 'quit' to exit.")
            print("=" * 50 + "\n")
            
            # Main communication loop
            while True:
                try:
                    user_input = input(f"[Client {self.client_id}] Enter value: ").strip()
                    
                    if user_input.lower() in ['quit', 'exit', 'q']:
                        print(f"[Client {self.client_id}] Exiting...")
                        break
                    
                    try:
                        value = int(user_input)
                        if value < 0 or value > 4294967295:  # 32-bit unsigned int range
                            print("Error: Value must be between 0 and 4294967295")
                            continue
                        
                        # Send data and get result
                        result = self.send_data(value)
                        print(f"[Client {self.client_id}] ✓ Success! Aggregated result: {result}\n")
                        
                    except ValueError:
                        print("Error: Please enter a valid integer")
                        
                except KeyboardInterrupt:
                    print(f"\n[Client {self.client_id}] Interrupted by user")
                    break
                except Exception as e:
                    print(f"[Client {self.client_id}] Error: {e}")
                    break
                    
        finally:
            self.terminate()
            self.disconnect()


def main():
    """
    Main entry point for the client application.
    """
    if len(sys.argv) < 2:
        print("Usage: python client.py <client_id> [server_host] [server_port]")
        print("Example: python client.py 1")
        print("Example: python client.py 2 localhost 9999")
        sys.exit(1)
    
    try:
        client_id = int(sys.argv[1])
        if client_id < 1 or client_id > 255:
            print("Error: Client ID must be between 1 and 255")
            sys.exit(1)
    except ValueError:
        print("Error: Client ID must be an integer")
        sys.exit(1)
    
    server_host = sys.argv[2] if len(sys.argv) > 2 else 'localhost'
    server_port = int(sys.argv[3]) if len(sys.argv) > 3 else 9999
    
    # Load pre-shared master keys from .env file
    env_vars = load_env_file('.env')
    
    # Read master key for this client
    key_name = f"CLIENT_{client_id}_KEY"
    master_key_hex = env_vars.get(key_name)
    
    if not master_key_hex:
        print(f"Error: {key_name} not found in .env file")
        print(f"Please add it to .env: {key_name}=<64-character-hex-key>")
        sys.exit(1)
    
    try:
        master_key = bytes.fromhex(master_key_hex)
        if len(master_key) != 32:
            raise ValueError(f"Key must be exactly 32 bytes (64 hex characters), got {len(master_key)} bytes")
    except ValueError as e:
        print(f"Error: Invalid master key format: {e}")
        print(f"Key must be 64 hexadecimal characters (32 bytes)")
        sys.exit(1)
    
    print(f"Starting Secure Client {client_id}")
    print(f"Server: {server_host}:{server_port}")
    print(f"Master Key: {master_key.hex()[:32]}...\n")
    
    client = SecureClient(client_id, master_key, server_host, server_port)
    client.run_interactive()


if __name__ == "__main__":
    main()
