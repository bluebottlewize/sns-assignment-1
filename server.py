"""
Multi-Threaded Server Implementation for Secure Multi-Client Communication Protocol

This server implements:
1. Non-blocking concurrency using threading
2. State isolation per client ID
3. Synchronized aggregation logic with round buffers
4. Session termination handling
5. Thread-safe operations

Each client connection is handled in a separate thread with independent state.
"""

import socket
import struct
import threading
import time
import os
import sys
from typing import Dict, Optional
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


class AggregationManager:
    """
    Thread-safe manager for synchronized aggregation across multiple clients.
    
    Maintains round-based buffers for collecting client data and computing aggregates.
    """
    
    def __init__(self, timeout: float = 2.0):
        """
        Initialize the aggregation manager.
        
        Args:
            timeout: Time to wait for additional clients before aggregating (seconds)
        """
        self.lock = threading.Lock()
        # Structure: {round_number: {client_id: value}}
        self.round_data: Dict[int, Dict[int, int]] = {}
        # Track when data was last added to each round
        self.round_timestamps: Dict[int, float] = {}
        self.timeout = timeout
    
    def add_data(self, client_id: int, round_num: int, value: int):
        """
        Add client data to the aggregation buffer for a specific round.
        
        Args:
            client_id: Client identifier
            round_num: Protocol round number
            value: Numeric value from client
        """
        with self.lock:
            if round_num not in self.round_data:
                self.round_data[round_num] = {}
                self.round_timestamps[round_num] = time.time()
            
            self.round_data[round_num][client_id] = value
            # Update timestamp when new data arrives
            self.round_timestamps[round_num] = time.time()
            
            print(f"[Aggregation] Client {client_id} added value {value} to Round {round_num}")
            print(f"[Aggregation] Round {round_num} current data: {self.round_data[round_num]}")
    
    def get_aggregate(self, round_num: int, wait: bool = True) -> int:
        """
        Compute the aggregate (sum) for a specific round.
        
        Args:
            round_num: Protocol round number
            wait: Whether to wait for the timeout period before aggregating
            
        Returns:
            Aggregated sum of all values in the round
        """
        if wait:
            # Wait for timeout to allow other clients to submit data
            time.sleep(self.timeout)
        
        with self.lock:
            if round_num not in self.round_data:
                # No data for this round yet (late joiner or solo client)
                print(f"[Aggregation] No data for Round {round_num}, returning 0")
                return 0
            
            values = list(self.round_data[round_num].values())
            aggregate = sum(values)
            
            print(f"[Aggregation] Round {round_num} aggregate: {aggregate} from {len(values)} client(s)")
            print(f"[Aggregation] Individual values: {values}")
            
            return aggregate
    
    def cleanup_round(self, round_num: int):
        """
        Clean up data for a completed round.
        
        Args:
            round_num: Protocol round number to clean up
        """
        with self.lock:
            if round_num in self.round_data:
                del self.round_data[round_num]
            if round_num in self.round_timestamps:
                del self.round_timestamps[round_num]
            print(f"[Aggregation] Cleaned up Round {round_num}")


class ClientHandler(threading.Thread):
    """
    Thread handler for a single client connection.
    
    Each client gets its own thread with isolated state.
    """
    
    def __init__(self, conn: socket.socket, addr: tuple, aggregation_manager: AggregationManager, master_keys: dict):
        """
        Initialize the client handler.
        
        Args:
            conn: Client socket connection
            addr: Client address (host, port)
            aggregation_manager: Shared aggregation manager
            master_keys: Dictionary of pre-shared master keys from .env
        """
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr
        self.aggregation_manager = aggregation_manager
        self.master_keys = master_keys
        
        # Client-specific state (will be initialized after handshake)
        self.client_id: Optional[int] = None
        self.session: Optional[ProtocolSession] = None
        self.terminated = False
        
        print(f"[Server] New connection from {addr}")
    
    def run(self):
        """
        Main thread execution - handles all communication with the client.
        """
        try:
            # Handshake phase
            if not self.handshake():
                print(f"[Client {self.client_id}] Handshake failed, closing connection")
                return
            
            print(f"[Client {self.client_id}] Handshake complete, entering ACTIVE phase")
            
            # Main communication loop
            while not self.terminated:
                try:
                    # Receive message from client
                    message = self.receive_message()
                    if not message:
                        print(f"[Client {self.client_id}] Connection closed")
                        break
                    
                    # Process the message
                    self.handle_message(message)
                    
                except Exception as e:
                    print(f"[Client {self.client_id}] Error: {e}")
                    self.terminate_session(f"Error processing message: {e}")
                    break
                    
        except Exception as e:
            print(f"[Connection {self.addr}] Fatal error: {e}")
        finally:
            self.cleanup()
    
    def handshake(self) -> bool:
        """
        Perform the handshake with the client.
        
        Returns:
            True if handshake successful, False otherwise
        """
        try:
            # Receive CLIENT_HELLO
            hello_msg = self.receive_message()
            if not hello_msg:
                return False
            
            # Parse the message to extract client ID
            # Format: Opcode(1) + ClientID(1) + Round(4) + Direction(1) + IV(16) + Ciphertext + HMAC(32)
            if len(hello_msg) < 7:
                print(f"[Server] Invalid message length: {len(hello_msg)}")
                return False
            
            client_id = hello_msg[1]  # Extract client ID from header
            self.client_id = client_id
            
            print(f"[Client {client_id}] Received CLIENT_HELLO")
            
            # Read pre-shared master key from loaded .env file
            key_name = f"CLIENT_{client_id}_KEY"
            master_key_hex = self.master_keys.get(key_name)
            
            if not master_key_hex:
                print(f"[Server] Error: {key_name} not found in .env file for Client {client_id}")
                return False
            
            try:
                master_key = bytes.fromhex(master_key_hex)
                if len(master_key) != 32:
                    print(f"[Server] Error: Key for Client {client_id} must be 32 bytes, got {len(master_key)}")
                    return False
            except ValueError as e:
                print(f"[Server] Error: Invalid key format for Client {client_id}: {e}")
                return False
            
            # Initialize protocol session for this client
            self.session = ProtocolSession("server", client_id, master_key)
            
            # Process CLIENT_HELLO and generate SERVER_CHALLENGE
            result = self.session.process_incoming(hello_msg)
            challenge_msg = result["response"]
            
            # Send SERVER_CHALLENGE
            self.send_message(challenge_msg)
            print(f"[Client {client_id}] Sent SERVER_CHALLENGE")
            
            return True
            
        except Exception as e:
            print(f"[Server] Handshake error: {e}")
            return False
    
    def handle_message(self, message: bytes):
        """
        Handle a message from the client in ACTIVE phase.
        
        Args:
            message: Raw message bytes
        """
        try:
            # Process the incoming message
            # The session.process_incoming() performs strict validation:
            #   1. Verify header (Round, Direction=C2S, Client ID)
            #   2. Verify HMAC (before decryption)
            #   3. Decrypt and unpad
            #   4. Extract data value
            #   5. Key evolution (C2S keys updated)
            result = self.session.process_incoming(message)

            # 2. Handle Automated Error Responses (e.g., Local Desync Detection)
            # If process_incoming detected an HMAC/Padding error, it generates
            # a KEY_DESYNC_ERROR packet and puts it in result["response"].
            if result.get("response"):
                print(f"[Client {self.client_id}] Local Desync detected. Sending Error Packet.")
                self.send_message(result["response"])
                self.terminate_session("Local Desync Detection")
                return

            # 3. Handle Peer Signaling (Termination or Desync reported by Client)
            status = str(result["data"])

            if "TERMINATED" in status:
                # This covers both OP_TERMINATE and OP_KEY_DESYNC_ERROR received from client
                print(f"[Client {self.client_id}] Session closed by peer signal: {status}")

                # Use a specialized cleanup to ensure they are removed from aggregation
                self.on_client_dropped(status)
                return
            
            # Extract the numeric value
            value = result["data"]

            current_round = self.session.round
            
            print(f"[Client {self.client_id}] Received CLIENT_DATA: {value} (Round {current_round})")
            
            # Add to aggregation buffer
            self.aggregation_manager.add_data(self.client_id, current_round, value)
            
            # Compute aggregate (waits for timeout to allow other clients)
            aggregate = self.aggregation_manager.get_aggregate(current_round, wait=True)
            
            # Generate response with aggregated result
            # The session.make_aggr_response() performs:
            #   1. Pack aggregate as 4-byte unsigned int
            #   2. Manual PKCS#7 padding
            #   3. Generate fresh 16-byte IV
            #   4. AES-128-CBC encryption with evolved S2C_Enc key
            #   5. HMAC-SHA256 with evolved S2C_Mac key
            #   6. Key evolution (S2C keys updated)
            #   7. Increment round number
            response_msg = self.session.make_aggr_response(aggregate)
            
            # Send response to client
            self.send_message(response_msg)
            print(f"[Client {self.client_id}] Sent SERVER_AGGR_RESPONSE: {aggregate} (Round {self.session.round})")
            
            # Cleanup old round data
            if current_round > 0:
                self.aggregation_manager.cleanup_round(current_round - 1)
                
        except Exception as e:
            # Any error in validation terminates the session
            self.terminate_session(f"Message processing failed: {e}")
            raise
    
    def send_message(self, message: bytes):
        """
        Send a message to the client.
        
        Args:
            message: Complete protocol message bytes
        """
        try:
            # Send message length first (4 bytes, big-endian)
            msg_len = struct.pack("!I", len(message))
            self.conn.sendall(msg_len + message)
        except Exception as e:
            raise ConnectionError(f"Failed to send message: {e}")
    
    def receive_message(self) -> Optional[bytes]:
        """
        Receive a message from the client.
        
        Returns:
            Complete protocol message bytes, or None if connection closed
        """
        try:
            # Receive message length first (4 bytes)
            len_data = self._recv_exact(4)
            if not len_data or len(len_data) < 4:
                return None
            
            msg_len = struct.unpack("!I", len_data)[0]
            
            # Sanity check on message length
            if msg_len > 10 * 1024 * 1024:  # 10 MB max
                raise ValueError(f"Message too large: {msg_len} bytes")
            
            # Receive the actual message
            message = self._recv_exact(msg_len)
            if not message or len(message) < msg_len:
                return None
            
            return message
            
        except Exception as e:
            print(f"[Client {self.client_id}] Receive error: {e}")
            return None
    
    def _recv_exact(self, n: int) -> bytes:
        """
        Receive exactly n bytes from the socket.
        
        Args:
            n: Number of bytes to receive
            
        Returns:
            Exactly n bytes, or less if connection closed
        """
        data = b''
        while len(data) < n:
            chunk = self.conn.recv(n - len(data))
            if not chunk:
                return data
            data += chunk
        return data
    
    def terminate_session(self, reason: str):
        """
        Terminate the session with this client.
        
        Args:
            reason: Reason for termination
        """
        print(f"[Client {self.client_id}] Session terminated: {reason}")
        self.terminated = True
        if self.session:
            self.session._terminate(f"Client sent: {reason}")
            self.session.terminated = True
    
    def cleanup(self):
        """Clean up resources."""
        try:
            self.conn.close()
        except:
            pass
        print(f"[Client {self.client_id}] Connection closed")


class SecureServer:
    """
    Multi-threaded secure server for handling multiple client connections.
    """
    
    def __init__(self, host: str = '0.0.0.0', port: int = 9999, aggregation_timeout: float = 2.0):
        """
        Initialize the secure server.
        
        Args:
            host: Server host address
            port: Server port number
            aggregation_timeout: Time to wait before aggregating (seconds)
        """
        self.host = host
        self.port = port
        self.aggregation_manager = AggregationManager(timeout=aggregation_timeout)
        self.server_socket = None
        self.running = False
        
        # Load pre-shared master keys from .env file
        self.master_keys = load_env_file('.env')
        
        # Thread-safe dictionary to track active clients
        self.active_clients: Dict[int, ClientHandler] = {}
        self.clients_lock = threading.Lock()
    
    def start(self):
        """
        Start the server and listen for connections.
        """
        try:
            # Create server socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            
            self.running = True
            
            print("=" * 60)
            print(f"Secure Multi-Client Server Started")
            print(f"Listening on {self.host}:{self.port}")
            print(f"Aggregation timeout: {self.aggregation_manager.timeout}s")
            print("=" * 60)
            print()
            
            # Accept connections
            while self.running:
                try:
                    conn, addr = self.server_socket.accept()
                    
                    # Create and start handler thread
                    handler = ClientHandler(conn, addr, self.aggregation_manager, self.master_keys)
                    handler.start()
                    
                except KeyboardInterrupt:
                    print("\n[Server] Shutting down...")
                    break
                except Exception as e:
                    if self.running:
                        print(f"[Server] Error accepting connection: {e}")
                        
        finally:
            self.stop()
    
    def stop(self):
        """Stop the server and clean up resources."""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        print("[Server] Server stopped")


def main():
    """
    Main entry point for the server application.
    """
    import sys
    
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9999
    timeout = float(sys.argv[2]) if len(sys.argv) > 2 else 2.0
    
    print("Starting Secure Multi-Client Server")
    print(f"Port: {port}")
    print(f"Aggregation timeout: {timeout}s\n")
    
    server = SecureServer(host='0.0.0.0', port=port, aggregation_timeout=timeout)
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[Server] Interrupted by user")
    except Exception as e:
        print(f"[Server] Fatal error: {e}")


if __name__ == "__main__":
    main()
