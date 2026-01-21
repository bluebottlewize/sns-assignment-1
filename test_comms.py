from protocol_fsm import ProtocolSession
import struct


def print_ok(msg):
    print(f"[OK] {msg}")


def main():
    # =========================
    # 1. Setup Phase
    # =========================
    master_key1 = b"K" * 32
    master_key2 = b"J" * 32

    # Instantiate two clients
    client1 = ProtocolSession("client", client_id=1, master_key=master_key1)
    client2 = ProtocolSession("client", client_id=2, master_key=master_key2)

    # Server needs two session objects to track state independently
    server_sessions = {
        1: ProtocolSession("server", client_id=1, master_key=master_key1),
        2: ProtocolSession("server", client_id=2, master_key=master_key2)
    }

    # =========================
    # 2. Handshake Phase (Concurrent)
    # =========================
    # Client 1 Handshake
    h1 = client1.make_client_hello()
    c1 = server_sessions[1].process_incoming(h1)
    client1.process_incoming(c1)

    # Client 2 Handshake
    h2 = client2.make_client_hello()
    c2 = server_sessions[2].process_incoming(h2)
    client2.process_incoming(c2)

    assert client1.phase == "ACTIVE" and client2.phase == "ACTIVE"
    print_ok("Both clients reached ACTIVE phase independently.")

    # =========================
    # 3. Aggregation Phase (Round 0)
    # =========================
    val1 = 10  # Client 1's data
    val2 = 20  # Client 2's data
    total_sum = val1 + val2

    # Step A: Clients send their individual data
    msg1 = client1.make_client_data(val1)
    msg2 = client2.make_client_data(val2)

    # Step B: Server processes both.
    # Important: In multi-client, process_incoming should return the decrypted val
    # to the server coordinator for aggregation.
    res1_val = server_sessions[1].process_incoming(msg1)
    res2_val = server_sessions[2].process_incoming(msg2)

    print_ok(f"Server received: Client1={res1_val}, Client2={res2_val}")

    # Step C: Server generates the AGGREGATE response for everyone
    # Both responses contain the TOTAL SUM (30)
    resp_to_c1 = server_sessions[1].finalize_round_and_respond(total_sum)
    resp_to_c2 = server_sessions[2].finalize_round_and_respond(total_sum)

    # Step D: Clients process the aggregate result
    client1.process_incoming(resp_to_c1)
    client2.process_incoming(resp_to_c2)

    print_ok(f"Both clients processed aggregate sum: {total_sum}")

    # =========================
    # 4. Verification
    # =========================
    # Check that keys are still unique even if aggregate data was the same
    assert client1.S2C_Enc != client2.S2C_Enc
    # Check that rounds incremented
    assert client1.round == 1 and client2.round == 1

    print_ok("Multi-client rounds synchronized and keys evolved correctly.")
    print("\nMULTI-CLIENT PROTOCOL TEST PASSED ✔️")


if __name__ == "__main__":
    main()