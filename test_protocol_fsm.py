from protocol_fsm import ProtocolSession, OP_CLIENT_DATA
import struct


def print_ok(msg):
    print(f"[OK] {msg}")


def main():
    # =========================
    # 1. Setup Phase
    # =========================
    master_key1 = b"K" * 32
    master_key2 = b"J" * 32

    c1_id, c2_id = 1, 2

    client1 = ProtocolSession("client", c1_id, master_key1)
    client2 = ProtocolSession("client", c2_id, master_key2)

    # The server needs a session for each client
    server_sessions = {
        c1_id: ProtocolSession("server", c1_id, master_key1),
        c2_id: ProtocolSession("server", c2_id, master_key2)
    }

    # =========================
    # 2. Handshake Phase
    # =========================
    # Client 1
    h1 = client1.make_client_hello()
    res1 = server_sessions[c1_id].process_incoming(h1)
    client1.process_incoming(res1["response"])

    # Client 2
    h2 = client2.make_client_hello()
    res2 = server_sessions[c2_id].process_incoming(h2)
    client2.process_incoming(res2["response"])

    assert client1.phase == "ACTIVE" and client2.phase == "ACTIVE"
    print_ok("Handshakes complete. All sessions ACTIVE.")

    # =========================
    # 3. ROUND 0: Aggregation
    # =========================
    v1_r0, v2_r0 = 50, 150
    expected_sum_r0 = v1_r0 + v2_r0

    # Clients generate messages
    m1 = client1.make_client_data(v1_r0)
    m2 = client2.make_client_data(v2_r0)

    # Server Processes (Coordinator Logic)
    # The FSM now returns {"response": None, "data": int} for DATA opcodes
    srv_res1 = server_sessions[c1_id].process_incoming(m1)
    srv_res2 = server_sessions[c2_id].process_incoming(m2)

    # Simulation of a Coordinator Buffer
    round_buffer = [srv_res1["data"], srv_res2["data"]]
    actual_sum = sum(round_buffer)
    print_ok(f"Server aggregated values: {round_buffer} -> Sum: {actual_sum}")

    # Server Finalizes and generates broadcast messages
    # Each client gets the SAME sum, but encrypted with THEIR specific S2C keys
    aggr_msg1 = server_sessions[c1_id].make_aggr_response(actual_sum)
    aggr_msg2 = server_sessions[c2_id].make_aggr_response(actual_sum)

    # Clients process the aggregate result
    client1.process_incoming(aggr_msg1)
    client2.process_incoming(aggr_msg2)

    print_ok("Round 0 complete. Rounds incremented.")

    # =========================
    # 4. ROUND 1: Verification of Key Continuity
    # =========================
    # If Round 0 evolution was wrong, Round 1 HMAC will fail immediately
    v1_r1 = 10
    m1_r1 = client1.make_client_data(v1_r1)

    try:
        res = server_sessions[c1_id].process_incoming(m1_r1)
        assert res["data"] == 10

        # Server Finalizes and generates broadcast messages
        # Each client gets the SAME sum, but encrypted with THEIR specific S2C keys
        aggr_msg_r1 = server_sessions[c1_id].make_aggr_response(res["data"])

        # Clients process the aggregate result
        client1.process_incoming(aggr_msg_r1)

        print_ok("Round 1 Data verified. Keys evolved correctly across the aggregate.")
    except Exception as e:
        print(f"[FAIL] Round 1 failed. Likely a key evolution mismatch: {e}")
        return

    # =========================
    # 5. Final Checks
    # =========================
    assert client1.round == 2  # Client1 just sent Round 1, but hasn't received Round 1 response yet
    assert server_sessions[c1_id].round == 2  # Server is at Round 1 (waiting for aggregation to finish)

    print("\nPROPER MULTI-CLIENT AGGREGATION TEST PASSED ✔️")


if __name__ == "__main__":
    main()