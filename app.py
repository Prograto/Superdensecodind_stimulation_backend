from flask import Flask, request
from flask_socketio import SocketIO, join_room, emit
import secrets, hashlib, binascii, random
from Crypto.Cipher import AES
from qiskit.quantum_info import Statevector

# --- Qiskit imports ---
SIMULATE_QISKIT = True
try:
    from qiskit import QuantumCircuit, transpile
    from qiskit_aer import AerSimulator
except Exception as e:
    print("⚠️ Qiskit not available, using mock mode:", e)
    SIMULATE_QISKIT = False

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")
rooms = {}  # room_id -> {'sender':sid,'receiver':sid,'qkd_key':bits}

# --- Helpers ---
def bits_from_bytes(b: bytes) -> str:
    return ''.join(f'{byte:08b}' for byte in b)

def bytes_from_bits(bits: str) -> bytes:
    pad_len = (8 - (len(bits) % 8)) % 8
    bits = bits + ('0' * pad_len)
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))

# --- QKD (BB84 simulation) ---
def bb84_simulator(num_bits=256, test_frac=0.2):
    alice_bits = [random.choice([0,1]) for _ in range(num_bits)]
    alice_bases = [random.choice(['Z','X']) for _ in range(num_bits)]
    bob_bases   = [random.choice(['Z','X']) for _ in range(num_bits)]

    bob_bits = []
    for a_bit,a_basis,b_basis in zip(alice_bits,alice_bases,bob_bases):
        if a_basis == b_basis:
            bob_bits.append(a_bit)
        else:
            bob_bits.append(random.choice([0,1]))

    sift_indices = [i for i,(ab,bb) in enumerate(zip(alice_bases,bob_bases)) if ab==bb]
    sifted_alice = [str(alice_bits[i]) for i in sift_indices]
    sifted_bob   = [str(bob_bits[i]) for i in sift_indices]

    if not sifted_alice: return {"success":False,"reason":"no sifted bits"}
    k = max(1, int(len(sifted_alice)*test_frac))
    test_idx = random.sample(range(len(sifted_alice)), k)
    mismatches=0
    for idx in test_idx:
        if sifted_alice[idx]!=sifted_bob[idx]:
            mismatches+=1

    final_key = ''.join(b for i,b in enumerate(sifted_alice) if i not in test_idx)
    return {"success": mismatches==0, "mismatches": mismatches, "key": final_key}

# --- Superdense Coding with qubit state logging ---
def superdense_chunk(two_bits: str, room=None):
    padded = False
    if len(two_bits) < 2:
        padded = True
    two_bits = (two_bits + "00")[:2]

    steps = []

    if not SIMULATE_QISKIT:
        op = {"00":"I","01":"X","10":"Z","11":"XZ"}[two_bits]
        steps.append(f"Alice encode: {op}")
        return {
            "decoded": two_bits,
            "op": op,
            "counts": {two_bits:1},
            "circuit": f"MOCK CIRCUIT encode {two_bits}",
            "steps": steps
        }

    qc = QuantumCircuit(2,2)

    # H on q0
    qc.h(0)
    sv = Statevector.from_instruction(qc)
    steps.append(f"[State] After H on q0: {sv}")
    if room: emit("qubit_state", {"state": str(sv), "step": "H on q0"}, room=room)

    # CNOT q0->q1
    qc.cx(0,1)
    sv = Statevector.from_instruction(qc)
    steps.append(f"[State] After CNOT q0->q1: {sv}")
    if room: emit("qubit_state", {"state": str(sv), "step": "CNOT q0->q1"}, room=room)

    # Alice encode
    op = "I"
    if two_bits == "01":
        qc.x(0)
        op="X"
        steps.append(f"[State] After X on q0: {Statevector.from_instruction(qc)}")
        if room: emit("qubit_state", {"state": str(Statevector.from_instruction(qc)), "step": "X on q0"}, room=room)
    elif two_bits == "10":
        qc.z(0)
        op="Z"
        steps.append(f"[State] After Z on q0: {Statevector.from_instruction(qc)}")
        if room: emit("qubit_state", {"state": str(Statevector.from_instruction(qc)), "step": "Z on q0"}, room=room)
    elif two_bits == "11":
        qc.z(0)
        if room: emit("qubit_state", {"state": str(Statevector.from_instruction(qc)), "step": "Z on q0"}, room=room)
        qc.x(0)
        if room: emit("qubit_state", {"state": str(Statevector.from_instruction(qc)), "step": "X on q0"}, room=room)
        op="XZ"
    # Bob decode
    qc.cx(0,1)
    if room: emit("qubit_state", {"state": str(Statevector.from_instruction(qc)), "step": "Bob CNOT q0->q1"}, room=room)
    qc.h(0)
    if room: emit("qubit_state", {"state": str(Statevector.from_instruction(qc)), "step": "Bob H on q0"}, room=room)

    # Measurement
    qc.measure([0,1],[0,1])
    simulator = AerSimulator()
    compiled = transpile(qc, simulator)
    job = simulator.run(compiled, shots=1)
    counts = job.result().get_counts(qc)
    measured = list(counts.keys())[0]
    decoded = measured if measured==two_bits else measured[::-1]

    return {
        "decoded": decoded,
        "op": op,
        "counts": counts,
        "circuit": str(qc.draw(output="text")),
        "steps": steps
    }


# --- AES helpers ---
def aes_gcm_encrypt(key:bytes, plaintext:str):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return {
        "ciphertext_hex": binascii.hexlify(ciphertext).decode(),
        "nonce_hex": binascii.hexlify(cipher.nonce).decode(),
        "tag_hex": binascii.hexlify(tag).decode()
    }

def aes_gcm_decrypt(key:bytes, ciphertext_hex:str, nonce_hex:str, tag_hex:str):
    try:
        ct = binascii.unhexlify(ciphertext_hex)
        nonce = binascii.unhexlify(nonce_hex)
        tag = binascii.unhexlify(tag_hex)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ct, tag).decode()
    except:
        return None

# --- SocketIO events ---
@socketio.on("join")
def on_join(data):
    role, room = data["role"], data["room"]
    join_room(room)
    rooms.setdefault(room,{})
    rooms[room][role] = request.sid
    emit("joined", {"role":role,"room":room}, room=request.sid)

@socketio.on("send_message")
def on_send_message(data):
    room, msg, use_qkd = data["room"], data["message"], data.get("use_qkd", True)
    if room not in rooms:
        emit("error", {"error": "Room not found"}, room=request.sid)
        return

    # --- Step 1: QKD ---
    if use_qkd or "qkd_key" not in rooms[room]:
        qkd = bb84_simulator()
        if not qkd["success"]:
            emit("qkd_failed", {"reason": "mismatch"}, room=request.sid)
            return
        rooms[room]["qkd_key"] = qkd["key"]
        emit("qkd_key", {"key": qkd["key"]}, room=room)

    # --- Step 2: AES key ---
    key_bits = rooms[room]["qkd_key"]
    aes_key = hashlib.sha256(key_bits.encode()).digest()
    emit("aes_key", {"hex": aes_key.hex()}, room=room)

    # --- Step 0: Bell info ---
    emit("bell_pair", {
        "state":"|Φ+> = (|00> + |11>)/√2",
        "qubit_sender":"Qubit A (Alice)",
        "qubit_receiver":"Qubit B (Bob)"
    }, room=room)

    # --- Step 3: AES encrypt + superdense ---
    enc = aes_gcm_encrypt(aes_key, msg)
    bitstream = bits_from_bytes(binascii.unhexlify(enc["ciphertext_hex"]))
    chunks = [bitstream[i:i+2] for i in range(0,len(bitstream),2)]

    decoded_bits = ""
    for i, ch in enumerate(chunks):
        step_info = superdense_chunk(ch, room=room)  # pass room
        decoded_bits += step_info["decoded"]

        payload = {
            "index": i,
            "encoded": ch,
            "op": step_info.get("op","?"),
            "decoded": step_info["decoded"],
            "counts": step_info.get("counts", {}),
            "circuit": str(step_info.get("circuit","")),
            "steps": step_info.get("steps",[])
        }

        emit("superdense_step", payload, room=room)


    decoded_bytes = bytes_from_bits(decoded_bits[:len(bitstream)])
    decoded_hex = binascii.hexlify(decoded_bytes).decode()

    emit("transmission_complete", {
        "ciphertext_hex": decoded_hex,
        "nonce_hex": enc["nonce_hex"],
        "tag_hex": enc["tag_hex"]
    }, room=room)

    plain = aes_gcm_decrypt(aes_key, decoded_hex, enc["nonce_hex"], enc["tag_hex"])
    emit("verified_plaintext", {"plaintext": plain}, room=room)

if __name__=="__main__":
    socketio.run(app, host="0.0.0.0", port=5000)
