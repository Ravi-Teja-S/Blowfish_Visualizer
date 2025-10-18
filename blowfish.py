# blowfish_full_visualizer_with_decrypt_fixed.py
import streamlit as st
import struct
import binascii
import pandas as pd
from blowfish_constants import P_ARRAY, S_BOXES


# ---------- Blowfish core ----------
def F(x, S):
    a = (x >> 24) & 0xFF
    b = (x >> 16) & 0xFF
    c = (x >> 8) & 0xFF
    d = x & 0xFF
    s1 = S[0][a]
    s2 = S[1][b]
    s3 = S[2][c]
    s4 = S[3][d]
    return (((s1 + s2) ^ s3) + s4) & 0xFFFFFFFF


def encrypt_block(L, R, P, S):
    rounds = []
    for i in range(16):
        L = (L ^ P[i]) & 0xFFFFFFFF
        F_out = F(L, S)
        R = (R ^ F_out) & 0xFFFFFFFF
        rounds.append({"round": i + 1, "L": f"{L:08X}", "R": f"{R:08X}", "F(L)": f"{F_out:08X}"})
        L, R = R, L
    # undo last swap (as in spec)
    L, R = R, L
    R = (R ^ P[16]) & 0xFFFFFFFF
    L = (L ^ P[17]) & 0xFFFFFFFF
    return L, R, rounds


def decrypt_block(L, R, P, S):
    rounds = []
    # Reverse of encryption — exact inverse
    for i in range(17, 1, -1):  # i = 17 down to 2 inclusive
        L = (L ^ P[i]) & 0xFFFFFFFF
        F_out = F(L, S)
        R = (R ^ F_out) & 0xFFFFFFFF
        rounds.append({
            "round": 19 - i,
            "L": f"{L:08X}",
            "R": f"{R:08X}",
            "F(L)": f"{F_out:08X}"
        })
        L, R = R, L  # swap

    # undo final swap
    L, R = R, L
    R ^= P[1]
    L ^= P[0]
    return L, R, rounds


def pad8(data_bytes):
    # zero padding variant: don't add an extra full block when already aligned
    if len(data_bytes) % 8 == 0:
        return data_bytes
    pad_len = 8 - (len(data_bytes) % 8)
    return data_bytes + b'\x00' * pad_len


def key_expansion(key_bytes: bytes):
    P = P_ARRAY.copy()
    S = [s.copy() for s in S_BOXES]
    key_len = len(key_bytes)
    if key_len == 0:
        raise ValueError("Key must be at least 1 byte")
    j = 0
    for i in range(len(P)):
        data = 0
        for k in range(4):
            data = (data << 8) | key_bytes[j]
            j = (j + 1) % key_len
        P[i] ^= data
    L, R = 0, 0
    for i in range(0, len(P), 2):
        L, R, _ = encrypt_block(L, R, P, S)
        P[i], P[i + 1] = L, R
    for box in range(4):
        for i in range(0, 256, 2):
            L, R, _ = encrypt_block(L, R, P, S)
            S[box][i], S[box][i + 1] = L, R
    return P, S


# ---------- Cached functions ----------
@st.cache_data
def compute_results(key_bytes, plaintext_bytes):
    P, S = key_expansion(key_bytes)
    data = pad8(plaintext_bytes)
    blocks = [data[i:i + 8] for i in range(0, len(data), 8)]
    results = []
    for idx, block in enumerate(blocks):
        L, R = struct.unpack(">II", block)
        Lf, Rf, rounds = encrypt_block(L, R, P, S)
        cipher_block = struct.pack(">II", Lf, Rf)
        cipher_hex = binascii.hexlify(cipher_block).decode().upper()
        results.append({"block_index": idx, "initial_L": f"{L:08X}", "initial_R": f"{R:08X}",
                        "rounds": rounds, "cipher_hex": cipher_hex})
    return P, S, results


# decrypt_results kept for completeness but not necessary if we reuse P,S from session
@st.cache_data
def decrypt_results_with_key_expansion(key_bytes, cipher_bytes):
    P, S = key_expansion(key_bytes)
    if len(cipher_bytes) % 8 != 0:
        raise ValueError("Ciphertext length must be multiple of 8 bytes (16 hex chars per block).")
    blocks = [cipher_bytes[i:i + 8] for i in range(0, len(cipher_bytes), 8)]
    decrypted = []
    for idx, block in enumerate(blocks):
        L, R = struct.unpack(">II", block)
        Lf, Rf, rounds = decrypt_block(L, R, P, S)
        plain_block = struct.pack(">II", Lf, Rf)
        cipher_hex = binascii.hexlify(plain_block).decode().upper()
        decrypted.append({"block_index": idx, "initial_L" : f"{L:08X}","initial_R":f"{R:08X}", "rounds": rounds,"cipher_hex":cipher_hex})
    return P, S, decrypted


# ---------------------------- Streamlit UI ----------------------------
st.set_page_config(page_title="Blowfish Visualizer (with Decrypt)", layout="wide")
st.title("🔐 Blowfish Full Visualizer")

# Tabs layout
tab_main, tab_encrypt, tab_decrypt = st.tabs(["🧩 Main Interface", "⚙️ Encryption Details", "🔁 Decryption Details"])

# Initialize session
for key_ in ["results", "P", "S", "full_cipher_hex"]:
    if key_ not in st.session_state:
        st.session_state[key_] = None if key_ != "full_cipher_hex" else ""

# --------------------- MAIN TAB ---------------------
with tab_main:
    st.header("Main Encryption / Decryption Panel")

    key = st.text_input("🔑 Key (1–56 bytes):", "MySecretKey")
    plaintext = st.text_input("✉️ Plaintext (any length, auto-padded):", "HELLO123")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("🚀 Encrypt"):
            try:
                key_bytes = key.encode("utf-8")
                plaintext_bytes = plaintext.encode("utf-8")
                P, S, results = compute_results(key_bytes, plaintext_bytes)
                st.session_state.P, st.session_state.S = P, S
                st.session_state.results = results
                st.session_state.full_cipher_hex = "".join([r["cipher_hex"] for r in results])
                st.success("Encryption complete ✅")
            except Exception as e:
                st.error(f"Encryption error: {e}")

    with col2:
        cipher_prefill = st.session_state.full_cipher_hex or ""
        cipher_input = st.text_area("🧮 Ciphertext (Hex, 16 chars per block)", cipher_prefill, height=120,key="ciphertext_encrypt")
        if st.button("🔓 Decrypt"):
            try:
                if not cipher_input.strip():
                    st.warning("Please enter ciphertext or run Encrypt first.")
                else:
                    hex_str = "".join(cipher_input.split())
                    cipher_bytes = binascii.unhexlify(hex_str)
                    key_bytes = key.encode("utf-8")

                    # Use same P,S if available
                    P_dec, S_dec = (st.session_state.P, st.session_state.S) if st.session_state.P else key_expansion(key_bytes)

                    decrypted_blocks, plaintext_bytes = [], []
                    for i in range(0, len(cipher_bytes), 8):
                        L, R = struct.unpack(">II", cipher_bytes[i:i + 8])
                        Lf, Rf, _ = decrypt_block(L, R, P_dec, S_dec)
                        decrypted_blocks.append(struct.pack(">II", Lf, Rf))

                    plaintext_bytes = b"".join(decrypted_blocks).rstrip(b"\x00")
                    try:
                        decoded_text = plaintext_bytes.decode("utf-8")
                        st.success(f"✅ Decrypted Text: {decoded_text}")
                    except:
                        st.warning("⚠️ Could not decode as UTF-8 — showing raw bytes:")
                        st.code(binascii.hexlify(plaintext_bytes).decode().upper())

            except Exception as e:
                st.error(f"Decryption error: {e}")

    # Ciphertext result summary
    if st.session_state.results:
        st.divider()
        st.subheader("🔒 Final Ciphertext Output")
        st.code(st.session_state.full_cipher_hex, language="text")

        st.subheader("Final P-Array")
        st.code("\n".join([f"P[{i}] = {hex(p)}" for i, p in enumerate(st.session_state.P)]))

        st.subheader("Final S-boxes (as 16×16 grids)")
        for box_idx, box in enumerate(st.session_state.S):
            st.markdown(f"**S-box {box_idx}**")
            grid_data = [box[i:i + 16] for i in range(0, 256, 16)]
            df_box = pd.DataFrame([[f"{val:08X}" for val in row] for row in grid_data])
            st.dataframe(df_box, use_container_width=True, hide_index=True)

# --------------------- ENCRYPTION TAB ---------------------
with tab_encrypt:
    st.header("Encryption Rounds & State Details")

    if not st.session_state.results:
        st.info("Run encryption first to see details.")
    else:
        st.subheader("📘 Explore Rounds (Global Slider)")
        round_num = st.slider("Round number", 0, 16, 16,key="encryption_slider")

        for res in st.session_state.results:
            st.markdown(f"### 🧱 Block {res['block_index']}")
            if round_num > 0:
                rd = res['rounds'][round_num - 1]
                st.write(f"Round {rd['round']:02}: L = `{rd['L']}`, R = `{rd['R']}`, F(L) = `{rd['F(L)']}`")
            else:
                st.write(f"Initial: L = `{res['initial_L']}`, R = `{res['initial_R']}`")
            st.success(f"Ciphertext: `{res['cipher_hex']}`")

        st.divider()
        summary_df = pd.concat([
            pd.DataFrame(
                block['rounds'][:round_num] if round_num > 0 else [
                    {'round': 0, 'L': block['initial_L'], 'R': block['initial_R'], 'F(L)': ''}]
            ).assign(Block=block['block_index'], Cipher_Hex=block['cipher_hex'])
            for block in st.session_state.results
        ], ignore_index=True)

        # Keep only necessary columns and order
        summary_df = summary_df[['Block', 'round', 'L', 'R', 'F(L)', 'Cipher_Hex']].rename(columns={'round': 'Round'})

        st.dataframe(summary_df, use_container_width=True)

# --------------------- DECRYPTION TAB ---------------------
with tab_decrypt:
    st.header("Decryption Rounds & State Details")

    if not st.session_state.results:
        st.info("Run encryption first to see decryption details.")
    else:
        key_bytes = key.encode("utf-8")
        cipher_hex = st.session_state.full_cipher_hex
        cipher_bytes = binascii.unhexlify(cipher_hex)

        # Use the same P and S from encryption
        P, S = st.session_state.P, st.session_state.S

        # Prepare decryption rounds for all blocks
        decrypted_rounds_results = []
        decrypted_blocks = []

        for idx in range(0, len(cipher_bytes), 8):
            L, R = struct.unpack(">II", cipher_bytes[idx:idx + 8])
            # Run decrypt_block using same P,S (rounds reversed internally)
            Lf, Rf, rounds = decrypt_block(L, R, P, S)
            decrypted_blocks.append(struct.pack(">II", Lf, Rf))
            decrypted_rounds_results.append({
                "block_index": idx // 8,
                "initial_L": f"{L:08X}",
                "initial_R": f"{R:08X}",
                "rounds": rounds,
                "final_hex": binascii.hexlify(struct.pack(">II", Lf, Rf)).decode().upper()
            })

        st.session_state.decrypted_rounds = decrypted_rounds_results

        # Show final decrypted text
        plaintext_bytes = b"".join(decrypted_blocks).rstrip(b"\x00")
        try:
            decoded_text = plaintext_bytes.decode("utf-8")
            st.success(f"✅ Decrypted Text: {decoded_text}")
        except:
            st.warning("⚠️ Could not decode as UTF-8 — showing raw bytes:")
            st.code(binascii.hexlify(plaintext_bytes).decode().upper())

        # Slider to explore decryption rounds
        st.divider()
        st.subheader("📘 Explore Decryption Rounds (Global Slider)")
        round_num_dec = st.slider("Decryption Round number", 0, 16, 16, key="decryption_slider")

        for res in st.session_state.decrypted_rounds:
            st.markdown(f"### 🧱 Block {res['block_index']}")
            if round_num_dec > 0:
                if round_num_dec <= len(res['rounds']):
                    rd = res['rounds'][round_num_dec - 1]
                    st.write(f"""Round {rd['round'] - 1:02}: L = `{rd['L']}`, R = `{rd['R']}`, F(L) = `{rd['F(L)']}`""")
                else:
                    st.write("Round data not available")
            else:
                st.write(f"Initial: L = `{res['initial_L']}`, R = `{res['initial_R']}`")

            st.success(f"Decrypted Hex at this block: `{res['final_hex']}`")
            text = bytes.fromhex(res['final_hex']).decode('utf-8')
            st.success(f"Decrypted Text at this block: {text}")

        st.divider()
        st.title("🔤 UTF-8 Table for A-Z, a-z, 0-9")

        # Character set
        chars = [chr(i) for i in range(ord('A'), ord('Z') + 1)] + \
                [chr(i) for i in range(ord('a'), ord('z') + 1)] + \
                [chr(i) for i in range(ord('0'), ord('9') + 1)]

        # Build UTF-8 table
        utf8_table = pd.DataFrame([
            {
                "Character": ch,
                "UTF-8 (Hex)": f"{ord(ch):02X}",  # Use ord() instead of encode()[0]
                "Decimal": ord(ch)
            }
            for ch in chars
        ])

        # Display with search / sort
        st.dataframe(utf8_table, use_container_width=True)