#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
MID-TERM PROJECT: CENTRALIZED KEY DISTRIBUTION & AUTHENTICATION (KERBEROS + AES)
Actors:
  - KDC   : Key Distribution Center Server
  - Tri   : Initiator Client (ID_T = "Tri")
  - Vu    : Responder Server (ID_V = "Vu")
  - Thanh : Malicious Attacker on the network (Replay & Tampering Attacks)
================================================================================
"""

import hashlib
import json
import os
import time

# ==============================================================================
# PART 1: CRYPTOGRAPHIC PRIMITIVES (AES-128-CBC & HMAC-SHA1 FROM SCRATCH)
# ==============================================================================

# Bang S-Box chuan cua AES (Session 4 / Doc2read Table 4.3)
AES_SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]
AES_INV_SBOX = [0] * 256
for idx, val in enumerate(AES_SBOX):
    AES_INV_SBOX[val] = idx

RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

def gf_mul(a: int, b: int) -> int:
    """Nhan 2 phan tu trong truong Galois GF(2^8) voi P(x) = x^8 + x^4 + x^3 + x + 1"""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p

def aes_key_expansion(key: bytes) -> list:
    """Mo rong khoa 128-bit thanh 11 subkeys (Session 4 Slide 26-28)"""
    key_symbols = list(key)
    w = [key_symbols[4*i : 4*(i+1)] for i in range(4)]
    for i in range(4, 44):
        temp = list(w[i - 1])
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [AES_SBOX[b] for b in temp]
            temp[0] ^= RCON[i // 4]
        w.append([w[i - 4][j] ^ temp[j] for j in range(4)])
    return [sum(w[4*r : 4*(r+1)], []) for r in range(11)]

def aes_encrypt_block(block: bytes, round_keys: list) -> bytes:
    """Ma hoa 1 khoi 16 bytes bang AES-128 (10 rounds)"""
    state = [block[i] ^ round_keys[0][i] for i in range(16)]
    for r in range(1, 11):
        # 1. Byte Substitution
        state = [AES_SBOX[b] for b in state]
        # 2. ShiftRows (column-major state)
        state = [
            state[0], state[5], state[10], state[15],
            state[4], state[9], state[14], state[3],
            state[8], state[13], state[2], state[7],
            state[12], state[1], state[6], state[11]
        ]
        # 3. MixColumns (omitted in round 10)
        if r < 10:
            new_state = [0] * 16
            for c in range(4):
                col = state[4*c : 4*(c+1)]
                new_state[4*c + 0] = gf_mul(0x02, col[0]) ^ gf_mul(0x03, col[1]) ^ col[2] ^ col[3]
                new_state[4*c + 1] = col[0] ^ gf_mul(0x02, col[1]) ^ gf_mul(0x03, col[2]) ^ col[3]
                new_state[4*c + 2] = col[0] ^ col[1] ^ gf_mul(0x02, col[2]) ^ gf_mul(0x03, col[3])
                new_state[4*c + 3] = gf_mul(0x03, col[0]) ^ col[1] ^ col[2] ^ gf_mul(0x02, col[3])
            state = new_state
        # 4. Key Addition
        state = [state[i] ^ round_keys[r][i] for i in range(16)]
    return bytes(state)

def aes_decrypt_block(block: bytes, round_keys: list) -> bytes:
    """Giai ma 1 khoi 16 bytes bang AES-128"""
    state = [block[i] ^ round_keys[10][i] for i in range(16)]
    for r in range(9, -1, -1):
        # 1. InvShiftRows
        state = [
            state[0], state[13], state[10], state[7],
            state[4], state[1], state[14], state[11],
            state[8], state[5], state[2], state[15],
            state[12], state[9], state[6], state[3]
        ]
        # 2. InvByteSubstitution
        state = [AES_INV_SBOX[b] for b in state]
        # 3. Key Addition
        state = [state[i] ^ round_keys[r][i] for i in range(16)]
        # 4. InvMixColumns
        if r > 0:
            new_state = [0] * 16
            for c in range(4):
                col = state[4*c : 4*(c+1)]
                new_state[4*c + 0] = gf_mul(0x0E, col[0]) ^ gf_mul(0x0B, col[1]) ^ gf_mul(0x0D, col[2]) ^ gf_mul(0x09, col[3])
                new_state[4*c + 1] = gf_mul(0x09, col[0]) ^ gf_mul(0x0E, col[1]) ^ gf_mul(0x0B, col[2]) ^ gf_mul(0x0D, col[3])
                new_state[4*c + 2] = gf_mul(0x0D, col[0]) ^ gf_mul(0x09, col[1]) ^ gf_mul(0x0E, col[2]) ^ gf_mul(0x0B, col[3])
                new_state[4*c + 3] = gf_mul(0x0B, col[0]) ^ gf_mul(0x0D, col[1]) ^ gf_mul(0x09, col[2]) ^ gf_mul(0x0E, col[3])
            state = new_state
    return bytes(state)

def aes_cbc_encrypt(key: bytes, plaintext: bytes) -> str:
    """Ma hoa AES-128-CBC (Session 4 Slide 38-39): y_1 = e_k(x_1 ^ IV), y_i = e_k(x_i ^ y_{i-1})"""
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len] * pad_len)
    iv = os.urandom(16)
    round_keys = aes_key_expansion(key)
    
    ciphertext = b""
    prev_block = iv
    for i in range(0, len(padded), 16):
        block = padded[i : i+16]
        xored = bytes(a ^ b for a, b in zip(block, prev_block))
        enc_block = aes_encrypt_block(xored, round_keys)
        ciphertext += enc_block
        prev_block = enc_block
    return (iv + ciphertext).hex()

def aes_cbc_decrypt(key: bytes, hex_data: str) -> bytes:
    """Giai ma AES-128-CBC: x_1 = e_k^-1(y_1) ^ IV, x_i = e_k^-1(y_i) ^ y_{i-1}"""
    raw = bytes.fromhex(hex_data)
    iv, ciphertext = raw[:16], raw[16:]
    round_keys = aes_key_expansion(key)
    
    plaintext_padded = b""
    prev_block = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i : i+16]
        dec_block = aes_decrypt_block(block, round_keys)
        plaintext_padded += bytes(a ^ b for a, b in zip(dec_block, prev_block))
        prev_block = block
        
    pad_len = plaintext_padded[-1]
    if pad_len < 1 or pad_len > 16 or plaintext_padded[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid PKCS#7 padding (Ciphertext corrupted or wrong key)")
    return plaintext_padded[:-pad_len]

def derive_kek_from_password(password: str) -> bytes:
    """Dung SHA-1 (Session 7) bam mat khau va lay 16 bytes (128 bits) lam KEK"""
    return hashlib.sha1(password.encode("utf-8")).digest()[:16]

def compute_hmac_sha1(key: bytes, message: bytes) -> str:
    """Cai dat HMAC-SHA1 theo dung so do Slide 7 Session 8 (ipad = 0x36, opad = 0x5c)"""
    block_size = 64  # 512 bits block size cua SHA-1
    if len(key) > block_size:
        key = hashlib.sha1(key).digest()
    k_plus = key.ljust(block_size, b"\x00")
    
    s_i = bytes(b ^ 0x36 for b in k_plus)  # k+ XOR ipad
    s_o = bytes(b ^ 0x5C for b in k_plus)  # k+ XOR opad
    
    inner_hash = hashlib.sha1(s_i + message).digest()
    outer_hash = hashlib.sha1(s_o + inner_hash).hexdigest()
    return outer_hash


# ==============================================================================
# PART 2: KERBEROS SYSTEM ENTITIES (KDC, TRI, VU, THANH) - SESSION 8 SLIDE 16
# ==============================================================================

class KDCServer:
    def __init__(self):
        # Co so du lieu KEK (Key Encryption Key) cua KDC
        self.kek_db = {
            "Tri": derive_kek_from_password("tri_usth_secret_2026"),
            "Vu":  derive_kek_from_password("vu_usth_secret_2026")
        }

    def handle_request(self, id_T: str, id_V: str, r_T: int, lifetime_sec: int = 30):
        print(f"\n[KDC] Received RQST(ID_T='{id_T}', ID_V='{id_V}', r_T={r_T})")
        k_T = self.kek_db[id_T]
        k_V = self.kek_db[id_V]
        
        # Sinh khoa phien ngau nhien k_ses (128-bit) va thoi han T
        k_ses = os.urandom(16).hex()
        T = round(time.time() + lifetime_sec, 2)
        
        # Goi tin cho Tri: y_T = e_{k_T}(k_ses, r_T, T, ID_V)
        payload_T = json.dumps({"k_ses": k_ses, "r_T": r_T, "T": T, "ID_V": id_V}).encode()
        y_T = aes_cbc_encrypt(k_T, payload_T)
        
        # Goi tin Ticket cho Vu: y_V = e_{k_V}(k_ses, ID_T, T)
        payload_V = json.dumps({"k_ses": k_ses, "ID_T": id_T, "T": T}).encode()
        y_V = aes_cbc_encrypt(k_V, payload_V)
        
        print(f"[KDC] Generated session key k_ses = {k_ses} (Lifetime T = {lifetime_sec}s)")
        print(f"[KDC] -> Issued y_T (encrypted with k_T): {y_T[:48]}...")
        print(f"[KDC] -> Issued y_V (Ticket with k_V)   : {y_V[:48]}...")
        return y_T, y_V


class TriClient:
    def __init__(self):
        self.id = "Tri"
        self.k_T = derive_kek_from_password("tri_usth_secret_2026")
        self.last_nonce = None
        self.k_ses = None
        self.ticket_y_V = None

    def create_kdc_request(self, target_id: str):
        self.last_nonce = int.from_bytes(os.urandom(4), "big")
        print(f"\n[Tri] Generated Nonce r_T = {self.last_nonce} -> Sending RQST to KDC...")
        return self.id, target_id, self.last_nonce

    def process_kdc_response(self, y_T: str, y_V: str, expected_target: str):
        dec_bytes = aes_cbc_decrypt(self.k_T, y_T)
        data = json.loads(dec_bytes.decode())
        
        print(f"[Tri] Decrypted y_T -> r'_T={data['r_T']}, ID_V='{data['ID_V']}', T={data['T']}")
        if data["r_T"] != self.last_nonce:
            raise ValueError("[Tri ALERT] Nonce mismatch! Possible KDC replay attack!")
        if data["ID_V"] != expected_target:
            raise ValueError("[Tri ALERT] Target ID mismatch!")
        if time.time() > data["T"]:
            raise ValueError("[Tri ALERT] Session key lifetime T already expired!")
            
        print("[Tri] Verified r'_T == r_T, ID_V, and Lifetime T successfully!")
        self.k_ses = bytes.fromhex(data["k_ses"])
        self.ticket_y_V = y_V

    def send_secure_message(self, plaintext_msg: str):
        # Tao Timestamp T_S va goi xac thuc y_TV = e_{k_ses}(ID_T, T_S)
        T_S = round(time.time(), 2)
        auth_payload = json.dumps({"ID_T": self.id, "T_S": T_S}).encode()
        y_TV = aes_cbc_encrypt(self.k_ses, auth_payload)
        
        # Ma hoa ban tin x: y = e_{k_ses}(x) va tinh HMAC-SHA1
        y = aes_cbc_encrypt(self.k_ses, plaintext_msg.encode("utf-8"))
        mac = compute_hmac_sha1(self.k_ses, bytes.fromhex(y))
        
        print(f"[Tri -> Vu] Sending Authenticator y_TV (with T_S={T_S}), Ticket y_V, Ciphertext y, and HMAC:")
        print(f"            Ciphertext y = {y[:48]}...")
        print(f"            HMAC-SHA1 m  = {mac}")
        return {"y_TV": y_TV, "y_V": self.ticket_y_V, "y": y, "mac": mac}


class VuServer:
    def __init__(self, max_clock_skew: float = 5.0):
        self.id = "Vu"
        self.k_V = derive_kek_from_password("vu_usth_secret_2026")
        self.max_skew = max_clock_skew

    def receive_message(self, packet: dict):
        print("\n[Vu] Processing incoming packet...")
        try:
            # 1. Giai ma Ticket y_V bang khoa KEK k_V
            ticket_data = json.loads(aes_cbc_decrypt(self.k_V, packet["y_V"]).decode())
            k_ses = bytes.fromhex(ticket_data["k_ses"])
            id_T = ticket_data["ID_T"]
            T = ticket_data["T"]
            
            # 2. Giai ma Authenticator y_TV bang k_ses
            auth_data = json.loads(aes_cbc_decrypt(k_ses, packet["y_TV"]).decode())
            id_T_prime = auth_data["ID_T"]
            T_S = auth_data["T_S"]
            now = round(time.time(), 2)
            
            print(f"[Vu] Decrypted Ticket y_V     -> Sender ID_T='{id_T}', Lifetime T={T}")
            print(f"[Vu] Decrypted Auth y_TV      -> ID'_T='{id_T_prime}', Timestamp T_S={T_S} (Current time={now})")
            
            # 3. Kiem tra 3 dieu kien Kerberos (Session 8 Slide 16)
            if id_T_prime != id_T:
                print(f"[Vu REJECTED] Identity mismatch: ID'_T ({id_T_prime}) != ID_T ({id_T})!")
                return False
            if now > T:
                print(f"[Vu REJECTED] Session Key Lifetime Expired! (Current {now} > T {T})")
                return False
            delta = abs(now - T_S)
            if delta > self.max_skew:
                print(f"[Vu REJECTED - REPLAY ATTACK DETECTED] Timestamp T_S expired! Delta = {delta:.2f}s > allowed {self.max_skew}s")
                return False
                
            # 4. Kiem tra tinh toan ven ban ma bang HMAC-SHA1 (Session 8 Slide 3 & 7)
            computed_mac = compute_hmac_sha1(k_ses, bytes.fromhex(packet["y"]))
            if computed_mac != packet["mac"]:
                print(f"[Vu REJECTED - TAMPERING DETECTED] HMAC mismatch!\n     Expected: {packet['mac']}\n     Computed: {computed_mac}")
                return False
                
            # 5. Giai ma ban tin x
            plaintext = aes_cbc_decrypt(k_ses, packet["y"]).decode("utf-8")
            print(f"[Vu ACCEPTED] All checks passed! Decrypted message from {id_T}: \"{plaintext}\"")
            return True
            
        except Exception as e:
            print(f"[Vu REJECTED] Cryptographic error: {e}")
            return False


# ==============================================================================
# PART 3: EXPERIMENTAL SCENARIOS (NORMAL FLOW & THANH'S ATTACKS)
# ==============================================================================

def run_experiments():
    print("=" * 78)
    print("  EXPERIMENT 1: NORMAL KERBEROS AUTHENTICATION & SECURE MESSAGE (TRI -> VU)")
    print("=" * 78)
    kdc = KDCServer()
    tri = TriClient()
    vu = VuServer(max_clock_skew=5.0)
    
    # Buoc 1 & 2: Tri xin khoa phien tu KDC
    id_T, id_V, r_T = tri.create_kdc_request(target_id="Vu")
    y_T, y_V = kdc.handle_request(id_T, id_V, r_T, lifetime_sec=30)
    
    # Buoc 3 & 4: Tri xac thuc va gui tin nhan cho Vu
    tri.process_kdc_response(y_T, y_V, expected_target="Vu")
    captured_packet = tri.send_secure_message("Chao Vu, gui ban tai lieu matUSTH_2026!")
    vu.receive_message(captured_packet)

    # --------------------------------------------------------------------------
    print("\n" + "=" * 78)
    print("  EXPERIMENT 2: THANH PERFORMS A REPLAY ATTACK (AFTER 6 SECONDS)")
    print("=" * 78)
    print("[Thanh - Attacker] Intercepted packet (y_TV, y_V, y, mac) from network.")
    print("[Thanh - Attacker] Waiting 6 seconds before re-sending packet to Vu...")
    time.sleep(6.1)
    print("[Thanh -> Vu] Replaying captured packet to Vu...")
    vu.receive_message(captured_packet)

    # --------------------------------------------------------------------------
    print("\n" + "=" * 78)
    print("  EXPERIMENT 3: THANH PERFORMS CIPHERTEXT TAMPERING ATTACK (FLIPPING 1 BYTE)")
    print("=" * 78)
    fresh_packet = tri.send_secure_message("Chuyen khoan cho Vu 10,000,000 VND")
    
    # Thanh sua 1 byte trong ban ma y nhung khong co k_ses de tinh lai HMAC
    corrupted_y = bytearray.fromhex(fresh_packet["y"])
    corrupted_y[-1] ^= 0xFF  # Dao bit byte cuoi cung
    tampered_packet = dict(fresh_packet)
    tampered_packet["y"] = corrupted_y.hex()
    
    print("[Thanh - Attacker] Modified 1 byte of ciphertext y in transit and forwarded to Vu...")
    vu.receive_message(tampered_packet)

    # --------------------------------------------------------------------------
    print("\n" + "=" * 78)
    print("  EXPERIMENT 4: PERFORMANCE BENCHMARK (100 FULL KERBEROS HANDSHAKES)")
    print("=" * 78)
    t_start = time.perf_counter()
    for _ in range(100):
        _, _, r = tri.create_kdc_request("Vu") if False else ("Tri", "Vu", 123456)
        yt, yv = kdc.kek_db["Tri"], kdc.kek_db["Vu"]
        enc = aes_cbc_encrypt(yt, b'{"k_ses":"00112233445566778899aabbccddeeff","r_T":123456,"T":9999999999}')
        dec = aes_cbc_decrypt(yt, enc)
        mac = compute_hmac_sha1(yt, enc.encode())
    elapsed_ms = (time.perf_counter() - t_start) * 1000
    print(f"  - Total time for 100 AES-128-CBC + HMAC-SHA1 cycles : {elapsed_ms:.2f} ms")
    print(f"  - Average latency per cryptographic operation       : {elapsed_ms / 100:.3f} ms")
    print("=" * 78)

if __name__ == "__main__":
    run_experiments()