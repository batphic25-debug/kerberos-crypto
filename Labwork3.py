
# LABWORK 3 - INTRODUCTION TO CRYPTOGRAPHY

def str_to_int(text: str) -> int:
    """Chuyển đổi chuỗi ASCII sang số nguyên (Big-endian)"""
    return int.from_bytes(text.encode('ascii'), byteorder='big')

def int_to_str(number: int) -> str:
    """Chuyển đổi số nguyên sang chuỗi ASCII (Big-endian)"""
    byte_length = (number.bit_length() + 7) // 8
    return number.to_bytes(byte_length, byteorder='big').decode('ascii')


# --- EXERCISE 1 ---
msg_ex1 = "flow"
int_ex1 = str_to_int(msg_ex1)
print("#EXERCISE 1")
print(f"Message: '{msg_ex1}' -> Integer: {int_ex1}\n")


# --- EXERCISE 2 ---
int_ex2 = 14445
msg_ex2 = int_to_str(int_ex2)
print("#EXERCISE 2")
print(f"Integer: {int_ex2} -> Message: '{msg_ex2}'\n")


# --- EXERCISE 3 ---
def rsa_system(p: int, q: int, e: int = None, d: int = None, M: int = None, C: int = None):
    N = p * q
    phi = (p - 1) * (q - 1)
    
    # Tìm khóa còn thiếu bằng nghịch đảo modulo: e * d = 1 mod phi(N)
    if e is not None and d is None:
        d = pow(e, -1, phi)
    elif d is not None and e is None:
        e = pow(d, -1, phi)
        
    pub_key = (N, e)
    priv_key = d
    
    # Mã hóa hoặc giải mã bằng Repeated Squaring: pow(base, exp, mod)
    if M is not None:
        C = pow(M, e, N)
    elif C is not None:
        M = pow(C, d, N)
        
    return pub_key, priv_key, M, C

print("#EXERCISE 3")
# Case 1: p = 251, q = 191, e = 65537, M = 26729
pub1, priv1, M1, C1 = rsa_system(p=251, q=191, e=65537, M=26729)
print(f"1. Public Key (N, e) = {pub1}, Private Key d = {priv1}")
print(f"   Plaintext M = {M1} -> Ciphertext C = {C1}")

# Case 2: p = 233, q = 151, d = 9473, C = 29600
pub2, priv2, M2, C2 = rsa_system(p=233, q=151, d=9473, C=29600)
print(f"2. Public Key (N, e) = {pub2}, Private Key d = {priv2}")
print(f"   Ciphertext C = {C2} -> Plaintext M = {M2}\n")


# --- EXERCISE 4 ---
print("#EXERCISE 4")
p4, q4, e4 = 81401, 27109, 65537
C4 = 412589464

pub4, priv4, M4, _ = rsa_system(p=p4, q=q4, e=e4, C=C4)
plaintext_str = int_to_str(M4)

print(f"Public Key (N, e) = {pub4}")
print(f"Private Key d     = {priv4}")
print(f"Decrypted Int M   = {M4}")
print(f"Plaintext String  = '{plaintext_str}'")