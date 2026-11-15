#Ex1
a = 123
b = 543
bin_a = bin(a)[2:]
xor_ab = a ^ b
bin_xor_ab = bin(xor_ab)[2:]

print("=== EXERCISE 1 ===")
print(f"1. Binary form of a ({a}): {bin_a}")
print(f"2. a XOR b in binary: {bin_xor_ab}")
print(f"   a XOR b in decimal: {xor_ab}\n")

#Ex2
A = [105, 110, 116, 114, 111, 50, 99, 114, 121, 112, 116, 111, 123, 119, 51,
108, 99, 48, 109, 51, 95, 116, 48, 95, 106, 48, 117, 114, 110, 51, 121, 125]

msg_ex2 = ''.join([chr(i) for i in A])
print("=== EXERCISE 2 ===")
print(f"The message is: {msg_ex2}\n")

#Ex3

B = [99, 100, 126, 120, 101, 56, 105, 120, 115, 122, 126, 101, 113, 59, 121,
126, 57, 122, 85, 58, 100, 85, 96, 58, 127, 120, 100, 57, 115, 119]
k = 10
msg_ex3 = ''.join([chr(c ^ k) for c in B])
print("=== EXERCISE 3 ===")
print(f"The message is: {msg_ex3}\n")

#Ex4



