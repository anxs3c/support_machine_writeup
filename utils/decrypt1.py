import base64

enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
key = "armando"
enc_bytes = base64.b64decode(enc_password)
decrypted = []

for i in range(len(enc_bytes)):
    decrypted_char = enc_bytes[i] ^ ord(key[i % len(key)]) ^ 223
    decrypted.append(decrypted_char)
    
password = bytes(decrypted).decode('utf-8')
print(f"Decrypted Password: {password}")
