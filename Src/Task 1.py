import aes

ENCODING = "utf8"

key = "i like to party "[::-1]
encoded_key = aes.utils.bytes2int(bytes(key, ENCODING))
Cipher = aes.aes(encoded_key, 128, mode="ECB")

message = "I like to joggin"[::-1]
encoded_message = aes.utils.int2arr8bit(aes.utils.bytes2int(bytes(message, ENCODING)), 16)
ciphertext = Cipher.enc_once(encoded_message)
plaintext = Cipher.dec_once(ciphertext)

decoded_plaintext = "".join([chr(x) for x in plaintext])

print("-"*30 + " Output " + "-"*30)
print(f"Initialisation Vector: None")
print(f"Key String: {key[::-1]}")
print(f"Encoded Key: {aes.utils.int2arr8bit(encoded_key, 16)}")
print()
print(f"Message String: {message[::-1]}")
print(f"Encoded Message: {encoded_message}")
print(f"Ciphertext: {ciphertext}")
print()
print(f"Decrypted Plaintext: {plaintext}")
print(f"Decoded Plaintext: {decoded_plaintext}")
