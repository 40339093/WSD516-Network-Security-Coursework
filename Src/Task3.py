from fun_padding_oracle import fun_padding_oracle
from Task2 import CBC_AES
import json
import copy


def padded_attack(iv, ciphertext):
    g_array = [0 for i in range(len(ciphertext))]

    for byte in range(len(ciphertext)-1, -1, -1):
        padding = [0 for i in range(byte)]
        padding.extend([(16 - byte) for i in range(16 - byte)])
        Cdash1 = [iv[x] ^ padding[x] ^ g_array[x] for x in range(len(ciphertext))]

        for g in range(255, -1, -1):
            Cdash2 = copy.copy(Cdash1)
            Cdash2[byte] = Cdash1[byte] ^ g
            oracle = fun_padding_oracle(Cdash2, ciphertext, "B911959")
            if oracle:
                g_array[byte] = g
                # print(f"Byte: {byte}  Pad: {16-byte}  g: {g}  Oracle: {oracle}")
                break

    return g_array


if __name__ == "__main__":
    iv = CBC_AES.iv_generate("I have a secret ", "Many happy days ")
    ciphertext = [163, 12, 163, 152, 142, 134, 172, 157, 98, 105, 216, 76, 228, 127, 51, 157, 70, 133, 28, 176, 101, 155, 225, 176, 218, 248, 210, 27, 8, 50, 91, 136]
    print(f"Encrypted Data: {ciphertext}")
    print(f"Data is split into {len(ciphertext)/16} blocks")
    print(f"Initialisation Vector for c0: 0x{''.join([ '%02x' % x for x in iv])}")
    blocks = [[ciphertext[i+j] for j in range(16)] for i in range(0, len(ciphertext)-1, 16)]
    plaintext = []
    for index, block in enumerate(blocks):
        if index == 0:
            plaintext.append(padded_attack(iv, block))
        else:
            plaintext.append(padded_attack(blocks[index - 1], block))

    plaintext_str = "".join([chr(x) for x in sum(plaintext, [])])
    plaintext_str = plaintext_str.strip(plaintext_str[-1])
    print(f"Decrypted Message: {plaintext_str}")
    print(f"Padding: {plaintext[-1][-1]}")
