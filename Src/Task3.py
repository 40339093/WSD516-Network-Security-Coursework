from fun_padding_oracle import fun_padding_oracle
from Task2 import CBC_AES
import copy
import json


crack = lambda x, y, z: x ^ y ^ z


def padded_attack(ciphertext):
    blocks = [[ciphertext[i + j] for j in range(16)] for i in range(0, len(ciphertext) - 1, 16)]
    Pguess_array = []
    X_array = []

    for index, block in reversed(list(enumerate(blocks))):
        if index == 0:
            break
        prev_block = blocks[index - 1]
        # This is Pguess
        Pguess = [0 for i in range(len(block))]
        X = [0 for i in range(len(block))]
        for byte in range(len(block) - 1, -1, -1):
            padding = [0 for i in range(byte)]
            padding.extend([(16 - byte) for i in range(16 - byte)])
            for x in range(255, -1, -1):
                # Value of x also needs to be stored
                Pguess[byte] = crack((16-byte), prev_block[byte], x)
                X[byte] = x
                if fun_padding_oracle(padding, block, "B911959"):
                    print(f"Byte {byte}:   X: {x}   Padding: {16-byte}")
                    break
        Pguess_array.append(Pguess)
        X_array.append(X)
    return {
        "Pguess": Pguess_array,
        "X": X_array
    }

if __name__ == "__main__":
    iv = CBC_AES.iv_generate("I have a secret ", "Many happy days ")
    ciphertext = [215, 111, 91, 253, 156, 68, 68, 10, 120, 235, 241, 47, 48, 18, 150, 145]
    encrypted_data = copy.copy(iv)
    encrypted_data.extend(ciphertext)
    cracked = padded_attack(encrypted_data)

    print(json.dumps(cracked, indent=2))

    # plaintext = [0 for i in range(len(ciphertext))]
    # for byte in ciphertext:
    #     plaintext[byte] = crack(cracked[byte], iv[byte], )
    #
    # pass
