"""
###########################################################
# Developer: Arun Goyal (B911959)                         #
#                                                         #
# Filename: Task3.py                                      #
# Description: Implementation of the Padded Oracle Attack #
#     and decryption of the encrypted string provided in  #
#     the brief.                                          #
#                                                         #
# Runtime on Intel i7-7700HQ w/ 16GB RAM:  2670.75 ms     #
#                                                         #
# Dependencies: copy, time, fun_padding_oracle, Task2     #
###########################################################
"""

from fun_padding_oracle import fun_padding_oracle
from Task2 import CBC_AES
import copy


def padded_attack(iv, ciphertext):
    """
    Function to conduct the padded oracle attack on the provided data
    :param iv: Initialisation Vector or previous block of ciphertext as array of 8-bit integers
    :param ciphertext: Ciphertext block to be attacked as array of 8-bit integers
    :return: Cracked data as array of 8-bit integers
    """
    # Array of 0's created to store output
    g_array = [0 for i in range(len(ciphertext))]

    # Iterating through the ciphertext block from last byte to 1st
    for byte in range(len(ciphertext)-1, -1, -1):
        # Creates an array of padding values for the byte being cracked
        padding = [0 for i in range(byte)]
        padding.extend([(16 - byte) for i in range(16 - byte)])

        # Ciphertext block is XORed against the padding value and previously calculated plaintext values
        # This operation is done to minimise the number of XOR operations that occur within the loop
        # that iterates through the byte values for g
        Cdash1 = [iv[x] ^ padding[x] ^ g_array[x] for x in range(len(ciphertext))]

        # Values of g that make up the guessed value of the plaintext byte
        for g in range(255, -1, -1):
            # Creates a copy of the intermediary Cdash value to XOR against the guessed value
            Cdash2 = copy.copy(Cdash1)
            Cdash2[byte] = Cdash1[byte] ^ g

            # New block using the current value for g passed to the oracle function
            oracle = fun_padding_oracle(Cdash2, ciphertext, "B911959")

            # If the oracle returns true, the value for g is added to g_array and the
            # loop is broken out of to crack the next byte
            if oracle:
                g_array[byte] = g
                break

    return g_array


if __name__ == "__main__":
    # Execution Timer Start
    import time
    start = time.time()

    # Initialsiation of Attack Variables
    iv = CBC_AES.iv_generate("I have a secret ", "Many happy days ")
    # The ciphertext array was taken from the B911959.mat file provided
    ciphertext = [163, 12, 163, 152, 142, 134, 172, 157, 98, 105, 216, 76, 228, 127, 51, 157, 70, 133, 28, 176, 101, 155, 225, 176, 218, 248, 210, 27, 8, 50, 91, 136]

    # Output of initialisation to stdout
    print(f"Encrypted Data: {ciphertext}")
    print(f"Data is split into {len(ciphertext)/16} blocks")
    print(f"Initialisation Vector for c0: 0x{''.join([ '%02x' % x for x in iv])}")

    # Ciphertext array split into 128-bit blocks
    blocks = [[ciphertext[i+j] for j in range(16)] for i in range(0, len(ciphertext)-1, 16)]
    plaintext = []

    # Iterate through each of the ciphertext blocks, passing them 1 at a time to the padded_attack function
    for index, block in enumerate(blocks):
        if index == 0:
            plaintext.append(padded_attack(iv, block))
        else:
            plaintext.append(padded_attack(blocks[index - 1], block))

    # Flattening of output data to a 1 dimensional string instead of 2D array
    plaintext_str = "".join([chr(x) for x in sum(plaintext, [])])
    # Removal of radding from the end of the string
    plaintext_str = plaintext_str.strip(plaintext_str[-1])

    # Output of decrypted string and identified padding to stdout for verification
    print(f"Decrypted Message: {plaintext_str}")
    print(f"Padding: {plaintext[-1][-1]}")

    # End of timings
    end = time.time()
    runtime = end - start
    print(f"\nTotal Execution Time: {runtime*1000}ms")
