"""
###########################################################
# Developer: Arun Goyal (B911959)                         #
#                                                         #
# Filename: Task2.py                                      #
# Description: Implementation of CBC wrapper for the AES  #
#     library that was validated in Task 1. Additional    #
#     testing and validation within the boilerplate to    #
#     ensure that encrypted values are correct.           #
#                                                         #
# Dependencies: aes                                       #
###########################################################
"""

import aes


class CBC_AES:
    """
    Custom wrapper class to implement CBC encryption around the AES library that was validated in Task 1
    """
    def __init__(self, key, iv=None, verbose=False):
        """
        CBC Class Initialiser
        Stores the encryption key and initialisation vector as well as creating the ECB Cipher object

        :param key: The encryption key to use, passed as a 128-bit integer
        :param iv: The Initialisation Vector for the 1st block of CBC passed as an array of 8-bit integers
        :param verbose: Bool flag to enable Verbose output to stdout (Default: False)
        """

        # Encoding for strings set to UTF-8
        self.encoding = "utf8"
        self.verbose = verbose

        # Formatting of Key integer
        self.key = aes.utils.bytes2int(bytes(key[::-1], self.encoding))

        # IV set to all 0 if no IV provided at initialisation
        if iv is None:
            self.iv = 0x00000000000000000000000000000000
        else:
            self.iv = iv

        # Instantiation of imported AES object in ECB mode
        self.cipher = aes.aes(self.key, 128, mode="ECB")

        # Output of Initialisation values when Verbose is True
        if self.verbose:
            print("\n" + "-"*30 + " Initial Variables " + "-"*30)
            print(f"Initialisation Vector: 0x{''.join([ '%02x' % x for x in self.iv])}")
            print(f"Master Key: {self.key:#x}")

    @staticmethod
    def iv_generate(key, data):
        """
        Generates the Initialisation Vector

        :param key: Key to encrypt the initialisation vector with as a 128-bit integer
        :param data: Nonce to be encrypted as a string
        :return: 16 byte array of 8-bit integers
        """

        # Formatting of Nonce Key and Nonce to be encrypted
        nonce_key = aes.utils.bytes2int(bytes(key[::-1], "utf8"))
        nonce = aes.utils.int2arr8bit(aes.utils.bytes2int(bytes(data[::-1], "utf8")), 16)

        # Encryption of Nonce to provide IV
        iv_cipher = aes.aes(nonce_key, 128, mode="ECB")
        return iv_cipher.enc_once(nonce)

    def cbc_encrypt(self, data):
        """
        Encrypts the data passed to it using the cipher's attributes

        :param data: The data to be encrypted as a string
        :return: Encrypted ciphertext as an array of 8-bit integers
        """

        # Formatting of ciphertext from string to 8-bit integer array
        encoded_data = aes.utils.int2arr8bit(aes.utils.bytes2int(bytes(data[::-1], self.encoding)), len(data))

        # Addition of padding at the end of the plaintext array
        pads = 16 - (len(encoded_data) % 16)
        if pads != 0:
            encoded_data.extend([pads for i in range(pads)])
        else:
            encoded_data.extend([16 for i in range(16)])

        # Splitting plaintext into 128-bit blocks
        blocks = [[encoded_data[i+j] for j in range(16)] for i in range(0, len(encoded_data)-1, 16)]
        ciphertext = []

        # Iterating through the blocks in the ciphertext
        # Enumerate allows the blocks index to also be used
        for index, block in enumerate(blocks):
            xored_block = []

            # IV value XORed for Block 0
            if index == 0:
                for x in range(16):
                    xored_block.append(block[x] ^ self.iv[x])
            # Previosu block used for all other blocks
            else:
                for x in range(16):
                    xored_block.append(block[x] ^ ciphertext[index-1][x])

            # Encryption of XORed block of data
            ciphertext.append(self.cipher.enc_once(xored_block))
        # Flattening of 2D array of ciphertext blocks into a single 1D array
        complete_ciphertext = sum(ciphertext, [])

        # Output of Encryption values and stages when Verbose is True
        if self.verbose:
            print("\n" + "-" * 30 + " Encrypt Values " + "-" * 30)
            print(f"Plaintext Message: {data}")
            print(f"No. of Required Padding Bytes: {pads}")
            print(f"Pad Value Used: {pads}")
            print(f"Encoded Data: {encoded_data}")
            print(f"Ciphertext: {complete_ciphertext}")
            print(f"Ciphertext (formatted): 0x{''.join([ '%02x' % x for x in complete_ciphertext])}")

        return complete_ciphertext

    def cbc_decrypt(self, data):
        """
        Decrypts the passed ciphertext, returning a string

        :param data: ciphertext as an array of 8-bit integers
        :return: plaintext as string
        """

        # Ciphertext is split into 128-bit blocks
        blocks = [[data[i + j] for j in range(16)] for i in range(0, len(data) - 1, 16)]
        plaintext_array = []

        # Iterate through each of the ciphertext blocks from last to 1st
        for index, block in reversed(list(enumerate(blocks))):
            # Block is decrypted
            decrypted = self.cipher.dec_once(block)
            xored_block = []

            # If block 0, XOR against IV
            if index == 0:
                for x in range(16):
                    xored_block.append(decrypted[x] ^ self.iv[x])
            # Other blocks XORed against previous block
            else:
                for x in range(16):
                    xored_block.append(decrypted[x] ^ blocks[index - 1][x])
            plaintext_array.append(xored_block)

        # Decrypted plaintext array converted to string
        plaintext_str = "".join([chr(x) for x in sum(reversed(plaintext_array), [])])

        # Identification and removal of padding from the end of the string
        pad_value = plaintext_array[0][15]
        pads = plaintext_array[0].count(pad_value)
        plaintext = plaintext_str.strip(plaintext_str[-1])

        # Output of Decryption values and stages when Verbose is True
        if self.verbose:
            print("\n" + "-" * 30 + " Decrypt Values " + "-" * 30)
            print(f"Ciphertext: {data}")
            print(f"Ciphertext (formatted): 0x{''.join([ '%02x' % x for x in data])}")
            print(f"Decrypted Data: {sum(reversed(plaintext_array), [])}")
            print(f"Identified Pad: {pad_value}")
            print(f"Padded Bytes: {pads}")
            print(f"Padding Valid: {pads == pad_value}")
            print(f"Plaintext: {plaintext}")

        return plaintext


if __name__ == "__main__":

    # Declaration of variables used to validate encryption
    key = "She is beautiful"
    iv_nonce = "Many happy days "
    iv_key = "I have a secret "
    message = "This is a message to you from Bob"

    # Initialisation of CBC_AES Object
    cipher = CBC_AES(key, CBC_AES.iv_generate(iv_key, iv_nonce), True)
    # Encryption of plaintext message
    ciphertext = cipher.cbc_encrypt(message)
    # Decryption of ciphertext
    plaintext = cipher.cbc_decrypt(ciphertext)
