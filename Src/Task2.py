import aes


class CBC_AES:
    def __init__(self, key, iv=None, verbose=False):
        self.encoding = "utf8"
        self.verbose = verbose
        self.key = aes.utils.bytes2int(bytes(key[::-1], self.encoding))
        if iv is None:
            self.iv = 0x00000000000000000000000000000000
        else:
            self.iv = iv

        self.cipher = aes.aes(self.key, 128, mode="ECB")

        if self.verbose:
            print("\n" + "-"*30 + " Initial Variables " + "-"*30)
            print(f"Initialisation Vector: 0x{''.join([ '%02x' % x for x in self.iv])}")
            print(f"Master Key: {self.key:#x}")

    @staticmethod
    def iv_generate(key, data):
        nonce_key = aes.utils.bytes2int(bytes(key[::-1], "utf8"))
        nonce = aes.utils.int2arr8bit(aes.utils.bytes2int(bytes(data[::-1], "utf8")), 16)
        iv_cipher = aes.aes(nonce_key, 128, mode="ECB")
        return iv_cipher.enc_once(nonce)

    def cbc_encrypt(self, data):

        encoded_data = aes.utils.int2arr8bit(aes.utils.bytes2int(bytes(data[::-1], self.encoding)), len(data))
        pads = 16 - (len(encoded_data) % 16)
        if pads != 0:
            encoded_data.extend([pads for i in range(pads)])
        else:
            encoded_data.extend([16 for i in range(16)])

        blocks = [[encoded_data[i+j] for j in range(16)] for i in range(0, len(encoded_data)-1, 16)]
        ciphertext = []

        for index, block in enumerate(blocks):
            xored_block = []
            if index == 0:
                for x in range(16):
                    xored_block.append(block[x] ^ self.iv[x])
            else:
                for x in range(16):
                    xored_block.append(block[x] ^ ciphertext[index-1][x])
            ciphertext.append(self.cipher.enc_once(xored_block))
        complete_ciphertext = sum(ciphertext, [])

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
        blocks = [[data[i + j] for j in range(16)] for i in range(0, len(data) - 1, 16)]
        plaintext_array = []

        for index, block in reversed(list(enumerate(blocks))):
            decrypted = self.cipher.dec_once(block)
            xored_block = []
            if index == 0:
                for x in range(16):
                    xored_block.append(decrypted[x] ^ self.iv[x])
            else:
                for x in range(16):
                    xored_block.append(decrypted[x] ^ blocks[index - 1][x])
            plaintext_array.append(xored_block)
        plaintext_str = "".join([chr(x) for x in sum(reversed(plaintext_array), [])])
        pad_value = plaintext_array[0][15]
        pads = plaintext_array[0].count(pad_value)
        plaintext = plaintext_str.strip(plaintext_str[-1])

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

    key = "She is beautiful"
    iv_nonce = "Many happy days "
    iv_key = "I have a secret "
    message = "This is a message to you from Bob"

    # https://gchq.github.io/CyberChef/#recipe=AES_Encrypt(%7B'option':'Hex','string':'69%2020%206c%2069%206b%2065%2020%2074%206f%2020%2070%2061%2072%2074%2079%2020'%7D,%7B'option':'Hex','string':'64%2049%2068%2068%203b%208a%207e%2059%200c%20a1%2060%2018%20b7%207f%2085%20d1'%7D,'CBC','Raw','Hex',%7B'option':'Hex','string':''%7D)From_Hex('Auto')To_Decimal('Space',false)&input=VGVzdCBkYXRhIHNob3dpbmcgbW9yZSB0aGFuIDEgYmxvY2sgdG8gYmUgZW5jb2RlZCBieSBtZQ

    cipher = CBC_AES(key, CBC_AES.iv_generate(iv_key, iv_nonce), True)
    ciphertext = cipher.cbc_encrypt(message)
    plaintext = cipher.cbc_decrypt(ciphertext)
