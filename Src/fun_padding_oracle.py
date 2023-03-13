import aes


def fun_padding_oracle(iv, ciphertext, student_id):
    """
    Custom Python implementation of the fun_padding_oracle function that was initially provided as
    an encrypted matlab file. Extra care has been taken to keep the parameters and return values identical
    to those of the original function.

    :param iv: The Initialisation Vector or previous ciphertext block to use for decryption as 8-bit integer array
    :param ciphertext: The block of ciphertext being cracked as 8-bit integer array
    :param student_id: Student ID value to be used as part of the encryption key as string
    :return: True if the padding of the decrypted block is valid
    """

    # Formatting of the key and instatiation of the AES Object
    key = f"Me ID is {student_id}"
    encoded_key = aes.utils.bytes2int(bytes(key[::-1], "utf8"))
    cipher = aes.aes(encoded_key, 128, mode="ECB")

    # Splitting passed ciphertext into 128-bit blocks
    blocks = [[ciphertext[i + j] for j in range(16)] for i in range(0, len(ciphertext) - 1, 16)]
    plaintext_array = []

    # Iterates through the array of ciphertext blocks from last to 1st
    for index, block in reversed(list(enumerate(blocks))):
        # Decrypts the current block
        decrypted = cipher.dec_once(block)
        xored_block = []

        # If block 0, XOR against the IV value
        if index == 0:
            for x in range(16):
                xored_block.append(decrypted[x] ^ iv[x])
        # Other blocks XOR against the previous block
        else:
            for x in range(16):
                xored_block.append(decrypted[x] ^ blocks[index - 1][x])
        plaintext_array.append(xored_block)

    # Pad value and count is extracted from the decrypted array
    pad_val = plaintext_array[0][-1]
    pads = plaintext_array[0].count(pad_val)

    # Returns the boolean evaluation of the padding value being equivalent to
    # the number of times it occurs within the block as is expected when using
    # the PKCS7 padding standard
    return pads == pad_val

# Lambda function to return "SUCCESS" if values x and y are the same,
# otherwise FAILED for use within the validation tests in the boilerplate
success = lambda x, y: "SUCCESS" if x == y else "FAILED"


if __name__ == "__main__":
    """
    Boilerplate Validation tests to ensure the correct functionality 
    of the oracle function
    The test cases chosen to run are:
        1. A single block with padding up to 16-bytes
            Expected Value True
        2. Block made up of 16 characters, resulting in a complete padding block
            Expected Value True
        3. Passing only the 1st block from the previous test containing no padding
            Expected Value False
        4. Message has 4 padded bytes of value 7
            Expected Value False
    """

    # For the encryption of test cases, the object developed in Task 2 was used
    from Task2 import CBC_AES

    # Initialisation of Validation key, IV and cipher object
    student_ID = "B911959"
    key = f"Me ID is {student_ID}"
    iv = CBC_AES.iv_generate("I have a secret ", "Many happy days ")
    validation = CBC_AES(key, iv, False)

    # TEST CASE 1 - Valid Padding at the end of the block
    print("\n" + "-"*40 + " TEST CASE 1 " + "-"*40)
    print("Text fewer than 16 bytes, padded by encryption")
    message = "Test1"
    print(f"Message: {message}")
    ciphertext = validation.cbc_encrypt(message)
    print(f"Ciphertext Array: {ciphertext}")
    print(f"Ciphertext: 0x{''.join([ '%02x' % x for x in ciphertext])}")
    oracle = fun_padding_oracle(iv, ciphertext, student_ID)
    print(f"Oracle Output: {oracle}")
    print(f"Expected Output: {True}")
    print(f"Successful Test: {success(oracle, True)}")

    # TEST CASE 2 - 16 byte block of padding appended to plaintext
    print("\n" + "-" * 40 + " TEST CASE 2 " + "-" * 40)
    print("Text is 16 bytes. A full block of 16 padded bytes is appended to the end")
    message = "Test2 is complet"
    print(f"Message: {message}")
    ciphertext = validation.cbc_encrypt(message)
    print(f"Ciphertext: 0x{''.join(['%02x' % x for x in ciphertext])}")
    oracle = fun_padding_oracle(iv, ciphertext, student_ID)
    print(f"Oracle Output: {oracle}")
    print(f"Expected Output: {True}")
    print(f"Successful Test: {success(oracle, True)}")

    # TEST CASE 3 - Passing first block from previous test
    print("\n" + "-" * 40 + " TEST CASE 3 " + "-" * 40)
    print("Only the 1st ciphertext block from Test 2 is used, containing no padding")
    blocks = [[ciphertext[i+j] for j in range(16)] for i in range(0, len(ciphertext)-1, 16)]
    print(f"Oracle Block: 0x{''.join(['%02x' % x for x in blocks[0]])}")
    oracle = fun_padding_oracle(iv, blocks[0], student_ID)
    print(f"Oracle Output: {oracle}")
    print(f"Expected Output: {False}")
    print(f"Successful Test: {success(oracle, False)}")

    # TEST CASE 4 - Invalid Padding
    print("\n" + "-" * 40 + " TEST CASE 4 " + "-" * 40)
    print("Message contains 4 padded bytes with value 7")
    data = "Hello World!"
    message = aes.utils.int2arr8bit(aes.utils.bytes2int(bytes(data[::-1], "utf8")), len(data))
    message.extend([7 for i in range(16 - len(data))])
    xored_data = []
    for x in range(16):
        xored_data.append(message[x] ^ iv[x])
    ciphertext = aes.aes(aes.utils.bytes2int(bytes(key[::-1], "utf8")), 128, mode="ECB").enc_once(xored_data)
    print(f"Message: {message}")
    print(f"Ciphertext: 0x{''.join(['%02x' % x for x in ciphertext])}")
    oracle = fun_padding_oracle(iv, ciphertext, student_ID)
    print(f"Oracle Output: {oracle}")
    print(f"Expected Output: {False}")
    print(f"Successful Test: {success(oracle, False)}")



