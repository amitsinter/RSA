import random

from CryptoModules.Serpent.Constants import ROUNDS
from CryptoModules.Serpent.serpent_utils import string_to_bitstring, decryption_round, encryption_round, \
    final_permutation, bitstring_to_string, initial_permutation, generate_round_keys


class Serpent:

    @staticmethod
    def encrypt(text, key):
        '''

        :param text: string of chars, should be 16 chars (128 bit block)
        :param key:  string of chars, should be less or equal to 32 chars (256 bits)
        :return: cipher string of chars
        '''

        # Convert key and text to bit array
        bit_key = string_to_bitstring(key)
        bit_text = string_to_bitstring(text)

        # Sanity checks
        assert len(bit_text) == 128, 'Encryption ERROR!\nThe text block size must be 128 bits long!'
        assert (len(bit_key) > 1 and len(
            bit_key) <= 256), 'Encryption ERROR!\nThe key size must be less or equal to 256 bits!'

        # Key padding
        if (len(bit_key) < 256):
            bit_key += '1'
        bit_key += '0' * (256 - len(bit_key))

        # Create sub keys of the algorithm
        round_keys = generate_round_keys(bit_key)

        BHat_i = initial_permutation(bit_text)

        for i in range(ROUNDS):
            BHat_i = encryption_round(i, BHat_i, round_keys)

        cipher = final_permutation(BHat_i)

        return bitstring_to_string(cipher)
        # return cipher

    @staticmethod
    def decrypt(cipher, key):
        bit_key = string_to_bitstring(key)
        bit_cipher = string_to_bitstring(cipher)

        # Key padding
        if len(bit_key) < 256:
            bit_key += '1'
        bit_key += '0' * (256 - len(bit_key))

        # Create sub keys of the algorithm
        round_keys = generate_round_keys(bit_key)

        BHatiPlus1 = initial_permutation(bit_cipher)

        for i in range(ROUNDS - 1, -1, -1):
            BHatiPlus1 = decryption_round(i, BHatiPlus1, round_keys)
        plaintext = final_permutation(BHatiPlus1)

        # plaintext = ''.join([chr(int(plaintext[i:i + 8], 2)) for i in range(0, len(plaintext), 8)])
        return bitstring_to_string(plaintext)

    def test(self):
        print("Encryption:")
        text = "ravivravivraviv1"
        key = "sdfg"
        print(text)
        e = self.encrypt(text, key)
        for c in e:
            print(str(hex(ord(c))), end=' ')

        print("\n\nDecryption:")

        d = self.decrypt(e, key)
        print(d)
        for c in d:
            print(str(hex(ord(c))), end=' ')

    @staticmethod
    def generate_key():
        key = ''
        for i in range(32):
            key += chr(random.randint(0, 255))
        return key


if __name__ == '__main__':
    serpent = Serpent()
    serpent.test()
