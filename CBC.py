from CryptoModules.Serpent.Serpent import Serpent
from CryptoModules.Serpent.bit_operations import string_xor
from CryptoModules.Serpent.serpent_utils import xor_two_strings

BLOCK_BYTES = 16
# IV = chr(0) * BLOCK_BYTES


def CBC_strip(msg):
    last = ord(msg[-1])
    return msg[0:(len(msg) - last)]


def CBC_pad(msg):
    pad_size = BLOCK_BYTES - len(msg) % BLOCK_BYTES
    return msg + chr(pad_size) * pad_size


def CBC_encrypt(plain_text, key, encryption_func = Serpent.encrypt ):

    cipher_text = ''
    current_cipher_block = chr(0) * BLOCK_BYTES
    plain_text = CBC_pad(plain_text)
    for i in range(int(len(plain_text) / BLOCK_BYTES)):
        plain_text_block = plain_text[i*BLOCK_BYTES:(i+1)*BLOCK_BYTES]
        current_cipher_block = encryption_func(xor_two_strings(current_cipher_block, plain_text_block), key)
        cipher_text += current_cipher_block

    return cipher_text


def CBC_decrypt(cipher_text, key, decryption_func = Serpent.decrypt):
    plain_text = ''
    prev_cipher_block = chr(0) * BLOCK_BYTES

    for i in range(int(len(cipher_text) / BLOCK_BYTES)):
        cipher_text_block = cipher_text[i * BLOCK_BYTES:(i + 1) * BLOCK_BYTES]
        current_plain_block = xor_two_strings(decryption_func(cipher_text_block,key), prev_cipher_block)
        prev_cipher_block = cipher_text_block
        plain_text += current_plain_block

    plain_text = CBC_strip(plain_text)
    return plain_text

#
# text = "qwertyuiopasdfghjkl;"
# key = "s674hn456ghggdfg"
#
# # enc = encrypt(text, key)
# # print(enc)
# # print(decrypt(enc, key))
#
#
# enc = CBC_encrypt(encrypt, text, key)
# # print(enc)
# res = CBC_decrypt(decrypt, enc, key)
# print(res)
