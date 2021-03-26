from CryptoModules.Serpent.Constants import LTInverseTable, FPtable, IPtable, LTtable, ROUNDS, PHI, SBOXES_NUM, SBoxDecimalTable
from CryptoModules.Serpent.bit_operations import rotate_string_left, string_multiple_xor, string_xor, num_to_bitstring


def string_to_bitstring(s):
    bs = ''
    for c in s:
        bs += '{:08b}'.format(ord(c))[::-1]
    return bs

def xor_two_strings(s1, s2):
    bit_str1 = string_to_bitstring(s1)
    bit_str2 = string_to_bitstring(s2)
    res = string_xor(bit_str1, bit_str2)
    return bitstring_to_string(res)

def bitstring_to_string(bs):
    s = ''
    for i in range(int(len(bs) / 8)):
        bit_char = bs[i * 8:(i + 1) * 8]
        bit_char = bit_char[::-1]
        s += chr(int(bit_char, 2))
    return s


def decryption_round(round_index, transformed, KHat):
    if 0 <= round_index <= ROUNDS - 2:
        to_s_box = inverse_linear_transformation(transformed)
    elif round_index == ROUNDS - 1:
        to_s_box = string_xor(transformed, KHat[ROUNDS])
    else:
        raise ValueError(f'Invalid round number {round_index}')

    to_xor = ''.join([sbox_inverse_func(round_index, to_s_box[ind:ind + 4]) for ind in range(0, len(to_s_box), 4)])
    output = string_xor(to_xor, KHat[round_index])
    return output


def inverse_linear_transformation(inp):
    assert len(inp) == 128, 'input to inverse linear transf. is not 128 bits'

    res = ''
    for array in LTInverseTable:
        out = '0'
        for array_element in array:
            out = string_xor(out, inp[array_element])
        res += out
    return res


def encryption_round(round_index, round_input, KHat):
    # First we xor the round input with the key
    input_xor_key = string_xor(round_input, KHat[round_index])
    # Then we apply the Sbox function on the result
    sbox_res = ''.join([sbox_func(round_index, input_xor_key[index:index + 4])
                        for index in range(0, len(input_xor_key), 4)])

    # If it is round 0 to 30 we apply the linear transformation
    # Otherwise we do bitwise xor between the sbox_res and the last key
    if 0 <= round_index <= ROUNDS - 2:
        round_output = linear_transformation(sbox_res)
    elif round_index == ROUNDS - 1:
        round_output = string_xor(sbox_res, KHat[ROUNDS])
    else:
        raise ValueError(f'round number {round_index} out of range')
    return round_output


def linear_transformation(inp):
    assert len(inp) == 128, 'input to linear transf. is not 128 bits'
    res = ''
    for array in LTtable:
        out = '0'
        for e in array:
            out = string_xor(out, inp[e])
        res += out
    return res


def generate_round_keys(bit_key):
    # W is a dictionary where the key is the index of the prekey and it holds the corrspending value
    # W_-8 ,... W_-1 are simply the key split into 8 words of 32 bit
    w = {}
    for i in range(-8, 0):
        w[i] = bit_key[(i + 8) * 32: (i + 9) * 32]

    # W_0, ... W_131 are called prekeys and are generated according to the paper
    for i in range(132):
        xor_res = string_multiple_xor(w[i - 8], w[i - 5], w[i - 3], w[i - 1], num_to_bitstring(PHI, 32),
                                      num_to_bitstring(i, 32))
        w[i] = rotate_string_left(xor_res, 11)

    # GROUPED ROUND KEYS GENERATION
    round_keys = []
    for i in range(ROUNDS + 1):
        # print("round #"+str(i))
        # consider 4 w-words
        # group 4 corresponding bits from considered 4 w-words
        # then, send it to S_box
        sbox_num = (ROUNDS + 3 - i) % ROUNDS
        temp_k = ['', '', '', '']
        for a, b, c, d in zip(w[(4 * i)], w[(4 * i) + 1], w[(4 * i) + 2], w[(4 * i) + 3]):
            to_sbox = a + b + c + d
            res = sbox_func(sbox_num, to_sbox)
            # print(res)
            for j in range(4):
                temp_k[j] += res[j]

        round_keys.append(''.join(temp_k))  # making 4 32-bit keys into single 128-bit round key

    # The keys used in the rounds have the initial permutation on them
    round_keys = [initial_permutation(i) for i in round_keys]
    return round_keys


def initial_permutation(inp):
    return permutate(IPtable, inp)


def final_permutation(inp):
    return permutate(FPtable, inp)


def permutate(table, inp):
    assert len(table) == len(inp), 'Invalid Input: The length of inp and table does not match!'
    return ''.join([inp[table[i]] for i in range(len(table))])


def sbox_func(box_num, bit_input):
    num_input = int(bit_input[::-1], 2)
    num_output = SBoxDecimalTable[box_num % SBOXES_NUM][num_input]
    return num_to_bitstring(num_output, 4)


def sbox_inverse_func(box_num, bit_input):
    num_input = int(bit_input[::-1], 2)
    num_output = -1
    for idx in range(len(SBoxDecimalTable[box_num % SBOXES_NUM])):
        if SBoxDecimalTable[box_num % SBOXES_NUM][idx] == num_input:
            num_output = idx
            break

    assert num_output != -1, 'We broke the system :('
    return num_to_bitstring(num_output, 4)
