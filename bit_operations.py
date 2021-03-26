def rotate_string_left(str, shift):
    shift = shift % len(str)
    return str[-shift:] + str[:-shift]


def shift_string_left(str, shift):
    if shift >= len(str):
        return '0' * len(str)
    else:
        return str[shift:] + '0' * shift


def string_xor(str1, str2):
    assert len(str1) == len(str2), "Invalid Input"
    # This is an intrinsic function of string_multiple_xor
    """

    :param str1: first bit string
    :param str2: second bit string
    :return: bit wise xor between the strings
    """
    return ''.join(['1' if i != j else '0' for i, j in zip(str1, str2)])


def string_multiple_xor(*strs):
    """

    :param strs: array of bit strings
    :return: bit wise xor between all string
    """
    res = strs[0]
    for s in strs[1:]:
        res = string_xor(res, s)
    return res


def num_to_bitstring(num, length):
    p_format = '{0:0' + str(length) + 'b}'
    return p_format.format(num)[::-1]
