from binascii import unhexlify

def int2bytes(i, length=None, endian='little'):
    """Convert an integer to a string (bytes):

    i: the integer to be converted
    length: (optional) the desired length of the string (in bytes), the default
        is to output the shortest string that can represent the integer
    """
    if length is None:
        length = i.bit_length()
        length += 8 - ((length % 8) or 8)
        assert length % 8 == 0
        assert length >= i.bit_length()
        length //= 8
    elif i.bit_length()/8.0 > length:
        raise ValueError("Integer too large to be represented in desired length")

    # Oh BDFL, forgive us our abuses!
    format_string = '%%0%dx' % (length * 2)
    hex_string = format_string % i

    if endian == 'little':
        return unhexlify(hex_string)[::-1]
    elif endian == 'big':
        return unhexlify(hex_string)
    else:
        raise TypeError('Argument endian must be either \'big\' or \'little\'')

def bytes2int(b, endian='little'):
    """Convert a string (bytes) to an integer:

    b: the string (bytes) to be converted
    """
    if endian == 'little':
        return sum(ord(char) << (i * 8) for i, char in enumerate(b))
    elif endian == 'big':
        return sum(ord(char) << (i * 8) for i, char in enumerate(reversed(b)))
    else:
        raise TypeError('Argument endian must be either \'big\' or \'little\'')

def encode_varint(i,endian='little'):
    """Produce a byte encoding of an integer.

    The encoding captures both the value and length of the integer, so appending
    the encoded integer to arbitrary data will not effect the ability to decode
    the integer. In addition, the encoding never produces a string ending in a
    null, so after transforming to and from an int (little endian), the string
    will be unchanged.
    """
    if endian not in ('little', 'big'):
        raise TypeError('Argument endian must be either \'big\' or \'little\'')

    encoded = ''
    # the final byte (most-significant byte little-endian) is never 0x00
    if i+1 < 0xfb:
        signifier = chr(i+1)
    elif i <= 0xff:
        signifier = chr(0xfb)
        encoded = chr(i)
    elif i <= 0xffff:
        signifier = chr(0xfc)
        encoded = int2bytes(i,2,endian=endian)
    elif i <= 0xffffffff:
        signifier = chr(0xfd)
        encoded = int2bytes(i,4,endian=endian)
    elif i <= 0xffffffffffffffff:
        signifier = chr(0xfe)
        encoded = int2bytes(i,8,endian=endian)
    else:
        l = (i.bit_length() - 1) // 8 + 1
        s = int2bytes(i,l)
        assert len(s) == l
        signifier = chr(0xff)
        if endian == 'little':
            encoded = s + encode_varint(l,endian=endian)
        else:
            encoded = encode_varint(l,endian=endian) + s

    if endian == 'little':
        return encoded + signifier
    else:
        return signifier + encoded
    
def decode_varint(s,endian='little'):
    """Decode an string produced by mnemonic.encode_varint

    returns a 2-tuple of (integer, bytes consumed)
    The bytes consumed indicates how long the encoded integer was. This is
    useful if the integer was appended to some data.
    """
    if endian not in ('little', 'big'):
        raise TypeError('Argument endian must be either \'big\' or \'little\'')

    if endian == 'little':
        signifier, encoded = s[-1], s[:-1]
    else:
        signifier, encoded = s[0], s[1:]
    signifier = ord(signifier)
    if signifier == 0:
        raise ValueError("this encoding scheme never has a null signifier")

    if signifier < 0xfb:
        return (signifier-1, 1)
    elif signifier == 0xfb:
        return (ord(encoded), 2)
    elif signifier == 0xfc:
        bounds = 2
        consumed = 3
    elif signifier == 0xfd:
        bounds = 4
        consumed = 5
    elif signifier == 0xfe:
        bounds = 8
        consumed = 9
    elif signifier == 0xff:
        (bounds, consumed) = decode_varint(encoded, endian=endian)
        if endian == 'little':
            encoded = encoded[:-consumed]
        else:
            encoded = encoded[consumed:]
        consumed += bounds + 1

    if endian == 'little':
        return (bytes2int(encoded[-bounds:], endian=endian), consumed)
    else:
        return (bytes2int(encoded[:bounds], endian=endian), consumed)

__all__ = ['int2bytes', 'bytes2int', 'encode_varint', 'decode_varint']
