from pyhmy.bech32 import bech32
import binascii
import eth_utils


def toBHex(addr, hrp='one'):
    head, data = bech32.bech32_decode(addr)
    if head != hrp:
        return None
    return bytearray(bech32.convertbits(data[:], 5, 8, False))


def toHex(addr, hrp='one'):
    b = toBHex(addr, hrp)
    h = binascii.hexlify(b)
    return '0x' + h.decode('utf-8')


def checksum_encode(addr):  # Takes a 20-byte binary address as input
    hex_addr = addr.hex()
    checksummed_buffer = ""

    # Treat the hex address as ascii/utf-8 for keccak256 hashing
    hashed_address = eth_utils.keccak(text=hex_addr).hex()

    # Iterate over each character in the hex address
    for nibble_index, character in enumerate(hex_addr):

        if character in "0123456789":
            # We can't upper-case the decimal digits
            checksummed_buffer += character
        elif character in "abcdef":
            # Check if the corresponding hex digit (nibble) in the hash is 8 or higher
            hashed_address_nibble = int(hashed_address[nibble_index], 16)
            if hashed_address_nibble > 7:
                checksummed_buffer += character.upper()
            else:
                checksummed_buffer += character
        else:
            raise eth_utils.ValidationError(
                f"Unrecognized hex character {character!r} at position {nibble_index}"
            )

    return "0x" + checksummed_buffer


def toChecksum(addr, hrp='one'):
    b = toBHex(addr)
    if not b:
        return None
    return checksum_encode(b)
