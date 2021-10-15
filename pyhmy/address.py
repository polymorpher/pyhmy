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


def toChecksum(addr, hrp='one'):
    b = toBHex(addr)
    if not b:
        return None
    return eth_utils.to_checksum_address(b)
