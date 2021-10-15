from pyhmy.bech32 import bech32
import binascii
import eth_utils


def to_bhex(addr, hrp='one'):
    head, data = bech32.bech32_decode(addr)
    if head != hrp:
        return None
    return bytearray(bech32.convertbits(data[:], 5, 8, False))


def to_hex(addr, hrp='one'):
    b = to_bhex(addr, hrp)
    h = binascii.hexlify(b)
    return '0x' + h.decode('utf-8')


def to_checksum(addr, hrp='one'):
    b = to_bhex(addr, hrp)
    if not b:
        return None
    return eth_utils.to_checksum_address(b)
