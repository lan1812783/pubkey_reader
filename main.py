import sys
import base64
import struct
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.type import univ

# Ref: https://blog.oddbit.com/post/2011-05-08-converting-openssh-public-keys/

der_encoded = base64.decodebytes(
    bytes(
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1rYQ8OYbgw54kuS0suCb"
        "vQku5XLv4z0tBrfggrWbiiujaicwtbwRYN1VWWixyshuTzF4YgjYmimVeSIojmKz"
        "q5xkfjVKyo6iCaoTYYOhlASTMFs/h0F5vSercDNAvv0/996ZTee3FiAd5qfOqDa8"
        "RK4bSMREvJuKkeMzntLwjhNgEWZDcWsGXpqSo03JClZXAQAzSEimeReY8xH6BpFQ"
        "j909lgn2IysoZRiOzGrtXmC0WF2ng1AMNL8PYnfaZtkpiHgRX8aBBBSfdpr0ardj"
        "tO7+YAZF2GUfvadlECYcw8gTSfnqRFN7SC24/fPWwEHV1NFOv8/qXZG+4obVlOp7"
        "RwIDAQAB",
        'utf-8'))

pkcs1_seq = der_decoder.decode(der_encoded)

algId: univ.Sequence = pkcs1_seq[0].getComponentByPosition(0)
publicKey: univ.BitString = pkcs1_seq[0].getComponentByPosition(1)

class BinaryStreamReader:
    def __init__(self, bin_str):
        self.bit_idx = 0
        self.bin_str = bin_str
    def read_nbytes_as_int(self, n_bytes):
        prev_bit_idx = self.bit_idx
        self.bit_idx += n_bytes * 8
        number = int(self.bin_str[prev_bit_idx:self.bit_idx], 2)
        return number

print(f'- Algorithm Identifier: {algId.getComponentByPosition(0)}')
binStreamReader = BinaryStreamReader(publicKey.asBinary())
# Refs:
#   https://stackoverflow.com/a/12750816
#   https://stackoverflow.com/a/13104466
binStreamReader.read_nbytes_as_int(6)
n_len = binStreamReader.read_nbytes_as_int(2)
n = binStreamReader.read_nbytes_as_int(n_len)
print(f'- Modulus: {n}')
binStreamReader.read_nbytes_as_int(1)
e_len = binStreamReader.read_nbytes_as_int(1)
e = binStreamReader.read_nbytes_as_int(e_len)
print(f'- Exponent: {e}')
