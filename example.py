from crypto.key import Key
from crypto.algorithm.aes128 import AES128
from crypto.util import *

"""
    Test vectors are from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf.
    They can be found in page 24 and after on.

    [Output]
    $ python example.py
    KEY        : 2b7e151628aed2a6abf7158809cf4f3c
    PLAIN TEXT : 6bc1bee22e409f96e93d7e117393172a
    CIPHER TEXT: 3ad77bb40d7a3660a89ecaf32466ef97

    KEY        : 2b7e151628aed2a6abf7158809cf4f3c
    PLAIN TEXT : ae2d8a571e03ac9c9eb76fac45af8e51
    CIPHER TEXT: f5d3d58503b9699de785895a96fdbaaf

    KEY        : 2b7e151628aed2a6abf7158809cf4f3c
    PLAIN TEXT : 30c81c46a35ce411e5fbc1191a0a52ef
    CIPHER TEXT: 43b1cd7f598ece23881b00e3ed030688

    KEY        : 2b7e151628aed2a6abf7158809cf4f3c
    PLAIN TEXT : f69f2445df4f9b17ad2b417be66c3710
    CIPHER TEXT: 7b0c785e27e8ad3f8223207104725dd4
"""

# Key.
key = Key(hex_str_bytes("2b7e151628aed2a6abf7158809cf4f3c"))

# Plain text list.
plain_text_list = [
    hex_str_bytes("6bc1bee22e409f96e93d7e117393172a"),
    hex_str_bytes("ae2d8a571e03ac9c9eb76fac45af8e51"),
    hex_str_bytes("30c81c46a35ce411e5fbc1191a0a52ef"),
    hex_str_bytes("f69f2445df4f9b17ad2b417be66c3710"),
]

# AES-128 cipher.
aes128 = AES128(key)

# Loop over each plain text and encrypt them using same key.
# Then print the results.
for plain_text in plain_text_list:
    cipher = aes128.encrypt(plain_text)
    printp("KEY        :", key.as_str(False))
    printp("PLAIN TEXT :", hex(plain_text, False))
    printp("CIPHER TEXT:", hex(cipher, False))
    print()
