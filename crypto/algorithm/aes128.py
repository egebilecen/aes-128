from typing import Literal
from crypto.key import Key
from crypto.math import *

"""
    AES-128 algorithm class.
"""
class AES128:
    """
        Substitution box definition.
    """
    _substitution_box: bytes = bytes([
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
    ])

    """
        Round constants definition.
    """
    _round_constants: list[int] = [
        0x01000000, 0x02000000, 
        0x04000000, 0x08000000,
        0x10000000, 0x20000000,
        0x40000000, 0x80000000,
        0x1B000000, 0x36000000
    ]

    """
        Mixing Matrix
    """
    _mixing_matrix: list[list[int]] = [
        [0x02, 0x03, 0x01, 0x01],
        [0x01, 0x02, 0x03, 0x01],
        [0x01, 0x01, 0x02, 0x03],
        [0x03, 0x01, 0x01, 0x02]
    ]

    """
        Constructor of the class. Expects a Key class object.
    """
    def __init__(self, key: Key, byte_order: Literal["big", "little"] = "big") -> None:
        if key.size() != 128:
            raise ValueError("AES-128 algorithm expects a 128-bit key.")
        
        self._key: Key = key
        self._rounds: int = 10
        self._byte_order: Literal["big", "little"] = byte_order

    """
        Groups single bytes into 4-byte ints.
    """
    def _group_bytes(self, byte_arr: bytes) -> list[int]:
        return [int.from_bytes(byte_arr[(i * 4) : ((i * 4) + 4)], byteorder=self._byte_order) for i in range(4)]

    """
        Expands the grouped 4-bytes into single bytes.
    """
    def _expand_bytes(self, grouped_bytes: list[int]) -> bytearray:
        byte_arr: bytearray = bytearray()

        for group in grouped_bytes:
            byte_arr.extend(int.to_bytes(group, 4, self._byte_order))

        return byte_arr

    """
        Gets the byte in given index of the 4-byte number.
        Indexing starts from 0 and right-most byte is 
        considered to be 0th index.
    """
    def _get_byte(self, num: int, index: int) -> int:
        # Amount of shift to get target 8-bit.
        byte_shift: int = index * 8

        # Target byte of the word.
        return (num & (0xFF << byte_shift)) >> byte_shift

    """
        Rotates the row to the left by given count.
        byte_arr is a regular array which will be
        interpreted as if it was column-major
        matrix while performing the rotation.
        
        [][][][] -> 0th row
        [][][][] -> 1st row
        [][][][] -> 2nd row
        [][][][] -> 3rd row
    """
    def _rotate_row_left(self, byte_arr: bytearray, row: int, count: int) -> None:
        if row < 0 or row > 3:
            raise ValueError("row cannot be smaller than 0 or cannot be bigger than 3.")
        
        # Rotating a row more than 3 times is
        # same as rotating it by count % 4.
        if count > 3:
            count = count % 4

        # No rotation.
        if count < 1:
            return

        # Convert linear indexing into column-major indexing depending
        # on which row we are rotating.
        row_indexes: list[int] = [row, row + 4, row + 8, row + 12]

        # Get the elements in the row using their indexes.
        elements: list[int] = [byte_arr[i] for i in row_indexes]

        # Rotate the elements to left by given count.
        elements = elements[count : ] + elements[0 : count]

        # Update the original array with new rotated values.
        for i, row_index in enumerate(row_indexes):
            byte_arr[row_index] = elements[i]

    """
        Generates round key list to be used in each round.
    """
    def _expand_key(self) -> list[int]:
        # Get the key bytes.
        key_bytes: bytes = self._key.as_bytes()

        # Combine key bytes into 4-byte int (aka word).
        # Initially, this variable holds w0, w1, w2, and w3.
        # It will be expanded with keys.
        key_words: list[int] = self._group_bytes(key_bytes)

        # Do key expansion for self._rounds rounds.
        for i in range(1, self._rounds + 1):
            # Words of the last/previous round.
            last_round_words: list[int] = [w for w in key_words[((i - 1) * 4) : (((i - 1) * 4) + 4)]]
            
            ### Begining of g() function (in specification).
            # Rotate the last word of the last round to left by 1 byte (or 8 bits).
            rotated_word: int = rotate_left(last_round_words[-1], 8, 32)

            # Substitute the rotated last word of the last round.
            substituted_word: int = 0x00

            # Iterate 4 times to get each byte in the word.
            for j in range(4):
                # Get the target byte of the word.
                byte: int = self._get_byte(rotated_word, j)

                # Save the substituted value.
                substituted_word |= self._substitution_box[byte] << (j * 8)

            # Get the round constant.
            round_const: int = self._round_constants[i - 1]

            # XOR the substituted word with round constant.
            word_g: int = substituted_word ^ round_const
            ### end of g() function.

            # Calculate the new batch of key words.
            # First new word. It's the XOR of last round's first key
            # and word produced in g() function.
            wn_1: int = last_round_words[0] ^ word_g

            # Second new word. It's the XOR of first new word
            # and last round's second key.
            wn_2: int = wn_1 ^ last_round_words[1]

            # Third new word. It's the XOR of second new word
            # and last round's third key.
            wn_3: int = wn_2 ^ last_round_words[2]

            # Fourth new word. It's the XOR of third new word
            # and last round's fourth key.
            wn_4: int = wn_3 ^ last_round_words[3]

            # Expand the keys.
            key_words.extend([wn_1, wn_2, wn_3, wn_4])

        return key_words
    
    """
        Updates the state with the round key.
    """
    def _add_round_key(self, state: list[int], keys: list[int]) -> None:
        # Loop over each grouped 4-bytes (words).
        for i, w in enumerate(state):
            # Update the state by XORing it with the related key.
            state[i] = w ^ keys[i]
    
    """
        Applies substitution layer to the state.
    """
    def _substitution_layer(self, state: list[int]) -> None:
        # Loop over each grouped 4-bytes (words).
        for i, w in enumerate(state):
            # Temporary value that will store the substituted value.
            temp: int = 0x00

            # Get each byte of the word.
            for j in range(4):
                byte: int = self._get_byte(w, j)

                # Save the substitution of the byte.
                temp |= self._substitution_box[byte] << (j * 8)

            # Update the state.
            state[i] = temp

    """
        Shifts the rows of the state.
    """
    def _shift_rows(self, state: list[int]) -> None:
        # Convert grouped 4-bytes back into single bytes as
        # we will need to rotate rows which is easier to
        # perform when array contains individual bytes.
        byte_arr: bytearray = self._expand_bytes(state)

        # Rotate the second row to left by 1 bytes.
        self._rotate_row_left(byte_arr, 1, 1)

        # Rotate the third row to left by 2 bytes.
        self._rotate_row_left(byte_arr, 2, 2)

        # Rotate the fourth row to left by 3 bytes.
        self._rotate_row_left(byte_arr, 3, 3)

        # Update the state.
        # In order to mutate the state variable,
        # we need to assign the new bytes by
        # using [:] trick which replaces all
        # elements in the array with the other
        # array's values.
        state[:] = self._group_bytes(byte_arr)

    """
        Mixes the columns of the state.
    """
    def _mix_columns(self, state: list[int]) -> None:
        # Convert grouped 4-bytes back into single bytes as
        # we need single bytes to perform mixing operations.
        byte_arr: bytearray = self._expand_bytes(state)

        # This byte array will hold the values after mixing
        # operation is performed.
        mixed_arr: bytearray = byte_arr.copy()

        # Galois Field we are operating. If result of polynomial
        # multiplication exceeds this, we will reduce it.
        galois_field: int = 2 ** 3

        # Primivite polynomial to be used to perform modulo reduce.
        primitive_poly: list[int] = [8, 4, 3, 1, 0] # Equivalent of 0b1_0001_1011.

        # Loop over each columns.
        for i in range(4):
            # Get relevant column of the state.
            col: bytearray = byte_arr[(i * 4) : ((i * 4) + 4)]
            
            for j, mat in enumerate(self._mixing_matrix):
                # Perform matrix multiplication.
                v1: int = poly_to_num(poly_mult(num_to_poly(mat[0]), num_to_poly(col[0]), galois_field, primitive_poly))
                v2: int = poly_to_num(poly_mult(num_to_poly(mat[1]), num_to_poly(col[1]), galois_field, primitive_poly))
                v3: int = poly_to_num(poly_mult(num_to_poly(mat[2]), num_to_poly(col[2]), galois_field, primitive_poly))
                v4: int = poly_to_num(poly_mult(num_to_poly(mat[3]), num_to_poly(col[3]), galois_field, primitive_poly))

                # Save the value after mixing.
                mixed_arr[(i * 4) + j] = v1 ^ v2 ^ v3 ^ v4

        # Update the state.
        # In order to mutate the state variable,
        # we need to assign the new bytes by
        # using [:] trick which replaces all
        # elements in the array with the other
        # array's values.
        state[:] = self._group_bytes(mixed_arr)

    """
        Encrypts the given byte array using AES algorithm.
    """
    def encrypt(self, byte_arr: bytes) -> bytes:
        if len(byte_arr) * 8 != 128:
            raise ValueError("AES-128 can only encrypt 128-bits.")
        
        # Convert byte array into 4-byte array as all operations
        # performed on group of 4-bytes.
        state: list[int] = self._group_bytes(byte_arr)

        # Generate round keys to be used in each round.
        round_keys: list[int] = self._expand_key()

        # Do initial key whitening.
        self._add_round_key(state, round_keys[0 : 4])

        # Iterate for self._rounds rounds.
        for i in range(1, self._rounds + 1):
            # Apply substitution layer.
            self._substitution_layer(state)

            # Shift the rows.
            self._shift_rows(state)

            # Not last round, mix the columns.
            if i != self._rounds:
                self._mix_columns(state)

            # Add round key into state.
            self._add_round_key(state, round_keys[(i * 4) : ((i * 4) + 4)])
            
        # Convert the state back to byte array and return it.
        return self._expand_bytes(state)
