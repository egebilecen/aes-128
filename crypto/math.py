from crypto.util import *

"""
    Generate a number that has all their bits set to 1
    up to size.

    For example:
    bit_ones(8) -> 11111111
"""
def bit_ones(size: int) -> int:
    num: int = 0x00

    for i in range(0, size):
        num |= (1 << i)

    return num

"""
    Rotates the bits of the given number to the left.
"""
def rotate_left(num: int, bits: int, width: int) -> int:
    if bits > width:
        bits = bits % width

    # Preserve the bits that otherwise would be lost when shifted to
    # the left.
    preserved_bits: int = (num & (bit_ones(bits) << (width - bits))) >> (width - bits)

    # Group of bits that can be safely shifted to left without worry
    # of losing bits.
    bits_to_shift: int  = num & (bit_ones(width - bits))

    rotated: int = (bits_to_shift << bits) | preserved_bits

    return rotated

"""
    Rotates the bits of the given number to the right.
"""
def rotate_right(num: int, bits: int, width: int) -> int:
    if bits > width:
        bits = bits % width

    # Preserve the bits that otherwise would be lost when shifted to
    # the right.
    preserved_bits: int = num & bit_ones(bits)

    # Group of bits that can be safely shifted to right without worry
    # of losing bits.
    bits_to_shift: int  = num & (bit_ones(width - bits) << bits)

    rotated: int = (bits_to_shift >> bits) | (preserved_bits << (width - bits))

    return rotated

"""
    Converts a number to its polynomial representation. Only their exponents
    are returned. width parameter is the width (bit-wise) of the number.

    For example:
    0x87 -> x^7 + x^2 + x + 1

    This function will return [7, 2, 1, 0] for 0x87.
"""
def num_to_poly(num: int, width: int = 8) -> list[int]:
    poly: list[int] = []

    for i in range(width):
        bit: int = 1 if num & (0x01 << i) != 0 else 0

        if bit != 0:
            poly.insert(0, i)

    return poly

"""
    Converts polynomial representation back to number.

    For example:
    [7, 2, 1, 0] -> x^7 + x^2 + x + 1 -> 10000111 -> 0x87 -> 135
"""
def poly_to_num(poly: list[int]) -> int:
    temp: int = 0x00

    for elem in poly:
        temp |= 0x01 << elem

    return temp

"""
    Performs polynomial addition in Galois Field GF(2).
    Logic is quite simple. We merge both polynomial exponents
    array and only grab the non-duplicate exponents.

    For example:
    (x^4 + x^3 + x + 1) + (x^4 + x^2 + x) = x^3 + x^2 + 1
    [4, 3, 1, 0, 4, 2, 1] -> [3, 2, 0]
"""
def poly_solve(poly: list[int]) -> list[int]:
    return sorted([elem for elem in poly if poly.count(elem) == 1], reverse=True)

"""
    Adds two polynomials.

    For example:
    (x^4 + x^3 + x + 1) + (x^4 + x^2 + x) = x^3 + x^2 + 1
    [4, 3, 1, 0] + [4, 2, 1] = [3, 2, 0]
"""
def poly_add(poly1: list[int], poly2: list[int]) -> list[int]:
    return poly_solve(poly1 + poly2)

"""
    Multiplies two polynomials. If the result exceeds the Galois Field given as
    param gf, it reduces the resultant polynomial with the primitive polynomial
    given as parameter.

    For example:
    0x02 * 0x87 -> x * (x^7 + x^2 + x + 1) = x^8 + x^3 + x^2 + x

    If we are operating in GF(2^3), we need to reduce the resultant polynomial.
    
    For example:
    gf = 2 ^ 3, reducer_poly = [8, 4, 3, 1, 0] (Equivalent of x^8 + x^4 + x^3 + x + 1
                                                which AES uses.)
    
    Since the resultant polynomial is out of the Galois Field, it will be reduced to:
    (x^8 + x^3 + x^2 + x) + (x^8 + x^4 + x^3 + x + 1) = (x^4 + x^2 + 1) = [4, 2, 0]
"""
def poly_mult(left_poly: list[int], right_poly: list[int], gf: int, primitive_poly: list[int]) -> list[int]:
    # Resultant polynomial will be stored in this array.
    result_poly: list[int] = []
    
    # Multiply each element of the left poly with the 
    # each element of the right poly and add it into result.
    for pl in left_poly:
        for pr in right_poly:
            # Temporary value to hold the result of element
            # multiplication.
            res: int = 0

            # We are multiplying the right polynomial's element
            # with 1. Just add it to the result polynomial.
            if pl == 0:
                res = pr

            # We are multiplying the left polynomial's element
            # with 1. Just add it to the result polynomial.
            elif pr == 0:
                res  = pl

            # Since our polynomial arrays holds exponents,
            # we can just add them together.
            else:
                res = pl + pr

            # Append element to the result polynomial.
            result_poly.append(res)

    # Solve the polynomial. Performs addition operation.
    result_poly = poly_solve(result_poly)

    # Check if we are out of galois field we are operating on. 
    # If yes, do polynomial addition with the primitive polynomial.
    if len(result_poly) > 0 and result_poly[0] >= gf:
        result_poly = poly_add(result_poly, primitive_poly)

    # Return the resultant polynomial.
    return result_poly
