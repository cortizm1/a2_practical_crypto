"""Part 0: implement these yourself before requesting generated code.

Save your first attempt as padding_first_attempt.py before subsequent revisions.

PKCS#7 padding
--------------
A block cipher mode such as CBC works on whole blocks, so a message must be
extended to a multiple of the block size before encryption and the extension
removed after decryption. PKCS#7 (RFC 5652 §6.3) does this by appending N
bytes, each with the value N, where N is between 1 and the block size and is
chosen so that the result is a whole number of blocks.

Two worked examples with the default block size of 16:

    15-byte input  41 41 41 41 41 41 41 41 41 41 41 41 41 41 41
                   (one byte short of a block, so N = 1)
    padded (16)    41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 01

    16-byte input  41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41
                   (already block-aligned, so N = 16: a whole extra block)
    padded (32)    41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41
                   10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10

Unpadding reverses this: read the last byte to learn N, check that the last N
bytes all equal N, and remove them.

The contract (handout Part 0)
-----------------------------
* `pkcs7_pad(data: bytes, block_size: int = 16) -> bytes`
* `pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes`
* Support block sizes 1 through 255.
* Padding always appends at least one byte, including a full block when the
  input is already aligned.
* Unpadding raises `ValueError` for an invalid block size, empty input,
  non-block-aligned input, or invalid padding.
* Use these functions for JM1 (specification §7.1-§7.2).

The handout also asks for your own examples (empty input, an aligned input,
an input one byte short of a block, and invalid padding) and your own
explanation of why padding is always added. Write the first version of these
functions and examples without generated code or a library padding helper.
"""

from utils import logged, error_writer
from random import randint

@logged
def pad_lengther(data_length: int, block_size:int):
  pad_length = block_size if (data_length % block_size == 0) else abs(block_size - (data_length % block_size))
  return pad_length

@logged
def pad_generator(pad_length: int, byte_candidate: int):
  pad_ = b''.join([bytes([byte_candidate]) for i in range(0, pad_length)])
  return pad_

@logged
def null_checker(data:bytes):
    if data is None or len(data) < 1:
      raise ValueError("Empty input.")

@logged
def block_checker(data:bytes, block_size:int):
  #non-block-aligned input, or invalid padding.
  if block_size > 255 or block_size < 1:
    raise ValueError("Invalid block size.")

@logged
def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """Return `data` with PKCS#7 padding for `block_size` (see the module docstring)."""
    
    _ = block_checker(data, block_size)
    pad_length_ = pad_lengther(len(data), block_size)
    pad_byte = int(pad_length_)

    pad_ = pad_generator(pad_length_, pad_byte)

    padded_bytes = b''.join([data, pad_])

    return padded_bytes

@logged
def pad_exception_checker(data: bytes, block_size: int):
  #Unpadding raises `ValueError` for an invalid block size, empty input,
  _ = null_checker(data)
  _ = block_checker(data, block_size)

  if len(data) % block_size != 0:
    raise ValueError("Invalid padding.")

@logged
def pad_checker(data: bytes, pad_digit:int, block_size:int) -> bytes:
    bool_ = True if (1 <= pad_digit <= block_size) and data[-pad_digit:].count(pad_digit) == pad_digit and len(data) % block_size == 0 else False

    if not bool_:
      raise ValueError("Invalid padding.")

@logged
def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    """Return `data` with valid PKCS#7 padding removed, or raise ValueError."""
    _ = pad_exception_checker(data, block_size)
    _ = pad_checker(data, data[-1], block_size)

    unpadded_data = data[:-(data[-1])]

    return unpadded_data


if __name__ == "__main__":
  test_bytes = bytes([5, 7])
  test = pkcs7_pad(test_bytes, 16)
  test_ = pkcs7_unpad(test, 16)

  test_bytes_2 = bytes()
  test = pkcs7_pad(test_bytes_2, 16)
  test_ = pkcs7_unpad(test, 16)