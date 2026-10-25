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

from utils import function_logger, function_logger_too, error_writer
from random import randint

@function_logger_too
def pad_lengther(data_length: int, block_size:int):
  try:
    pad_length = block_size if abs(data_length-block_size) == 0 else abs(data_length-block_size)
    return pad_length
  except Exception as e:
        error_writer(e, description="Unable to calculate length of pad.")

@function_logger_too
def pad_generator(pad_length: int, byte_candidate: int):
  try:
    pad_ = b''.join([bytes([byte_candidate]) for i in range(0, pad_length)])
    return pad_
  except Exception as e:
        error_writer(e, description="Unable to generate pad.")

@function_logger_too
def random_pad_byte(lastbyte: bytes, block_size: int):
  try:
    bool_ = True
    while bool_:
      random_pad_byte = randint(1, block_size)
      bool_ = True if random_pad_byte == int(lastbyte) else False
    return random_pad_byte
  except Exception as e:
    error_writer(e, description="Unable to generate pad.")

@function_logger_too
def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """Return `data` with PKCS#7 padding for `block_size` (see the module docstring)."""
    try:
        # we are thinking we are getting the chunk of the data here... chunking and serializing happend before this function
        pad_length_ = pad_lengther(len(data), block_size)
        random_pad_byte_ = random_pad_byte(data[-1], block_size)
        pad_ = pad_generator(pad_length_, random_pad_byte_)

        padded_bytes = b''.join([data, pad_])

        return padded_bytes
    except Exception as e:
        error_writer(e, description=f"{data} unable to pad byte-message (pkcs7).")

@function_logger
def reverse_pad_lengther(padded_data: bytes):
  try:
    pad_n = padded_data[-1]
    range_ = len(padded_data)

    for i, n in enumerate(padded_data):
        if int(padded_data[-(i+1)]) == int(pad_n):
          pass
        else:
          range_ = i
          break
    
    return range_
  except Exception as e:
        error_writer(e, description="Unable to calculate length of pad.")

def pad_exception_checker(data: bytes, block_size: int):
  #Unpadding raises `ValueError` for an invalid block size, empty input,
  #non-block-aligned input, or invalid padding.
  if block_size > 255 or block_size < 1:
    raise ValueError("Invalid block size.")

  elif len(data) < 1:
    raise ValueError("Empty input.")

  elif len(data) % block_size != 0:
    raise ValueError("Invalid padding.")

  #non-block-aligned input... what is this haha

  else:
    pass

@function_logger_too
def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    """Return `data` with valid PKCS#7 padding removed, or raise ValueError."""
    try:
        _ = pad_exception_checker(data, block_size)

        pad_length_ = reverse_pad_lengther(data)
        unpadded_data = data[:-(pad_length_)]
        return unpadded_data
    except Exception as e:
        error_writer(e, description=f"{data} unable to unpad byte-message (pkcs7).")

test_bytes = bytes([5, 7])
test = pkcs7_pad(test_bytes, 16)
test_ = pkcs7_unpad(test, 16)