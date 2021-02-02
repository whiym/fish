Base64
======

The base64 encoding for CBC mode is the standard padded scheme. However, for EBC mode is a little unique.

The charset is also non standard: `./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ`

Encoding
--------

8 bytes are encoded at a time, so inputs must be padded if not a multiple of 8.

Using an example input of: `qwertyui`

The hex and binary representations of the ascii characters are:

| ascii | hex | binary |
|---|---|---|
| q | 71 | 01110001 |
| w | 77 | 01110111 |
| e | 65 | 01100101 |
| r | 72 | 01110010 |
| t | 74 | 01110100 |
| y | 79 | 01111001 |
| u | 75 | 01110101 |
| i | 69 | 01101001 |

Taking the first 4 bytes (left), reading from the left and shifting to the left to form a 32 bit integer:

| | | | | | | |
|---:|---:|---:|---:|---:|---:|---:|
| **ascii**          |        q |        w |        e |        r |
| **binary (8 bit)** | 01110001 | 01110111 | 01100101 | 01110010 |

The resulting 6 bit encoding with the charset is:

| | | | | | | |
|---:|---:|---:|---:|---:|---:|---:|
| **binary (6 bit)** | 01 | 110001 | 011101 | 110110 | 010101 | 110010 |
| **dec (index)**    |  1 |     49 |     29 |     54 |     21 |     50 |
| **base64**         |  / |      L |      r |      Q |      j |      M |

Similarly for the second 4 bytes (right):

| | | | | | | |
|---:|---:|---:|---:|---:|---:|---:|
| **ascii**          |        t |        y |        u |        i |
| **binary (8 bit)** | 01110100 | 01111001 | 01110101 | 01101001 |

| | | | | | | |
|---:|---:|---:|---:|---:|---:|---:|
| **binary (6 bit)** | 01 | 110100 | 011110 | 010111 | 010101 | 101001 |
| **dec (index)**    |  1 |     52 |     30 |     23 |     21 |     41 |
| **base64**         |  / |      O |      s |      l |      j |      D |

The reading the right bytes first, from the right and shifting to the right results in the output: `DjlsO/MjQrL/`

Decoding
--------

12 bytes are decoded at a time, so inputs must be padded if not a multiple of 12.

Now the reverse is shown with an input of: `DjlsO/MjQrL/`

The decimal (index into the charset) and binary representation of the ascii characters are:

| ascii | index | binary (6 bits) |
|---|---|---|
| D | 41 | 101001 |
| j | 21 | 010101 |
| l | 23 | 010111 |
| s | 30 | 011110 |
| O | 52 | 110100 |
| / |  1 | 000001 |
| M | 50 | 110010 |
| j | 21 | 010101 |
| Q | 54 | 110110 |
| r | 29 | 110010 |
| L | 49 | 110001 |
| / |  1 | 000001 |

Taking the first 6 bytes (right), reading from the right, looking up their index into the charset and shifting to the
left to form a 32 bit integer:

| | | | | | | |
|---:|---:|---:|---:|---:|---:|---:|
| **base64**         |      / |      O |      s |      l |      j |      D |
| **dec (index)**    |      1 |     52 |     30 |     23 |     21 |     41 |
| **binary (6 bit)** | 000001 | 110100 | 011110 | 010111 | 010101 | 101001 |

Dropping 2 null bytes, the resulting 8 bit (ascii) encoding is:

| | | | | | | |
|---:|---:|---:|---:|---:|---:|---:|
| **binary (8 bit)** | 0000 | 01110100 | 01111001 | 01110101 | 01101001 | 
| **hex**            |      |       74 |       79 |       75 |       69 |
| **ascii**          |      |        t |        y |        u |        i |

Similarly, for the second 6 bytes (left):

| | | | | | | |
|---:|---:|---:|---:|---:|---:|---:|
| **base64**         |      / |      L |      r |      Q |      j |      M |
| **dec (index)**    |      1 |     49 |     29 |     54 |     21 |     50 |
| **binary (6 bit)** | 000001 | 110001 | 011101 | 110110 | 010101 | 110010 |

| | | | | | | |
|---:|---:|---:|---:|---:|---:|---:|
| **binary (8 bit)** | 0000 | 01110001 | 01110111 | 01100101 | 01110010 |
| **hex**            |      |       71 |       77 |       65 |       72 |
| **ascii**          |      |        q |        w |        e |        r |

Then reading the left bytes first, from the left and shifting to the right results in the output: `qwertyui`
