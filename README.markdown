Parcel
======
Parcel is a command line tool for converting binary data to and from
hexadecimal. This is a task I occasionally need to perform, and I wanted
a simple tool which covered the common cases so I don't have to write this
code again and again.


The hexadecimal data given will be read regardless of whitespace
or separator characters to attempt to support the widest range of use cases.
The hexadecimal output is configurable to allow a separator, an optional '0x' prefix,
hex words split into groups, and mulitple rows of a given number of bytes of data.

# Usage
Parcel has two distinct modes- bin and hex- and must be provided a mode on the
command line. In bin mode, a binary file is created, and in hex mode a text
file containing hexadecimal numbers is created.


```shell
parcel 0.1
Noah Ryan
Binary to Hex, Hex to Binary Converter

USAGE:
    parcel [FLAGS] [OPTIONS] --input <FILE> --output <OUTFILE>

FLAGS:
    -l, --lowercase    Print hex in lowercase (default is UPPERCASE)
    -p, --prefix       Print hex with the '0x' prefix before each word, if printing with separated words
    -h, --help         Prints help information
    -V, --version      Prints version information

OPTIONS:
    -i, --input <FILE>              Input file to convert
    -m, --mode <MODE>               The target format, either 'hex' or 'bin
    -o, --output <OUTFILE>          Output file
    -r, --row-width <ROWWIDTH>      Row length in decoded bytes when decoding binary into hex
    -s, --sep <SEPARATOR>           String separator between words [default:  ]
    -w, --word-width <WORDWIDTH>    Number of bytes to decode between separators on a line. Defaults to no separators.
```

## Encoding
Given the following file of hexadecimal numbers in a file called numbers.hex:
```text
0123456789ABCDEF
```

run the following command to encode them to binary:
```shell
parcel -i numbers.hex -o numbers.bin -m bin
```

To get the file (as viewed with xxd):
```text
00000000: 0123 4567 89ab cdef                      .#Eg....
```


Encoding has no flags to control the process- hex numbers are taken from a file,
skipping unrelated characters like whitespaces. One thing to be careful of
is that parcel will attempt to encode any characters that look like hex,
so the word 'Become" will be encoded as 0xBCEE (the non-hex characters are ignored).


Another example of a file that parcel will accept is:
```text
0x0123 0x4567
0x89AB
0xCDEF
```
Where parcel will notice the '0x' characters together and ignore them.


## Decoding
When decoding binary data into hex digits, parcel provides a number of options.

Using the example binary file (as viewed by xxd):
```text
00000000: 0123 4567 89ab cdef                      .#Eg....
```

These options control whether the result is a single sequence of characters:
```shell
parcel -i numbers.bin -o numbers.txt -m hex
```

resulting in:

```text
0123456789ABCDEF
```

This can be modified to, say, print 2 bytes as a word, prefixed by 0x,
with 4 bytes per line.

```shell
parcel -i numbers.bin -o numbers.txt -m hex -p -w 2 -r 4
```

resulting in:
```text
0X0123 0X4567
0X89AB 0XCDEF
```


Another example would be each byte separated by a comma, no prefix, all on one line:
```shell
parcel -i numbers.bin -o numbers.txt -m hex -w 1 -s ", "
```

```text
01, 23, 45, 67, 89, AB, CD, EF
```


# Installation
Parcel can be installed through 'cargo' with:
```shell
cargo install parcel
```

or it can be installed by retrieving binaries from https://github/nsmryan/parcel/releases.


# License
Parcel is licensed under either the MIT License or the APACHE 2.0 License,
whichever you prefer.
