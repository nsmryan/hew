extern crate clap;

use std::io::{Write, Read, BufReader};
use std::fs::OpenOptions;
use std::path::Path;

use clap::{App, Arg, ArgMatches};


const NIBBLE_TO_HEX_UPPER: [char; 16] = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'E', 'D', 'F'];
const NIBBLE_TO_HEX_LOWER: [char; 16] = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'e', 'd', 'f'];

#[derive(Copy, Clone, PartialEq)]
enum LineWidth {
    Width(usize),
    Unlimited,
}

impl LineWidth {
    pub fn is_end_of_line(&self, pos: usize) -> bool {
        match self {
            LineWidth::Width(chars_in_line) => pos == *chars_in_line,

            LineWidth::Unlimited => false,
        }
    }
}

#[derive(Copy, Clone, PartialEq)]
enum WordWidth {
    Chars(usize),
    Unlimited,
}

impl WordWidth {
    pub fn is_end_of_word(&self, pos: usize) -> bool {
        match self {
            WordWidth::Chars(chars_in_word) => (pos % *chars_in_word) == 0,

            WordWidth::Unlimited => false,
        }
    }
}

#[derive(Copy, Clone, PartialEq)]
enum Prefixed {
    NoPrefix,
    HexPrefix,
}

#[derive(Copy, Clone, PartialEq)]
enum Mode {
    Bin,
    Hex,
}

#[derive(Copy, Clone, PartialEq)]
enum Case {
    Upper,
    Lower,
}


fn main() {
    let matches = App::new("hew")
        .version("0.2")
        .author("Noah Ryan")
        .about("Binary to Hex, Hex to Binary Converter")
        .arg(Arg::with_name("FILE")
                  .help("Input file to convert")
                  .short("i")
                  .long("input")
                  .required(true)
                  .multiple(false)
                  .empty_values(false))
        .arg(Arg::with_name("OUTFILE")
                  .help("Output file")
                  .short("o")
                  .long("output")
                  .required(true)
                  .multiple(false)
                  .empty_values(false))
        .arg(Arg::with_name("MODE")
                  .help("The target format, either 'hex' or 'bin")
                  .short("m")
                  .long("mode")
                  .empty_values(false))
        .arg(Arg::with_name("ROWWIDTH")
                  .help("Row length in decoded bytes when decoding binary into hex")
                  .short("r")
                  .long("row-width")
                  .required(false)
                  .multiple(false)
                  .empty_values(false))
        .arg(Arg::with_name("WORDWIDTH")
                  .help("Number of bytes to decode between separators on a line. Defaults to no separators.")
                  .short("w")
                  .long("word-width")
                  .required(false)
                  .multiple(false)
                  .empty_values(false))
        .arg(Arg::with_name("SEPARATOR")
                  .help("String separator between words")
                  .short("s")
                  .long("sep")
                  .default_value(" ")
                  .required(false))
        .arg(Arg::with_name("LOWER")
                  .help("Print hex in lowercase (default is UPPERCASE)")
                  .short("l")
                  .long("lowercase")
                  .required(false)
                  .multiple(false))
        .arg(Arg::with_name("PREFIX")
                  .help("Print hex with the '0x' prefix before each word, if printing with separated words")
                  .short("p")
                  .long("prefix")
                  .required(false)
                  .multiple(false))
        .get_matches();

    run(matches);
}

fn check_file(filename: &String) {
    if !Path::new(filename).exists() {
        println!("File '{}' not found!", filename);
        std::process::exit(1);
    }
}

fn hexchar_to_byte(hex_char: char) -> u8 {
    if hex_char.is_ascii_digit() {
        hex_char as u8 - '0' as u8
    } else {
        hex_char.to_ascii_lowercase() as u8 - 'a' as u8 + 10
    }
}

fn hex_to_byte(hex_pair: [char; 2]) -> u8 {
    (hexchar_to_byte(hex_pair[0]) << 4) | 
    (hexchar_to_byte(hex_pair[1]) << 0)
}

fn byte_to_hex(byte: u8, case: Case) -> [char; 2] {
    let mut hex_pair: [char; 2] = ['0'; 2];

    match case {
        Case::Upper => {
            hex_pair[0] = NIBBLE_TO_HEX_UPPER[((byte & 0x0F) >> 0) as usize];
            hex_pair[1] = NIBBLE_TO_HEX_UPPER[((byte & 0xF0) >> 4) as usize];
        },

        Case::Lower => {
            hex_pair[0] = NIBBLE_TO_HEX_LOWER[((byte & 0x0F) >> 0) as usize];
            hex_pair[1] = NIBBLE_TO_HEX_LOWER[((byte & 0xF0) >> 4) as usize];
        },
    }

    hex_pair
}

fn encode<R: Read, W: Write>(mut input: R, mut output: W) {
    let mut hex_pair: [char; 2] = ['0'; 2];
    let mut byte: [u8; 1] = [0; 1];

    let mut next_index = 0;

    while let Ok(bytes) = input.read(&mut byte) {
        if bytes != 1 {
            break;
        }

        let chr = byte[0] as char;
        if chr.is_ascii_hexdigit() {
            hex_pair[next_index] = chr;
            next_index = (next_index + 1) % 2;

            if (next_index % 2) == 0 {
                byte[0] = hex_to_byte(hex_pair);
                output.write(&mut byte).expect("Error writing byte!");
            }
        } else if next_index == 1 && 
                  chr == 'x' &&
                  hex_pair[0] == '0' {
            next_index = 0;
        }
    }
}

fn decode<R: Read, W: Write>(mut input: R,
                             mut output: W,
                             line_width: LineWidth,
                             word_width: WordWidth,
                             case: Case,
                             prefix: Prefixed,
                             sep: &str) {
    let mut chars_in_line: usize = 0;

    let mut byte: [u8; 1] = [0; 1];
    let mut hex_str = String::with_capacity(2);

    while let Ok(num_bytes_read) = input.read(&mut byte) {
        if num_bytes_read != 1 {
            break;
        }

        if word_width.is_end_of_word(chars_in_line) && !(chars_in_line == 0) {
            output.write_all(sep.as_bytes()).expect("Error writing separator!");
        }

        if (word_width.is_end_of_word(chars_in_line) || chars_in_line == 0) &&
           prefix == Prefixed::HexPrefix {
            output.write_all(b"0x").expect("Error writing prefix '0x'!");
        }

        let hex_pair = byte_to_hex(byte[0], case);
        hex_str.clear();
        hex_str.push(hex_pair[0]);
        hex_str.push(hex_pair[1]);
        output.write_all(&hex_str.as_bytes()).unwrap();

        chars_in_line += 1;


        if line_width.is_end_of_line(chars_in_line) {
            output.write_all(b"\n").expect("Error writing newline!");
            chars_in_line = 0;
        }
    }
}


fn run(matches: ArgMatches) {
    let filename = matches.value_of("FILE").unwrap().to_string();
    check_file(&filename);

    let outfilename = matches.value_of("OUTFILE").unwrap();

    let mode;
    match matches.value_of("MODE").unwrap() {
        "hex" => mode = Mode::Hex,
        "bin" => mode = Mode::Bin,
        modestr => {
            println!("Mode was '{}', expected 'hex' or 'bin'!", modestr);
            std::process::exit(1);
        }
    }

    let width = if matches.is_present("ROWWIDTH") {
        let line_width = matches.value_of("ROWWIDTH")
                                .unwrap()
                                .parse()
                                .expect("Could not parse given row width!");
        LineWidth::Width(line_width)
    } else {
        LineWidth::Unlimited
    };

    let word_width = if matches.is_present("WORDWIDTH") {
        WordWidth::Chars(matches.value_of("WORDWIDTH").unwrap().parse().unwrap())
    } else {
        WordWidth::Unlimited
    };

    let sep = matches.value_of("SEPARATOR").unwrap();

    let case = if matches.is_present("LOWER") {
        Case::Lower
    } else {
        Case::Upper
    };

    let prefix = if matches.is_present("PREFIX") {
        Prefixed::HexPrefix
    } else {
        Prefixed::NoPrefix
    };

    let input_file = OpenOptions::new()
                       .read(true)
                       .open(filename)
                       .expect("Could not open input file!");
    let input_file = BufReader::new(input_file);

    let output_file = OpenOptions::new()
                        .write(true)
                        .create(true)
                        .append(false)
                        .truncate(true)
                        .open(outfilename)
                        .expect("Could not open output file!");

    match mode {
        Mode::Hex => {
            decode(input_file, output_file, width, word_width, case, prefix, sep);
        }

        Mode::Bin => {
            encode(input_file, output_file);
        }
    }
}
