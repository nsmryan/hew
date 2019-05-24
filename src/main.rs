extern crate clap;
extern crate crossbeam;

use std::io::{Write, Read, BufReader, BufWriter};
use std::fs::OpenOptions;
use std::path::Path;
#[cfg(feature = "flame")]use std::fs::File;

#[cfg(test)] use std::io::Cursor;
#[cfg(feature = "flame")] use flame::*;

use crossbeam::thread::*;
use crossbeam::channel::*;

use clap::{App, Arg, ArgMatches};


const WRITE_BUFFER_SIZE_BYTES: usize =  1024*16;
const READ_BUFFER_SIZE_BYTES: usize =  1024*128;

const NIBBLE_TO_HEX_UPPER: [char; 16] =
    ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'];

const NIBBLE_TO_HEX_LOWER: [char; 16] =
    ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'];

#[derive(Clone, PartialEq)]
struct Msg(Vec<u8>, Vec<u8>);

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
    let translation;

    match case {
        Case::Upper => {
            translation = &NIBBLE_TO_HEX_UPPER;
        },

        Case::Lower => {
            translation = &NIBBLE_TO_HEX_LOWER;
        },
    }

    hex_pair[0] = translation[((byte & 0xF0) >> 4) as usize];
    hex_pair[1] = translation[((byte & 0x0F) >> 0) as usize];

    hex_pair
}

fn buffered<R, W, F>(mut input: R, mut output: W, f: &F)
    where R: Read + Sync + Send,
          W: Write,
          F: Fn(&mut [u8], &mut Vec<u8>) + Sync {
    let mut write_buffer: Vec<u8> = vec!();

    let num_threads = 10;

    scope(|s| {
        let (sender, receiver) = bounded::<Msg>(num_threads);
        let (send_result, receive_result) = bounded::<Msg>(num_threads);
        let (recycle_sender, recycle_receive) = bounded::<Msg>(num_threads);

        for _ in 0..num_threads {
            recycle_sender.send(Msg(vec!(), vec!())).unwrap();

            let local_receiver = receiver.clone();
            let local_send_result = send_result.clone();
            let local_f = f.clone();
            s.spawn(move |_| {
                while let Ok(Msg(mut buffer, mut write_buffer)) = local_receiver.recv() {
                    local_f(&mut buffer[..], &mut write_buffer);
                    let result = local_send_result.send(Msg(buffer, write_buffer));
                    if !result.is_ok() {
                        break;
                    }
                }
            });
        }

        // spawn reader thread
        s.spawn(move |_| {
            let mut num_bytes_read = 0;
            let mut buffer: Vec<u8> = vec!(0; READ_BUFFER_SIZE_BYTES);

            num_bytes_read = input.read(&mut buffer).unwrap();
            while num_bytes_read > 0 {
                let Msg(mut buf, mut write_buf) = recycle_receive.recv().unwrap();
                buf.clear();
                write_buf.clear();
                for index in 0..num_bytes_read {
                    buf.push(buffer[index]);
                }

                sender.send(Msg(buf, write_buf)).unwrap();

                num_bytes_read = input.read(&mut buffer).unwrap();
            }
        });

        while let Ok(Msg(buff, write_buff)) = receive_result.recv() {
            output.write(&write_buff).expect("Error writing to output!");
            let result = recycle_sender.send(Msg(buff, write_buff));
            if !result.is_ok() {
                break;
            }
        }
    }).unwrap();
}

fn encode_buffer(buffer: &mut [u8], write_buffer: &mut Vec<u8>) {
    let mut hex_pair: [char; 2] = ['0'; 2];
    let mut byte: [u8; 1] = [0; 1];

    let mut next_index = 0;

    let mut write_index: usize = 0;

    for byte_index in 0..buffer.len() {
        byte[0] = buffer[byte_index];

        let chr = byte[0] as char;
        if chr.is_ascii_hexdigit() {
            hex_pair[next_index] = chr;
            next_index = (next_index + 1) % 2;

            if (next_index % 2) == 0 {
                byte[0] = hex_to_byte(hex_pair);
                write_buffer.push(byte[0]);
            }
        } else if next_index == 1 && 
                  chr == 'x' &&
                  hex_pair[0] == '0' {
            next_index = 0;
        }
    }
}

fn encode<R: Read + Sync + Send, W: Write>(input: &mut R, output: &mut W) {
    buffered(input, output, &encode_buffer);
}

#[test]
fn test_encode_upper_case() {
    // upper case
    let input = "0123456789ABCDEF";
    let mut output = Vec::with_capacity(input.len());

    encode(input.as_bytes(), &mut output);
    assert_eq!(output, vec!(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF));
}

#[test]
fn test_encode_lower_case() {
    // lower case
    let input = "0123456789abcdef";
    let mut output = Vec::with_capacity(input.len());

    encode(input.as_bytes(), &mut output);
    assert_eq!(output, vec!(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF));
}

#[test]
fn test_encode_with_whitespace() {
    let input = "01   \n23456789\r\nabcd ef";
    let mut output = Vec::with_capacity(input.len());

    encode(input.as_bytes(), &mut output);
    assert_eq!(output, vec!(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF));
}

#[test]
fn test_encode_with_prefix() {
    let input = "0x010x23450x6789\r\nabcd 0xef";
    let mut output = Vec::with_capacity(input.len());

    encode(input.as_bytes(), &mut output);
    assert_eq!(output, vec!(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF));
}

#[test]
// NOTE this does not test an odd number of hex digits, just an odd number of bytes
fn test_encode_odd_number() {
    let input = "0123456789abcd";
    let mut output = Vec::with_capacity(input.len());

    encode(input.as_bytes(), &mut output);
    assert_eq!(output, vec!(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD));
}

#[test]
fn test_encode_empty() {
    let input = "";
    let mut output = Vec::with_capacity(input.len());

    encode(input.as_bytes(), &mut output);
    assert_eq!(output, vec!());
}

fn decode<R: Read + Sync + Send, W: Write>(input: &mut R,
                             output: &mut W,
                             line_width: LineWidth,
                             word_width: WordWidth,
                             case: Case,
                             prefix: Prefixed,
                             sep: &str) {
    buffered(input, output, &|input, out| {
             decode_buffer(input, out, line_width, word_width, case, prefix, sep);
    });
}

fn decode_buffer(buffer: &[u8],
                 write_buffer: &mut Vec<u8>,
                 line_width: LineWidth,
                 word_width: WordWidth,
                 case: Case,
                 prefix: Prefixed,
                 sep: &str) {
    let mut chars_in_line: usize = 0;
    let mut write_index: usize = 0;

    let mut byte: [u8; 1] = [0; 1];
    let mut hex_bytes: [u8; 2] = [0; 2];

    for byte_index in 0..buffer.len() {
        byte[0] = buffer[byte_index];

        if word_width.is_end_of_word(chars_in_line) && !(chars_in_line == 0) {
            write_buffer.extend_from_slice(sep.as_bytes());
        }

        if (word_width.is_end_of_word(chars_in_line) || chars_in_line == 0) &&
           prefix == Prefixed::HexPrefix {
            write_buffer.extend_from_slice(&b"0x"[..]);
        }

        let hex_pair = byte_to_hex(byte[0], case);
        hex_bytes[0] = hex_pair[0] as u8;
        hex_bytes[1] = hex_pair[1] as u8;
        write_buffer.extend_from_slice(&hex_bytes[..]);

        chars_in_line += 1;

        if line_width.is_end_of_line(chars_in_line) {
            write_buffer.extend_from_slice(&b"\n"[..]);
            chars_in_line = 0;
        }
    }
}

#[test]
fn test_decode_simple() {
  let input = vec!(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF);
  let mut output = Vec::with_capacity(100);

  let line_width = LineWidth::Unlimited;
  let word_width = WordWidth::Unlimited;
  let case = Case::Upper;
  let prefix = Prefixed::NoPrefix;
  let sep = "";

  decode(Cursor::new(input), &mut output, line_width, word_width, case, prefix, &sep);

  assert_eq!(output.into_iter().map(|byte| byte as char).collect::<String>(),
             "0123456789ABCDEF");
}

#[test]
fn test_decode_case() {
  let input = vec!(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF);
  let mut output = Vec::with_capacity(100);

  let line_width = LineWidth::Unlimited;
  let word_width = WordWidth::Unlimited;
  let case = Case::Upper;
  let prefix = Prefixed::NoPrefix;
  let sep = "";

  decode(Cursor::new(input), &mut output, line_width, word_width, case, prefix, &sep);
  assert_eq!(output.into_iter().map(|byte| byte as char).collect::<String>(),
             "0123456789ABCDEF");

  let input = vec!(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF);
  let mut output = Vec::with_capacity(100);
  let case = Case::Lower;
  decode(Cursor::new(input), &mut output, line_width, word_width, case, prefix, &sep);
  assert_eq!(output.into_iter().map(|byte| byte as char).collect::<String>(),
             "0123456789abcdef");
}

#[test]
fn test_decode_words() {
  let input = vec!(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF);
  let mut output = Vec::with_capacity(100);

  let line_width = LineWidth::Unlimited;
  let word_width = WordWidth::Chars(1);
  let case = Case::Upper;
  let prefix = Prefixed::NoPrefix;
  let sep = " ";

  decode(Cursor::new(input), &mut output, line_width, word_width, case, prefix, &sep);
  assert_eq!(output.into_iter().map(|byte| byte as char).collect::<String>(),
             "01 23 45 67 89 AB CD EF");

  let input = vec!(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF);
  let mut output = Vec::with_capacity(100);
  let line_width = LineWidth::Width(2);
  decode(Cursor::new(input), &mut output, line_width, word_width, case, prefix, &sep);
  assert_eq!(output.into_iter().map(|byte| byte as char).collect::<String>(),
             "01 23\n45 67\n89 AB\nCD EF\n");

  let input = vec!(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF);
  let mut output = Vec::with_capacity(100);
  let prefix = Prefixed::HexPrefix;
  decode(Cursor::new(input), &mut output, line_width, word_width, case, prefix, &sep);
  assert_eq!(output.into_iter().map(|byte| byte as char).collect::<String>(),
             "0x01 0x23\n0x45 0x67\n0x89 0xAB\n0xCD 0xEF\n");

  let input = vec!(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF);
  let mut output = Vec::with_capacity(100);
  let sep = ", ";
  decode(Cursor::new(input), &mut output, line_width, word_width, case, prefix, &sep);
  assert_eq!(output.into_iter().map(|byte| byte as char).collect::<String>(),
             "0x01, 0x23\n0x45, 0x67\n0x89, 0xAB\n0xCD, 0xEF\n");
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

    let mut input_file = OpenOptions::new()
                       .read(true)
                       .open(filename)
                       .expect("Could not open input file!");
    let mut input_file = BufReader::new(input_file);

    let mut output_file = OpenOptions::new()
                        .write(true)
                        .create(true)
                        .append(false)
                        .truncate(true)
                        .open(outfilename)
                        .expect("Could not open output file!");

    let mut output_file = BufWriter::new(output_file);


    match mode {
        Mode::Hex => {
            decode(&mut input_file, &mut output_file, width, word_width, case, prefix, sep);
        }

        Mode::Bin => {
            encode(&mut input_file, &mut output_file);
        }
    }

    #[cfg(feature = "flame")]flame::dump_html(&mut File::create("flame-graph.html").unwrap()).unwrap();
}
