/// For example, the human friendly byte strings
///
/// "0C 04 4A6F686E" encodes
/// UTF8String, length 4, "John"; and
///
/// "02 01 19" encodes
/// INTEGER, length 1, 25.
fn _decode_human(s: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
    let clean: String = s.chars().filter(|x| !x.is_whitespace()).collect();

    let n = 2;
    (0..(clean.len()))
        .step_by(n)
        .map(|i| u8::from_str_radix(&clean[i..(i + n)], 16))
        .collect()
}

fn _parse(tlv: &[u8]) -> Option<i64> {
    let l = tlv.get(1).expect("wrong input length");
    println!("expect get len ok: {:?}", l);
    // ?? expect int or string tag, valuate return generic
    // let tag_byte = tlv.get(0).expect("empty input");
    // match tag_byte {
    //     b"02" => Some()
    //     _ => 
    // }
    // match l {
    //     _ => Some(0)
    // }
    Some(0)
}

/// 255 -> '01 FF'
fn _as_tlv_bytes(_num: u8) -> Vec<u8> {
    vec![]
}

fn main() {
    let _cli = Cli::parse();
    println!("yyy");
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_1() {
        match _parse(&_decode_human("0C 04 4A6F686E").unwrap()) {
            None => assert!(false),
            _ => {}
        }
    }
}

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Encode(CommandOptions),
    Decode(CommandOptions),
}

#[derive(Parser)]
struct CommandOptions {
    input_file: PathBuf,
    #[clap(short, help = "Basic Encoding Rule")]
    ber: bool,
    #[clap(short, help = "")]
    der: bool
}
