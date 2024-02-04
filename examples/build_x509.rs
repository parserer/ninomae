#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unreachable_code)]
use std::fmt;
use std::convert::{From, Into, TryFrom};
use base64::prelude::*;

#[derive(Debug)]
struct Error;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "todo")
    }
}

#[derive(Debug, PartialEq)]
pub enum Data {
    Integer(i64),
    VisibleString(String),
    Sequence(Vec<Data>),
    True,
    False,
    Null
}

/// Fields defined in version 3 of X.509.
#[derive(Default)]
struct CertificateData {
    version: u8,
    signature_algo: String
}

/// ```
/// let encoded: Vec<u8> = CertificateData::default().into();
/// ```
impl Into<Vec<u8>> for CertificateData {
    fn into(self) -> Vec<u8> {
        use Data::*;
        // let version = der::encode_int(self.version.into());
        let signature_algo = der::encode(&VisibleString(self.signature_algo));
        signature_algo
    }
}

/// ```
/// let decoded = CertificateData::from(vec![0_u8]);
/// ```
impl From<Vec<u8>> for CertificateData {
    fn from(mut data: Vec<u8>) -> Self {
        // assert (?? while consuming) struct tag, maybe len
        let data_iter = data.iter_mut();
        // CertificateData {
        //     version: data_iter.take(n) |> der::decode
        //     signature_algo: data_iter.take(n) |> der::decode
        // }
        unimplemented!()
    }
}

#[derive(Debug)]
enum Tag {
    Eoc,
    Boolean,
    Int
}
impl Tag {
    fn len(&self) -> usize {
        match self {
            Self::Boolean => 1,
            _ => unimplemented!()
        }
    }
}

// trait Encode {
//     /// ## DER extensions to BER
//     /// - Length encoding must use the definite form. Additionally, the shortest possible length encoding must be used.
//     /// - Bitstring, octetstring, and restricted character strings must use the primitive encoding.
//     /// - Elements of a Set are encoded in sorted order, based on their tag value.
//     fn as_der(&self) -> &[u8];
// }

fn div_ceil(n: u64, other: u64) -> u64 {
    // 10 / 4 = 2 | 2.5 | 3
    let quo: u64 = n / other;  // 2
    let div: f64 = (n as f64) / (other as f64);  // 2.5
    if div > (quo as f64) {
        quo + 1  // 3
    } else {
        quo
    }
}

/// Leftpad string with "0" until its length is a multiple of 8.
fn pad(src: &str) -> String {
    // "111" len 3.                 (3 /^ 8) * 8 - 3 -> leftpad 5
    // "11100000000000000" len 17.  (17 /^ 8) * 8 - 17 -> leftpad 7
    let zeros = {
        let n = div_ceil(src.len() as u64, 8) * 8 - (src.len() as u64);
        "0".repeat(n as usize)
    };
    format!("{zeros}{src}")
}

mod tests {
    use super::*;
    use Data::*;

    #[test]
    fn test_roundabout() {
        assert_eq!(
            der::decode(der::encode(&False)),
            Some(False));
        assert_eq!(
            der::decode(der::encode(&True)),
            Some(True));
        assert_eq!(
            der::decode(der::encode(&Integer(11))),
            Some(Integer(11)));
    }

    #[test]
    fn test_div_ceil() {
        assert_eq!(div_ceil(10, 4), 3);
        assert_eq!(div_ceil(10, 2), 5);
        assert_eq!(div_ceil(2, 10), 1);
    }
    #[test]
    fn test_pad() {
        assert_eq!(pad("111").len(), 8);
        assert_eq!(pad("101010101").len(), 16);
    }
    #[test]
    fn der_encode_length() {
        assert_eq!(der::encode_length(1), vec![1]);
        assert_eq!(der::encode_length(435), vec![130, 1, 179]);
    }
    #[test]
    fn bool_sequence() {
        assert_eq!(
            der::encode(&Sequence(vec![False, True])),
            vec![0x30, 6, 1, 1, 0x0, 1, 1, 0xFF]);
    }
    #[test]
    fn test_encode_int() {
        assert_eq!(
            der::encode(&Integer(2)),
            vec![2, 1, 0x2]);

        assert_eq!(
            der::encode(&Integer(-2)),
            vec![2, 1, 0b11111110]);

    }
    #[test]
    fn str_sequence() {
        // assert_eq!(
        der::encode(&Sequence(vec![VisibleString("Jones".into()), VisibleString("1230".into())]));
        // ?? impl Debug to print 0x not decimal
    }
}

// enum Contents {
//     Bytes(Vec<u8>),
//     Nested(Seq)
// }
// pub struct Seq {
//     tag: Tag,
//     contents: Box<Contents>
// }
// // well formed Seq has Bytes as inner most. like cons

mod der {
    use itertools::Itertools;
    use super::*;
    use Data::*;

    pub fn encode(data: &Data) -> Vec<u8> {
        match data {
            True => vec![1, 1, 0xFF],
            False => vec![1, 1, 0],
            Integer(z) => encode_int(*z),
            VisibleString(s) => encode_restricted_str(s),
            Null => vec![5, 0],
            Sequence(ds) => {
                let contents: Vec<_> = ds.iter().map(encode).flatten().collect();
                // ?? magic  Data::False.into()
                [&[0x30, contents.len() as u8], &contents[..]].concat()
            },
        }
    }

    // negative shall be two's complement
    // if contents.len() > 1: 1st octet and bit 8 of 2nd octet shall not be all ones or all zeros
    // ?? property check
    fn encode_int(data: i64) -> Vec<u8> {
        if data < 255 {  // if positive and fits in 1 octet
            // ?? magic
            vec![2, 1, data as u8]
        } else {
            // Informally, two's complement means "flipping, adding 1, ignoring overflow". This
            // happens to be how Rust represent numbers in memory; implementation of the spec's
            // rule for encoding signed integer is the following one line.
            let byte_array = data.to_be_bytes();

            [&[2, byte_array.len() as u8], &byte_array[..]].concat()
        }
    }

    pub fn encode_restricted_str(data: &str) -> Vec<u8> {
        // ?? assume ascii
        // VisibleString primitive
        let contents = data.as_bytes();
        [&[0x1A, contents.len() as u8], &contents[..]].concat()
    }

    pub fn decode(bytes: Vec<u8>) -> Option<Data> {
        match bytes.first() {
            Some(1) => {
                if *bytes.get(2).expect("todo") == 0 {
                    return Some(False);
                }
                // ?? length, contents skipped
                Some(True)
            }
            Some(2) => {
                let contents: [u8; 1] = (&bytes[2..]).try_into().expect("todo");

                Some(Integer(u8::from_be_bytes(contents).into()))
            }
            _ => unimplemented!()
        }
    }

    pub fn encode_string(data: String) -> Vec<u8> {
        vec![]
    }
    pub fn encode_length(data: u64) -> Vec<u8> {
        if data < 128 {
            // Return one-element vector of bytes.
            vec![data as u8]
        } else {
            // Long form consists of at least 3 bytes.
            let length_octets_str = format!("{data:b}");
            let n = div_ceil(length_octets_str.len() as u64, 8);

            {
                let mut v = vec![
                    u8::from_str_radix(&format!("1{n:07b}"), 2).expect("ineffective magic string format")
                ];
                for chunk in &pad(&length_octets_str).chars().chunks(8) {
                    let octet = String::from_iter(chunk);
                    v.push(u8::from_str_radix(&octet, 2).expect("ineffective magic string format"));
                }
                v
            }
        }
    }
}

/// Write result string to standard output.
///
/// ## Testing
/// ```sh
/// cargo r --example build_x509 > out.pem && cat out.pem
/// ```
fn main() {
    let zz = der::decode(vec![2, 1, 0x2]);
    let xx: Vec<u8> = vec![0x30];
    // println!("{:08b}", (0i8).to_be_bytes()[0]);
    for byt in ("J😭ones").as_bytes() {
        print!("{:x}", byt);
    }
    println!("");
    for byt in der::encode_restricted_str("J😭ones") {
        print!("{:x}", byt);
    }
    println!("");
    for byt in (-1i64).to_be_bytes() {
        print!("{:b}", byt);
    }
    println!("");

    // for b in ss {
    //     println!("i: {:08b}", b);
    // }
    // let input = CertificateData::default();
    // println!(
    //     "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
    //     BASE64_STANDARD.encode(input.as_der()));
}
