#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unreachable_code)]
use std::fmt;
use std::collections::HashMap;
use std::convert::{From, Into, TryFrom};
use std::slice::IterMut;
use base64::prelude::*;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Debug)]
struct Error(&'static str);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "todo")
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum Data {
    Integer(i64),
    VisibleString(String),
    Sequence(Vec<Data>),
    True,
    False,
    Null
}

/// Fields defined in version 3 of X.509.
#[derive(Debug, Default)]
struct CertificateData {
    version: u8,
    signature_algo: String
}

// ?? rules for mapping of record fields are at X680 doc
// 60 <l>
//        42 01 03
//        A0 0A 1A 08 "Director"
/// ```
/// let encoded: Bytes = CertificateData::default().into();
/// ```
impl Into<Bytes> for CertificateData {
    fn into(self) -> Bytes {
        use Data::*;
        let version = der::encode(&Integer(self.version.into()));
        let signature_algo = der::encode(&VisibleString(self.signature_algo));
        let contents: Vec<u8> = [
            &[0x42, 3u8], &version[..],
            &[0xA0, 3u8], &signature_algo[..] ].concat();
        let mut res = Bytes(contents);
        res.slap_tag(0x60);
        res
    }
}

/// ```
/// let decoded = CertificateData::from(vec![0_u8]).unwrap();
/// ```
impl TryFrom<&mut Vec<u8>> for CertificateData {
    type Error = Error;

    fn try_from(bytes: &mut Vec<u8>) -> Result<Self, Self::Error> {
        let bytes_iter = bytes.iter_mut();

        // bytes_iter.next();
        // bytes_iter.next();

        let (version, signature_algo) = {
            (0, String::new())
        };

        Ok(CertificateData { version, signature_algo })
    }
}

// ?? presumably we only need this until we have the asn1 spec compiler
fn parse_certificate_record(contents: Vec<u8>) -> HashMap<&'static str, Data> {
    // PICKUP non programmatically assign names to tlvs
    unimplemented!()
}

impl TryFrom<&mut Bytes> for CertificateData {
    type Error = Error;

    fn try_from(bytes: &mut Bytes) -> Result<Self, Self::Error> {
        let tag: Vec<_> = bytes.0.drain(..1).collect();
        // ?? multi-byte length  fn decode_length
        let length: Vec<_> = bytes.0.drain(..1).collect();

        let contents: Vec<_> = bytes.0.drain(..(length[0] as usize)).collect();

        let m = parse_certificate_record(contents);
        let (d1, d2) = match (m.get("version"), m.get("signature_algo")) {
            (Some(d1_ref), Some(d2_ref)) => (d1_ref.clone(), d2_ref.clone()),
            _ => return Err(Error("todo"))
        };

        match (d1, d2) {
            (Data::Integer(z), Data::VisibleString(signature_algo)) => Ok(CertificateData { version: z as u8, signature_algo }),
            _ => Err(Error("todo"))
        }
    }
}

#[derive(Debug)]
enum Tag {
    Eoc,
    Bool,
    Int,
    Seq
}

impl Into<u8> for Tag {
    fn into(self) -> u8 {
        match self {
            Tag::Eoc => 0,
            Tag::Bool => 1,
            Tag::Int => 2,
            Tag::Seq => 0x30
        }
    }
}

impl TryFrom<u8> for Tag {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Tag::Eoc),
            1 => Ok(Tag::Bool),
            2 => Ok(Tag::Int),
            _ => Err("unexpected Tag byte")
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
    // #[test]
    // fn test_pad() {
    //     assert_eq!(pad("111").len(), 8);
    //     assert_eq!(pad("101010101").len(), 16);
    // }

mod tests {
    use super::*;
    use Data::*;
    use test_log::test;
    use proptest::prelude::*;

    fn decodew(input: Vec<u8>) -> Data {
        der::decode(input).unwrap()
    }
    fn encodew(input: Data) -> Vec<u8> {
        der::encode(&input)
    }

    // ok:
    // proptest! {
    //     #[test]
    //     fn roundtrip(z: i64) {
    //         prop_assert_eq!(
    //             Data::Integer(z),
    //             decodew(encodew(Data::Integer(z))));
    //     }
    // }


    #[test]
    fn test_roundtrip() {
        assert_eq!(
            der::decode(der::encode(&False)),
            Ok(False));
        assert_eq!(
            der::decode(der::encode(&True)),
            Ok(True));
        assert_eq!(
            der::decode(der::encode(&Integer(255))),
            Ok(Integer(255)));
        assert_eq!(
            der::decode(der::encode(&Integer(0))),
            Ok(Integer(0)));
    }

    #[test]
    fn test_div_ceil() {
        assert_eq!(div_ceil(10, 4), 3);
        assert_eq!(div_ceil(10, 2), 5);
        assert_eq!(div_ceil(2, 10), 1);
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
    }
}

struct Bytes(Vec<u8>);
impl Bytes {
    fn slap_tag(&mut self, tag: u8) {
        self.0.insert(0, self.0.len() as u8);
        self.0.insert(0, tag);
    }
}

mod der {
    use itertools::Itertools;
    use super::*;
    use Data::*;

    pub fn encode(data: &Data) -> Vec<u8> {
        match data {
            True => vec![Tag::Bool.into(), 1, 0xFF],
            False => vec![Tag::Bool.into(), 1, 0],
            Integer(z) => encode_int(*z),
            VisibleString(s) => encode_restricted_str(s),
            Null => vec![5, 0],
            Sequence(ds) => {
                let contents: Vec<_> = ds.iter().map(encode).flatten().collect();
                [&[Tag::Seq.into(), contents.len() as u8], &contents[..]].concat()
            },
        }
    }

    // negative shall be two's complement
    // if contents.len() > 1: 1st octet and bit 8 of 2nd octet shall not be all ones or all zeros
    // ?? property check
    /// - [ ] [8.3.2] "... always encoded in the smallest possible number of octets."
    fn encode_int(data: i64) -> Vec<u8> {
        // ?? test this predicate
        if data.abs() < 255 {
            // Small positives and fit in 1 octet.
            vec![Tag::Int.into(), 1, data as u8]
        } else {
            // Informally, two's complement means "flipping, adding 1, ignoring overflow". This
            // happens to be how Rust represent numbers in memory; implementation of the spec's
            // rule for encoding signed integer is the following one line.
            let byte_array = data.to_be_bytes();

            // [&[Tag::Int.into(), byte_array.len() as u8], &byte_array[..]].concat()
            let res = [&[Tag::Int.into(), byte_array.len() as u8], &byte_array[..]].concat();
            println!("res: {:?}", res);
            res
        }
    }

    pub fn encode_restricted_str(data: &str) -> Vec<u8> {
        // ?? assume ascii
        // VisibleString primitive
        let contents = data.as_bytes();
        [&[0x1A, contents.len() as u8], &contents[..]].concat()
    }

    fn as_array_of_8(contents: &mut Vec<u8>) -> Result<[u8; 8], &'static str> {
        if contents.len() != 8 {
            // Pad left if short; cut left if long.
            contents.reverse();
            contents.resize(8, 0);
            contents.reverse();
        }
        Ok(contents[..].try_into().expect("correct length"))
    }

    pub fn decode(mut bytes: Vec<u8>) -> Result<Data, &'static str> {
        let mut bytes_iter = bytes.iter().peekable();

        let tag = match bytes_iter.next_if(|&x| Tag::try_from(*x).is_ok()) {
            None => return Err("tag"),
            tag_ref => *tag_ref.unwrap()
        };

        let length = match bytes_iter.next() {
            None => return Err("length"),
            Some(x) => *x as usize
        };

        // Destructure collected `bytes_iter` iterator into
        // `[contents: [u8;length], bytes]`.
        let mut contents: Vec<u8> = bytes_iter.map(|x| *x).collect();
        let _ = std::mem::replace(&mut bytes, contents.drain(length..).collect());

        match tag {
            0x1 => {
                match contents.get(0) {
                    Some(0x0) => Ok(False),
                    _ => Ok(True),
                }
            }
            0x2 => {
                let arr = as_array_of_8(&mut contents)?;
                Ok(Integer(i64::from_be_bytes(arr)))
            }
            _ => Err("else")
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
    let subscriber = FmtSubscriber::builder()
        // all spans/events with a level higher than TRACE (e.g, debug, info, warn, etc.)
        // will be written to stdout.
        .with_max_level(Level::TRACE)
        // completes the builder.
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");

    info!("preparing to shave yaks");

    let cd = CertificateData {
        version: 3,
        signature_algo: String::from("sha")
    };
    let mut encoded: Bytes = cd.into();
    let decoded = CertificateData::try_from(&mut encoded);
    println!("dec: {:?}", decoded);

    // for byt in ("J😭ones").as_bytes() {
    //     print!("{:x}", byt);
    // }
    // println!("");
    // for byt in der::encode_restricted_str("J😭ones") {
    //     print!("{:x}", byt);
    // }
    // println!("");

    // for b in ss {
    //     println!("i: {:08b}", b);
    // }
    // let input = CertificateData::default();
    // println!(
    //     "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
    //     BASE64_STANDARD.encode(input.as_der()));
}
