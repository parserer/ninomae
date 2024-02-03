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

#[derive(Debug)]
pub enum Data {
    Integer(i64),
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

static EMPTY: D = D::Contents(vec![]);

// encode  ??
// let bytes: Vec<u8> = cd.into();
impl Into<Vec<u8>> for CertificateData {
    fn into(self) -> Vec<u8> {
        // let version = der::encode_int(self.version.into());
        let signature_algo = der::encode_string(self.signature_algo);
        unimplemented!()
    }
}

impl<'a> From<CertificateData> for Tlv<'a> {
    fn from(data: CertificateData) -> Tlv<'a> {
        // let version = der::encode_int(data.version.into());
        let signature_algo = der::encode_string(data.signature_algo);

        Tlv {
            tag: Tag::Eoc,
            value: &EMPTY
        }
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

#[derive(Debug)]
enum D<'a> {
    Contents(Vec<u8>),
    Value(&'a Tlv<'a>)
}
impl D<'_> {
    fn len(&self) -> usize {
        match self {
            Self::Contents(d) => d.len(),
            Self::Value(d) => d.len()
        }
    }
}
#[derive(Debug)]
pub struct Tlv<'a> {
    tag: Tag,
    value: &'a D<'a>
}
impl<'a> Tlv<'a> {
    fn default() -> Self {
        Tlv {
            tag: Tag::Eoc,
            value: &EMPTY
        }
    }
    fn len(&self) -> usize {
        self.tag.len() + self.value.len()
    }
}

/// Parser
///
/// ```
/// let tlv = Tlv::try_from(bytes)?;
/// ```
impl TryFrom<Vec<u8>> for Tlv<'_> {
    type Error = ();
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let mut bytes = value.iter();
        bytes.next();
        Ok(Tlv::default())
    }
}


// let bytes: Vec<u8> = tlv.into();
impl Into<Vec<u8>> for Tlv<'_> {
    fn into(self) -> Vec<u8> {
        unimplemented!()
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

    // #[test]
    // fn test_roundabout() {
    //     assert_eq!(der::decode(vec![2, 1, 11]), 11);
    //     assert_eq!(der::decode(der::encode_int(11)), 11);
    //     // assert_eq!(der::decode(der::encode_true()), true);
    // }

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
    fn der_encode() {
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

        // assert_eq!(
        //     der::encode(&Integer(-2)),
        //     vec![]);

        // assert_eq!(
        //     der::encode(&Sequence(vec![Integer(12), Integer(12)])).len(),
        //     18);
    }
}

enum Contents {
    Bytes(Vec<u8>),
    Nested(Seq)
}
pub struct Seq {
    tag: Tag,
    contents: Box<Contents>
}
// well formed Seq has Bytes as inner most. like cons

mod der {
    use itertools::Itertools;
    use super::*;

    pub fn encode(data: &Data) -> Vec<u8> {
        use Data::*;
        match data {
            True => vec![1, 1, 0xFF],
            False => vec![1, 1, 0],
            Integer(z) => encode_int(*z),
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
            // Intuitively, two's complement means "flipping, adding 1, ignoring overflow". This
            // happens to be how Rust represent numbers in memory; implementation of the spec's
            // rule for encoding signed integer is the following one line.
            let byte_array = data.to_be_bytes();

            [&[2, byte_array.len() as u8], &byte_array[..]].concat()
        }
    }

    fn encode_bitstring(data: &str) -> Vec<u8> {
        unimplemented!()
    }

    pub fn decode(bytes: Vec<u8>) -> Data {
        match bytes.first() {
            Some(1) => unimplemented!(),
            Some(2) => {
                let contents = &bytes[2..];
                Data::Integer(contents[0].into())
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

    let tt = Tlv {
        tag: Tag::Boolean,
        value: &D::Contents(vec![9])
    };
    println!("tt: {:?}", tt);
    println!("len: {:?}", tt.len());
    // let xx: u8 = 260;
    let xx: Vec<u8> = vec![0x30];
    // println!("{:08b}", (0i8).to_be_bytes()[0]);
    for byt in (0i64).to_be_bytes() {
        print!("{:b}", byt);
    }
    println!("");
    for byt in (-1i64).to_be_bytes() {
        print!("{:b}", byt);
    }
    println!("");

    for byt in (-2i64).to_be_bytes() {
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
