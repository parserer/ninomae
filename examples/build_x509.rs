#![allow(dead_code)]
#![allow(unused_imports)]
use std::fmt;
use base64::prelude::*;

#[derive(Debug)]
struct Error;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "todo")
    }
}

/// Fields defined in version 3 of X.509.
#[derive(Default)]
struct CertificateData {
    version: u8,
    signature_algo: String
}

trait Encode {
    /// ## DER extensions to BER
    /// - Length encoding must use the definite form. Additionally, the shortest possible length encoding must be used.
    /// - Bitstring, octetstring, and restricted character strings must use the primitive encoding.
    /// - Elements of a Set are encoded in sorted order, based on their tag value.
    fn as_der(&self) -> &[u8];
}

impl Encode for CertificateData {
    fn as_der(&self) -> &[u8] {
        b"sha256WithRSAEncryption"
        // b""
    }
}

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
        assert_eq!(der::encode(435), vec![130, 1, 179]);
    }
}

mod der {
    use itertools::Itertools;
    use super::*;

    pub fn encode(length: u64) -> Vec<u8> {
        if length < 128 {
            // Return one-element vector of bytes.
            vec![length as u8]
        } else {
            // Long form consists of at least 3 bytes.
            let length_octets_str = format!("{length:b}");
            let n = div_ceil(length_octets_str.len() as u64, 8);
            let o1 = u8::from_str_radix(&format!("1{n:07b}"), 2).expect("ineffective magic string format");

            {
                let mut v = vec![o1];
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
    let ss = der::encode(435);
    println!("dbg: {:?}", ss);
    for b in ss {
        println!("i: {:08b}", b);
    }
    // let input = CertificateData::default();
    // println!(
    //     "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
    //     BASE64_STANDARD.encode(input.as_der()));
}
