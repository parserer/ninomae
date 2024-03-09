
use std::{cell::RefCell, rc::Rc};

use num::{Zero, BigInt};

use serde::{Serialize, Deserialize};


pub type EncodingDataRcel = Rc<RefCell<EncodingData>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodingData{
    pub identifier: Identifier,
    pub length: Option<Length>,
    pub content: Option<Content>,
}
impl EncodingData{
    pub fn new(identifier: Identifier) -> EncodingData{
        EncodingData { identifier, length: None, content: None}
    }
    pub fn is_length_limit_reached(&self) -> bool{
        if let Some(length) = self.length.as_ref() {
            if length.length.is_zero() {return true;}

            if let Some(content) = self.content.as_ref(){
                if length.length <= content.bytes_length(){
                    return true;
                } else {
                    return false;
                }
            } else {
                return false
            }
        }
        return true;
    }
    pub fn bytes_length(&self) -> u32{
        return self.identifier.bytes_length()
            + self.length.as_ref().map_or(0, |l| l.bytes_length())
            + self.content.as_ref().map_or(0, |c| c.bytes_length())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identifier{
    pub class: IdentifierClass,
    pub data_type: DataType,
    pub tag_number: u32
}
impl Identifier  {
    pub fn bytes_length(&self) -> u32{
        if self.tag_number < 31{
            return 1;
        } else {
            // enough if max identifier length is 4 bytes
            return self.tag_number.to_ne_bytes().len() as u32;
        }
    }
}

#[derive(Debug,Clone,PartialEq, Serialize, Deserialize)]
pub enum IdentifierClass{
    Universal,
    Application,
    ContextSpecific,
    Private
}

#[derive(Debug,Clone,PartialEq, Serialize, Deserialize)]
pub enum DataType{
    Primitive,
    Constructed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Length{
    pub length: u32
}
impl Length{
    pub fn new(val : u32)->Length{
        return Length { length: val}
    }

    pub fn get_length_as_usize(&self) -> Option<usize>{
        todo!()
    }
    
    pub fn bytes_length(&self) -> u32{
        return self.length.to_ne_bytes().len() as u32;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Content{
    Primitive(PrimitiveContent),
    Constructed(Vec<EncodingDataRcel>),
    // for data types not yet implemented
    Raw(Vec<u8>)
}
impl Content {
    pub fn bytes_length(&self) -> u32{
        let len = match self {
            Content::Primitive(pc) => pc.bytes_length(),
            Content::Constructed(children) => children.iter().fold(0, |acc, data| acc + data.borrow().bytes_length()),
            Content::Raw(r) => r.len() as u32
        };
        return len
    }
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PrimitiveContent{
    Boolean(bool),
    Integer(BigInt),
    OctetString(Vec<u8>),
    UTF8String(String),
    // byte represents unused bits in last byte, should be between 1-7
    BitString((Vec<u8>, u8)),
    Null,
}
impl PrimitiveContent{
    pub fn bytes_length(&self) -> u32{
        let len = match self {
            PrimitiveContent::Boolean(_) => 1,
            PrimitiveContent::Integer(i) => (i.bits()/8) as u32,
            PrimitiveContent::OctetString(os) => os.len() as u32,
            PrimitiveContent::UTF8String(ut8_str) => ut8_str.len() as u32,
            PrimitiveContent::BitString((bytes, _)) => bytes.len() as u32,
            PrimitiveContent::Null => 0
        };
        return len
    }
}