use num::{BigUint, Zero};


#[derive(Debug, Clone)]
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
        todo!()
    }
    pub fn bits(&self) -> u64{
        todo!()
    }
}

#[derive(Debug, Clone)]
pub struct Identifier{
    pub class: IdentifierClass,
    pub data_type: DataType,
    pub tag_number: u32
}
impl Identifier  {
}

#[derive(Debug,Clone,PartialEq)]
pub enum IdentifierClass{
    Universal,
    Application,
    ContextSpecific,
    Private
}

#[derive(Debug,Clone,PartialEq)]
pub enum DataType{
    Primitive,
    Constructed,
}

#[derive(Debug, Clone)]
pub struct Length{
    pub length: u32
}
impl Length{
}

#[derive(Debug, Clone)]
pub enum Content{
    Primitive(PrimitiveContent),
    Constructed(Vec<EncodingData>),
    // for data types not yet implemented
    Raw(Vec<u8>)
}
impl Content {
}


#[derive(Debug, Clone)]
pub enum PrimitiveContent{
    Boolean(bool),
    Integer(BigUint),
    OctetString(Vec<u8>),
    UTF8String(String)
}
impl PrimitiveContent{
}