
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
        false
    }
}

#[derive(Debug, Clone)]
pub struct Identifier{
    pub class: IdentifierClass,
    pub data_type: DataType,
    pub tag_number: Vec<u8>
}
impl Identifier  {
    pub fn get_tag_number_as_usize(&self) -> Option<usize>{
        todo!()
    }
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
    pub raw: Vec<u8>
}
impl Length{
    pub fn get_length_as_usize(&self) -> Option<usize>{
        todo!()
    }
}

#[derive(Debug, Clone)]
pub enum Content{
    Primitive(PrimitiveContent),
    Constructed(Vec<EncodingData>),
    // for data types not yet implemented
    Raw(Vec<u8>)
}


#[derive(Debug, Clone)]
pub enum PrimitiveContent{
    Boolean(bool),
    Integer(Vec<u8>),
    OctetString(Vec<u8>),
    UTF8String(String)
}
