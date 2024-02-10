
use std::{fmt::{Debug}, io::{Error}, iter::{Peekable, Enumerate}};

use num::{BigInt, One, Zero};

use self::{error_collector::{ErrorCollector, IErrorCollector}, output_builder::EncodingDataRcel, tlv::{Content, DataType, EncodingData, Identifier, IdentifierClass, Length, PrimitiveContent}};
use self::output_builder::EncodingDataOutputBuilder;

pub mod tlv;
pub mod output_builder;
pub mod error_collector;



type StateInput = Peekable<Enumerate<Box<dyn Iterator<Item = u8>>>>;
type TransitionResult = Result<Box<dyn IState>, TLVParseError>;
type ParserResult = Result<(StateInput, Vec<EncodingDataRcel>, Vec<TLVParseError>), TLVParseError>;

macro_rules! implem_take_results {
    () => {
        fn take_results(self: Box<Self>)-> ParserResult{
            return Ok((self.input, self.output.take_result(), self.errors.take_errors()))
        }  
    };
}

macro_rules! implem_into_state {
    ($from_state:ident, $target_state:ident) => {
        impl Into<$target_state> for Box<$from_state>{
            fn into(self) -> $target_state {
                $target_state{input:self.input, output:self.output,errors:self.errors}
            }
        } 
    };
}

trait IState {
    fn transition(self: Box<Self>) -> TransitionResult;
    fn is_finished(&self) -> bool{
        false
    }
    fn take_results(self: Box<Self>)-> ParserResult;
}


#[derive(Debug)]
pub struct TLVParseError{
    msg: String
}
impl std::fmt::Display for TLVParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TLV parse error")
    }
}
impl TLVParseError{
    pub fn new(msg: &str)-> TLVParseError{
        return TLVParseError{
            msg: msg.to_string()
        };
    }
}

pub struct TLVParser {
    _state: Box<dyn IState>,
}

impl TLVParser {
    pub fn new(input: Box<dyn Iterator<Item = u8>>)-> Result<TLVParser, Error>{
        return Ok(TLVParser{
            _state: Box::new(InitialState{
                input: input.enumerate().peekable(),
                output: EncodingDataOutputBuilder::new(),
                errors: ErrorCollector::new()
            }),
        })
    }
    pub fn parse(mut self) -> ParserResult{
        loop {
            if self._state.is_finished(){
                return  self._state.take_results();
            }
            self._state = self._state.transition()?;    
        }
    }
}

struct FinishedState{
    input: StateInput,
    output: EncodingDataOutputBuilder,
    errors: ErrorCollector
}

impl IState for FinishedState{
    implem_take_results!();
    fn transition(self: Box<Self>) -> TransitionResult {
        return Ok(Box::<FinishedState>::new(self.into()))
    }
    fn is_finished(&self) -> bool {
        true
    }
}
impl Into<FinishedState> for Box<FinishedState>{
    fn into(self) -> FinishedState {
        FinishedState{input:self.input,output:self.output,errors:self.errors}
    }
}

/// This state does not consume input, will just peek and determine whether
///  to continue parsing or not
struct InitialState{
    input: StateInput,
    output: EncodingDataOutputBuilder,
    errors: ErrorCollector
}
implem_into_state!(InitialState, FinishedState);
implem_into_state!(InitialState, ParseIdentifier);
impl IState for InitialState{
    implem_take_results!();
    fn transition(mut self: Box<Self>) -> TransitionResult{
        match self.input.peek(){
            Some(_) => return Ok(Box::<ParseIdentifier>::new(self.into())),
            _=> return Ok(Box::<FinishedState>::new(self.into()))
        }   
    }
}


const BIT_MASK_MSB: [u8; 9] = [
    0b0000_0000,
    0b1000_0000,
    0b1100_0000,
    0b1110_0000,
    0b1111_0000,
    0b1111_1000,
    0b1111_1100,
    0b1111_1110,
    0b1111_1111,
];

struct ParseIdentifier{
    input: StateInput,
    output: EncodingDataOutputBuilder,
    errors: ErrorCollector
}
implem_into_state!(ParseIdentifier, ParseLength);
impl IState for ParseIdentifier{
    implem_take_results!();
    fn transition(mut self: Box<Self>) -> TransitionResult{
        let (_pos, next) = self.input.next().ok_or(TLVParseError::new("Error parsing Identifier. Unexpected EOF"))?;
        // bit MSB 8-1 LSB
        // class is on bit 8-7
        let identifier_class = match next & 0b1100_0000{
            0b0000_0000 => IdentifierClass::Universal,
            0b0100_0000 => IdentifierClass::Application,
            0b1000_0000 => IdentifierClass::ContextSpecific,
            _ => IdentifierClass::Private,
        };
        // data type on bit 6
        let data_type = match next & 0b0010_0000{
            0b0000_0000 => DataType::Primitive,
            _ => DataType::Constructed,
        };
        //
        // tag_number type on bit 5-1 & subsequent bytes (if applicable)
        let tag_number : u32 = match next & 0b0001_1111{
            0b0001_1111 => {
                // IS THIS CORRECT IMPLEM? THERE IS NO CLEAR EXAMPLE IN SPEC
                // tag number on multiple bytes
                //  take until bit 8 is 0
                let mut tag_number = [0,0,0,0];
                // 
                let ( mut _pos, mut next) = self.input.next().ok_or(TLVParseError::new("Error parsing Identifier. Unexpected EOF"))?;
                let mut shift_needed = 1;
                let mut i=0;
                loop {
                    if i > 3{
                        return Err(TLVParseError::new("Identifier bytes longer than 4 bytes are not supported yet"));
                    }
                    let cur_num = (next << 1) as u8;
                    if i !=0 {
                        let prev = &mut tag_number[i-1];
                        // discard bit 8 and take needed bits
                        let mut bits_to_add_to_prev = cur_num & BIT_MASK_MSB[shift_needed];
                        bits_to_add_to_prev >>= 8-shift_needed;
                        // or bits with prev byte
                        *prev = *prev | bits_to_add_to_prev;
                        
                        if shift_needed != 7{
                            tag_number[i] = cur_num<<shift_needed;
                        }
                        shift_needed += 1;
                    } else {
                        tag_number[i] = cur_num;
                        shift_needed = 1;
                    }
                    i+=1;
                    // when bit 8  is 0 break
                    if (next & 0b1000_0000) == 0 {
                        break
                    }
                    (_pos ,next) = self.input.next().ok_or(TLVParseError::new("Error parsing Identifier. Unexpected EOF"))?;
                }
                // use le(little endian) to switch byte order
                u32::from_le_bytes(tag_number)
            },
            // tag on single byte
            _ => (next & 0b0001_1111) as u32,  
        };
        // output identifier
        self.output.add_identifier(Identifier{
            class:identifier_class,
            data_type,
            tag_number,
        });
        return Ok(Box::<ParseLength>::new(self.into()))
    }
}


struct ParseLength{
    input: StateInput,
    output: EncodingDataOutputBuilder,
    errors: ErrorCollector
}
implem_into_state!(ParseLength, ParseContent);
implem_into_state!(ParseLength, InitialState);
impl IState for ParseLength{
    implem_take_results!();
    fn transition(mut self: Box<Self>) -> TransitionResult{
        let (_pos, next) = self.input.next().ok_or(TLVParseError::new("Error parsing Length. Unexpected EOF"))?;
        let is_length_zero;
        if (next & 0b1000_0000) != 0 {
            // length on multiple lengths
            let num_bytes_to_take = next & 0b0111_1111;
            if num_bytes_to_take > 4 {
                return Err(TLVParseError::new("Length bytes on more than 4 bytes are not supported yet"));
            }
            let mut length = [0,0,0,0];
            // take num of bytes
            for i in 0..num_bytes_to_take {
                let (_pos, next) = self.input.next().ok_or(TLVParseError::new("Error parsing Identifier. Unexpected EOF"))?;
                length[i as usize] = next;
            }
            let length = Length{length: u32::from_le_bytes(length)};
            is_length_zero = length.length.is_zero();
            self.output.add_length(length);
        } else {
            // length on one byte
            let length = Length{length: (next & 0b0111_1111) as u32};
            is_length_zero = length.length.is_zero();
            self.output.add_length(length);
            
        }
        if is_length_zero{
            return Ok(Box::<InitialState>::new(self.into()))
        } else {
            return Ok(Box::<ParseContent>::new(self.into()))
        }
    }
}


struct ParseContent{
    input: StateInput,
    output: EncodingDataOutputBuilder,
    errors: ErrorCollector
}
implem_into_state!(ParseContent, ParseIdentifier);
implem_into_state!(ParseContent, InitialState);
impl ParseContent {
    fn take_bytes(&mut self, length: u32) -> Result<Vec<u8>, TLVParseError> {
        let mut content = Vec::new();
        let mut count = 0;
        while count < length {
            let (_pos, next) = self.input.next().ok_or(TLVParseError::new("Error parsing Content. Unexpected EOF"))?;
            content.push(next);
            count += 1;
        }
        return Ok(content);
    }
 
    fn parse_raw(&mut self, length: &Length)
    -> Result<(), TLVParseError>{
        if length.length.is_zero() {return Ok(());}

        let content = self.take_bytes(length.length)?;
        self.output.add_content(Content::Raw(content));
        return Ok(());
    }

    fn parse_boolean(&mut self, length: &Length)
    -> Result<(), TLVParseError>{
        if !length.length.is_one() {return Err(TLVParseError::new("Boolean values should have only 1 byte"));}

        let (_pos, next) = self.input.next().ok_or(TLVParseError::new("Error parsing Content. Unexpected EOF"))?;
        self.output.add_content(Content::Primitive(PrimitiveContent::Boolean(if next == 0xFF {true} else {false})));
        return Ok(());
    }

    fn parse_integer(&mut self, length: &Length)
    -> Result<(), TLVParseError>{
        if length.length.is_zero() {return Err(TLVParseError::new("Integer should have at least 1 byte"));}

        let content = self.take_bytes(length.length)?;
        self.output.add_content(Content::Primitive(PrimitiveContent::Integer(BigInt::from_signed_bytes_be(&content))));
        return Ok(());
    }

    fn parse_bitstring_primitive(&mut self, length: &Length)
    -> Result<(), TLVParseError>{
        if length.length.is_zero() {return Err(TLVParseError::new("Bitstring should have at least 1 byte"));}
        
        let num_unused_bits = self.take_bytes(1)?.pop().unwrap();
        let content = self.take_bytes(length.length-1)?;
        self.output.add_content(Content::Primitive(PrimitiveContent::BitString((content, num_unused_bits))));
        return Ok(());
    }

    fn parse_utf8string(&mut self, length: &Length)
    -> Result<(), TLVParseError>{

        let content = self.take_bytes(length.length)?;
        let utf8string = String::from_utf8_lossy(&content);
        self.output.add_content(Content::Primitive(PrimitiveContent::UTF8String(utf8string.to_string())));
        return Ok(());
    }

    fn parse_null(&mut self, length: &Length)
    -> Result<(), TLVParseError>{
        if !length.length.is_zero() {
            // warning length should be zero
            self.errors.add(TLVParseError::new("Null value should have no content"))
        }
        // what to do when not zero?
        self.output.add_content(Content::Primitive(PrimitiveContent::Null));
        return Ok(());
    }
}

impl IState for ParseContent{
    implem_take_results!();
    fn transition(mut self: Box<Self>) -> TransitionResult {
        // check prev tag, whether it is constructed or not
        let cur_data = self.output.get_cur_data().ok_or(TLVParseError::new("Parsing content without ownner"))?;

        let tag_number = cur_data.borrow().identifier.tag_number;
        let is_universal = cur_data.borrow().identifier.class == IdentifierClass::Universal;
        let is_primitive = cur_data.borrow().identifier.data_type == DataType::Primitive;
        let length = cur_data.borrow().length.clone().ok_or(TLVParseError::new("Owner does not have length defined"))?;

        if is_universal {
            // parse universal value

            // get tag number and whether tag is universal
            if is_primitive { 
                // there are several universally defined tags for a primitive type
                match tag_number{
                    1 => self.parse_boolean(&length)?,
                    2 => self.parse_integer(&length)?,
                    3 => self.parse_bitstring_primitive(&length)?,
                    4 => self.parse_utf8string(&length)?,
                    5 => self.parse_null(&length)?,
                    _ => self.parse_raw(&length)?
                }
            } else {
                // constructed parse nested tlvs
                return  Ok(Box::<ParseIdentifier>::new(self.into()));  
            }
        } else {
            if is_primitive { 
                // type depends on schema, keep as raw bytes for now
                // TODO some types (bitstring, utf8string) have constructed counterparts
                self.parse_raw(&length)?;
            } else {
                // constructed parse nested tlvs
                return  Ok(Box::<ParseIdentifier>::new(self.into()));  
            }     
        }
        return  Ok(Box::<InitialState>::new(self.into()));    
    }
}
#[cfg(test)]
mod test{

    use std::{vec};

    use clap::parser;
    use num::{BigInt, FromPrimitive, ToPrimitive, Zero};

    use crate::tlv_parser::{tlv::{DataType, IdentifierClass, Length, PrimitiveContent}, ParseContent, ParseLength};

    use super::{error_collector::ErrorCollector, output_builder::EncodingDataOutputBuilder, tlv::{Content, EncodingData, Identifier}, IState, ParseIdentifier, StateInput, TLVParser};


    fn create_input(input: Vec<u8>) -> StateInput{
        // input.iter().for_each(|b|{
        //     println!("{:b}",b)
        // });
        // println!("--");
        let iter : Box<dyn Iterator<Item = u8>>= Box::new(input.into_iter());
        iter.enumerate().peekable()
    }

    fn create_test_output_builder_w_id() -> EncodingDataOutputBuilder{
        let mut builder = EncodingDataOutputBuilder::new();
        builder.add_identifier(Identifier{
            class: IdentifierClass::Universal,
            data_type: DataType::Primitive,
            tag_number: 0
        });
        builder
    }
    fn create_test_output_builder_w_universal_prim_id(tag_num: u32) -> EncodingDataOutputBuilder{
        let mut builder = EncodingDataOutputBuilder::new();
        builder.add_identifier(Identifier{
            class: IdentifierClass::Universal,
            data_type: DataType::Primitive,
            tag_number: tag_num
        });
        builder
    }

    fn create_test_parseident(input: Vec<u8>, output_builder: EncodingDataOutputBuilder) 
    -> Box<ParseIdentifier>{
        Box::new(ParseIdentifier{
            input : create_input(input),
            output : output_builder,
            errors : ErrorCollector::new()
        })
    }
    fn create_test_parselength(input: Vec<u8>, output_builder: EncodingDataOutputBuilder) 
    -> Box<ParseLength>{
        Box::new(ParseLength{
            input : create_input(input),
            output : output_builder,
            errors : ErrorCollector::new()
        })
    }
    fn create_test_parsecontent(input: Vec<u8>, output_builder: EncodingDataOutputBuilder) 
    -> Box<ParseContent>{
        Box::new(ParseContent{
            input : create_input(input),
            output : output_builder,
            errors : ErrorCollector::new()
        })
    }

    #[test]
    fn test_parse_identifier_universal_primitive(){
        let output_builder = EncodingDataOutputBuilder::new();
        let state = create_test_parseident(vec![0],output_builder);
        let _next_state = state.transition().unwrap();

        let data = _next_state.take_results().unwrap().1.pop().unwrap();
        assert_eq!(data.borrow().identifier.class, IdentifierClass::Universal);
        assert_eq!(data.borrow().identifier.data_type, DataType::Primitive);
        assert!(data.borrow().identifier.tag_number.is_zero());
    }

    #[test]
    fn test_parse_identifier_app_constructed(){
        let output_builder = EncodingDataOutputBuilder::new();
        let state = create_test_parseident(vec![97],output_builder);
        
        let _next_state = state.transition().unwrap();

        let data = _next_state.take_results().unwrap().1.pop().unwrap();
        assert_eq!(data.borrow().identifier.class, IdentifierClass::Application);
        assert_eq!(data.borrow().identifier.data_type, DataType::Constructed);
        assert_eq!(data.borrow().identifier.tag_number.to_usize().unwrap(), 1);
    }

    #[test]
    fn test_parse_identifier_context_specific_tagnumber_single_max(){
        
        let output_builder = EncodingDataOutputBuilder::new();
        let state = create_test_parseident(vec![158],output_builder);
        let _next_state = state.transition().unwrap();

        let data = _next_state.take_results().unwrap().1.pop().unwrap();
        assert_eq!(data.borrow().identifier.class, IdentifierClass::ContextSpecific);
        assert_eq!(data.borrow().identifier.tag_number.to_usize().unwrap(), 30);
    }

    #[test]
    fn test_parse_identifier_tagnumber_multiple(){
        let output_builder = EncodingDataOutputBuilder::new();
        let state = create_test_parseident(vec![31, 248, 188, 158, 15],output_builder);
        
        let _next_state = state.transition().unwrap();

        let data = _next_state.take_results().unwrap().1.pop().unwrap();
        assert_eq!(data.borrow().identifier.tag_number, 4042322160);
    }

    #[test]
    fn test_parse_identifier_tagnumber_morethan4bytes(){
        let output_builder = EncodingDataOutputBuilder::new();
        let state = create_test_parseident(vec![31, 248, 188, 158, 143, 15],output_builder);
        
        assert!(state.transition().is_err());
    }

    #[test]
    fn test_parse_length_1byte(){
        let output_builder = create_test_output_builder_w_id();
        let state = create_test_parselength(vec![42],output_builder);
        
        let _next_state = state.transition().unwrap();

        let data = _next_state.take_results().unwrap().1.pop().unwrap();
        assert_eq!(data.borrow().length.as_ref().unwrap().length.to_usize().unwrap(), 42);
    }

    #[test]
    fn test_parse_length_3bytes(){
        let output_builder = create_test_output_builder_w_id();
        let state = create_test_parselength(vec![0x83, 0x11, 0x11, 0x11],output_builder);
        
        let _next_state = state.transition().unwrap();

        let data = _next_state.take_results().unwrap().1.pop().unwrap();
        assert_eq!(data.borrow().length.as_ref().unwrap().length, 1_118_481);
    }

    #[test]
    fn test_parse_length_morethan4bytes(){
        let output_builder = create_test_output_builder_w_id();
        let state = create_test_parselength(vec![0x85, 0x11, 0x11, 0x11, 0x11, 0x11],output_builder);
        
        assert!(state.transition().is_err());
    }

    #[test]
    fn test_parse_content_raw(){
        let mut output_builder = create_test_output_builder_w_id();
        output_builder.add_length(Length::new(4));
        let state = create_test_parsecontent(vec![1,2,3,4],output_builder);
        
        let _next_state = state.transition().unwrap();

        let data = _next_state.take_results().unwrap().1.pop().unwrap();
        assert!(matches!(data.borrow().content.as_ref().unwrap(), Content::Raw(_)));
        if let Content::Raw(len) = data.borrow().content.as_ref().unwrap(){
            assert_eq!(len.len(), 4);
        };
    }

    #[test]
    fn test_parse_content_boolean_true(){
        let mut output_builder = create_test_output_builder_w_universal_prim_id(1);
        output_builder.add_length(Length::new(1));
        let state = create_test_parsecontent(vec![0xff],output_builder);
        
        let _next_state = state.transition().unwrap();

        let data = _next_state.take_results().unwrap().1.pop().unwrap();
        match data.borrow().content.as_ref().unwrap() {
            Content::Primitive(PrimitiveContent::Boolean(val)) => {
                assert!(val);
            }
            v => panic!("{:#?}", v) 
        };
    }

    #[test]
    fn test_parse_content_boolean_false(){
        let mut output_builder = create_test_output_builder_w_universal_prim_id(1);
        output_builder.add_length(Length::new(1));
        let state = create_test_parsecontent(vec![0xfe],output_builder);
        
        let _next_state = state.transition().unwrap();

        let data = _next_state.take_results().unwrap().1.pop().unwrap();
        match data.borrow().content.as_ref().unwrap() {
            Content::Primitive(PrimitiveContent::Boolean(val)) => {
                assert!(!val);
            }
            v => panic!("{:#?}", v) 
        };
    }

    #[test]
    fn test_parse_content_boolean_wronglength(){
        let mut output_builder = create_test_output_builder_w_universal_prim_id(1);
        output_builder.add_length(Length::new(2));
        let state = create_test_parsecontent(vec![0xfe],output_builder);
        
        assert!(state.transition().is_err());
    }

    #[test]
    fn test_parse_content_int(){
        let mut output_builder = create_test_output_builder_w_universal_prim_id(2);
        output_builder.add_length(Length::new(4));
        let state = create_test_parsecontent(vec![0xff, 0xff, 0xff, 0xff],output_builder);
        
        let _next_state = state.transition().unwrap();

        let data = _next_state.take_results().unwrap().1.pop().unwrap();
        match data.borrow().content.as_ref().unwrap() {
            Content::Primitive(PrimitiveContent::Integer(val)) => {
                assert_eq!(val, &BigInt::from(-1));
            }
            v => panic!("{:#?}", v) 
        };
    }

    #[test]
    fn test_parse_content_int_wronglength(){
        let mut output_builder = create_test_output_builder_w_universal_prim_id(2);
        output_builder.add_length(Length::new(0));
        let state = create_test_parsecontent(vec![0xfe],output_builder);
        
        assert!(state.transition().is_err());
    }

    #[test]
    fn test_parse_content_bitstring_empty(){
        let mut output_builder = create_test_output_builder_w_universal_prim_id(3);
        output_builder.add_length(Length::new(1));
        let state = create_test_parsecontent(vec![0x00],output_builder);
        
        let _next_state = state.transition().unwrap();

        let data = _next_state.take_results().unwrap().1.pop().unwrap();
        match data.borrow().content.as_ref().unwrap() {
            Content::Primitive(PrimitiveContent::BitString((val, num_unused))) => {
                assert_eq!(val.len(), 0);
                assert_eq!(num_unused, &0);
            }
            v => panic!("{:#?}", v) 
        };
    }

    #[test]
    fn test_parse_content_bitstring_5b(){
        let mut output_builder = create_test_output_builder_w_universal_prim_id(3);
        output_builder.add_length(Length::new(6));
        let state = create_test_parsecontent(vec![0x07, 0x00, 0x01, 0x02, 0x03, 0x04,],output_builder);
        
        let _next_state = state.transition().unwrap();

        let data = _next_state.take_results().unwrap().1.pop().unwrap();
        match data.borrow().content.as_ref().unwrap() {
            Content::Primitive(PrimitiveContent::BitString((val, num_unused))) => {
                assert_eq!(val.len(), 5);
                assert_eq!(*num_unused, 7);
            }
            v => panic!("{:#?}", v) 
        };
    }

    #[test]
    fn test_parse_content_utf8string(){
        let mut output_builder = create_test_output_builder_w_universal_prim_id(4);
        output_builder.add_length(Length::new(5));
        let state = create_test_parsecontent("hello".to_string().into_bytes(),output_builder);
        
        let _next_state = state.transition().unwrap();

        let data = _next_state.take_results().unwrap().1.pop().unwrap();
        match data.borrow().content.as_ref().unwrap() {
            Content::Primitive(PrimitiveContent::UTF8String(val)) => {
                assert_eq!(val.len(), 5);
            }
            v => panic!("{:#?}", v) 
        };
    }

    #[test]
    fn test_parse_content_null(){
        let mut output_builder = create_test_output_builder_w_universal_prim_id(5);
        output_builder.add_length(Length::new(0));
        let state = create_test_parsecontent(vec![],output_builder);
        
        let _next_state = state.transition().unwrap();

        let data = _next_state.take_results().unwrap().1.pop().unwrap();
        match data.borrow().content.as_ref().unwrap() {
            Content::Primitive(PrimitiveContent::Null) => {

            }
            v => panic!("{:#?}", v) 
        };
    }

    #[test]
    fn test_parse_content_null_nzlength(){
        let mut output_builder = create_test_output_builder_w_universal_prim_id(5);
        output_builder.add_length(Length::new(1));
        let state = create_test_parsecontent(vec![],output_builder);
        
        let _next_state = state.transition().unwrap();

        let mut result = _next_state.take_results().unwrap();
        let data  = result.1.pop().unwrap();
        match data.borrow().content.as_ref().unwrap() {
            Content::Primitive(PrimitiveContent::Null) => {
                assert_eq!(result.2.len(), 1)
            }
            v => panic!("{:#?}", v) 
        };
    }

    #[test]
    fn test_parse_tlv_integer(){
        let input = vec![0x02, 0x04, 0x01, 0x02, 0x03, 0x04];
        let parser = TLVParser::new(Box::new(input.into_iter())).unwrap();

        let mut result = parser.parse().unwrap();
        let data  = result.1.pop().unwrap();

        assert_eq!(data.borrow().identifier.class, IdentifierClass::Universal);
        assert_eq!(data.borrow().identifier.data_type, DataType::Primitive);
        assert_eq!(data.borrow().identifier.tag_number, 2);
        assert_eq!(data.borrow().length.as_ref().unwrap().length, 4);
        match data.borrow().content.as_ref().unwrap() {
            Content::Primitive(PrimitiveContent::Integer(val)) => {
                assert_eq!(val, &BigInt::from_i32(16909060).unwrap())
            }
            v => panic!("{:#?}", v) 
        };
    }

    #[test]
    fn test_parse_tlv_constructed(){
        let input = vec![0x24, 0x08, 
                            0x04, 0x02, 'h' as u8, 'e' as u8,
                            0x04, 0x02, 'h' as u8, 'e' as u8,
                        ];
        let parser = TLVParser::new(Box::new(input.into_iter())).unwrap();

        let mut result = parser.parse().unwrap();
        let data  = result.1.pop().unwrap();

        assert_eq!(data.borrow().identifier.class, IdentifierClass::Universal);
        assert_eq!(data.borrow().identifier.data_type, DataType::Constructed);
        assert_eq!(data.borrow().identifier.tag_number, 4);
        assert_eq!(data.borrow().length.as_ref().unwrap().length, 4);
        match data.borrow().content.as_ref().unwrap(){
            Content::Constructed(children) => {
                for child in children{
                    assert_eq!(child.borrow().identifier.class, IdentifierClass::Universal);
                    assert_eq!(child.borrow().identifier.data_type, DataType::Primitive);
                    assert_eq!(child.borrow().identifier.tag_number, 4);
                    assert_eq!(child.borrow().length.as_ref().unwrap().length, 2);
                    match child.borrow().content.as_ref().unwrap(){
                        Content::Primitive(PrimitiveContent::UTF8String(val)) =>{
                            assert_eq!(val.as_str(), "he")
                        }
                        v => panic!("{:#?}", v)
                    }
                }
            }
            v => panic!("{:#?}", v) 
        };
    }
}