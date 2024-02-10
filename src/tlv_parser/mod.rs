
use std::{cell::RefCell, fmt::{Debug, Display}, io::{Error, Read}, iter::{Peekable, Enumerate}, rc::Rc, thread::sleep_ms};

use num::{BigInt, BigUint, One, Zero};

use self::{error_collector::{ErrorCollector, IErrorCollector}, output_builder::EncodingDataRcel, tlv::{Content, DataType, EncodingData, Identifier, IdentifierClass, Length, PrimitiveContent}};
use self::output_builder::EncodingDataOutputBuilder;

pub mod tlv;
pub mod output_builder;
pub mod error_collector;



type StateInput = Peekable<Enumerate<Box<dyn Iterator<Item = u8>>>>;
type TransitionResult = Result<Box<dyn IState>, TLVParseError>;
type ParserResult = Result<(StateInput, Vec<EncodingData>, Vec<TLVParseError>), TLVParseError>;

macro_rules! implem_take_results {
    () => {
        fn take_results(self)-> ParserResult{
            return Ok((self.input, self.output.take_result(), self.errors.take_errors()))
        }  
    };
}

macro_rules! implem_into_state {
    ($from_state:ident, $target_state:ident) => {
        impl Into<$target_state> for $from_state{
            fn into(self) -> $target_state {
                $target_state{input:self.input, output:self.output,errors:self.errors}
            }
        } 
    };
}

trait IState {
    fn transition(self) -> TransitionResult;
    fn is_finished(&self) -> bool{
        false
    }
    fn take_results(self)-> ParserResult;
}
impl IState for Box<dyn IState>{
    fn transition(self) -> TransitionResult {
        self.transition()
    }
    fn is_finished(&self) -> bool {
        self.is_finished()
    }

    fn take_results(self)-> ParserResult {
        self.take_results()
    }
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
                return self._state.take_results();
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
    fn transition(mut self) -> TransitionResult {
        return Ok(Box::<FinishedState>::new(self.into()))
    }
    fn is_finished(&self) -> bool {
        true
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
    fn transition(mut self) -> TransitionResult{
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
    fn transition(mut self) -> TransitionResult{
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
    fn transition(mut self) -> TransitionResult{
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
}

impl IState for ParseContent{
    implem_take_results!();
    fn transition(mut self) -> TransitionResult {
        // check prev tag, whether it is constructed or not
        let cur_data = self.output.get_cur_data().ok_or(TLVParseError::new("Parsing content without ownner"))?;

        if cur_data.borrow().identifier.data_type == DataType::Primitive{
            // parse primitive value
            let length = cur_data.borrow().length.clone().ok_or(TLVParseError::new("Owner does not have length defined"))?;
            // get tag number and whether tag is universal
            let tag_number = cur_data.borrow().identifier.tag_number;
            let is_universal = cur_data.borrow().identifier.class == IdentifierClass::Universal;
            
            if is_universal { 
                // there are several universally defined tags for a primitive type
                match tag_number{
                    1 => self.parse_boolean(&length)?,
                    2 => self.parse_integer(&length)?,
                    _ => self.parse_raw(&length)?
                }
            } else {
                // just keep bytes,
                self.parse_raw(&length)?;
            }
        } else {
            // constructed parse nested tlvs
            return  Ok(Box::<ParseIdentifier>::new(self.into()));  
        }
        return  Ok(Box::<InitialState>::new(self.into()));    
    }
}
#[cfg(test)]
mod test{

    use std::{any::{Any, TypeId}, ops::Deref, vec};

    use num::{BigInt, FromPrimitive, ToPrimitive, BigUint, Zero, traits::ToBytes};

    use crate::tlv_parser::{output_builder, tlv::{DataType, IdentifierClass, Length, PrimitiveContent}, ParseContent, ParseLength};

    use super::{error_collector::ErrorCollector, output_builder::EncodingDataOutputBuilder, tlv::{Content, Identifier}, IState, ParseIdentifier, StateInput};


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

    fn create_test_parseident(input: Vec<u8>, output_builder: EncodingDataOutputBuilder) -> ParseIdentifier{
        ParseIdentifier{
            input : create_input(input),
            output : EncodingDataOutputBuilder::new(),
            errors : ErrorCollector::new()
        }
    }
    fn create_test_parselength(input: Vec<u8>, output_builder: EncodingDataOutputBuilder) -> ParseLength{
        ParseLength{
            input : create_input(input),
            output : EncodingDataOutputBuilder::new(),
            errors : ErrorCollector::new()
        }
    }
    fn create_test_parsecontent(input: Vec<u8>, output_builder: EncodingDataOutputBuilder) -> ParseContent{
        ParseContent{
            input : create_input(input),
            output : EncodingDataOutputBuilder::new(),
            errors : ErrorCollector::new()
        }
    }

    #[test]
    fn test_parse_identifier_universal_primitive(){
        let mut output_builder = EncodingDataOutputBuilder::new();
        let mut state = create_test_parseident(vec![0],output_builder);
        let _next_state = state.transition().unwrap();

        let data = _next_state.take_results().unwrap().1.pop().unwrap();
        assert_eq!(data.identifier.class, IdentifierClass::Universal);
        assert_eq!(data.identifier.data_type, DataType::Primitive);
        assert!(data.identifier.tag_number.is_zero());
    }

    #[test]
    fn test_parse_identifier_app_constructed(){
        let mut output_builder = EncodingDataOutputBuilder::new();
        let mut state = create_test_parseident(vec![97],output_builder);
        
        let _next_state = state.transition().unwrap();

        let data = _next_state.take_results().unwrap().1.pop().unwrap();
        assert_eq!(data.identifier.class, IdentifierClass::Application);
        assert_eq!(data.identifier.data_type, DataType::Constructed);
        assert_eq!(data.identifier.tag_number.to_usize().unwrap(), 1);
    }

    #[test]
    fn test_parse_identifier_context_specific_tagnumber_single_max(){
        
        let mut output_builder = EncodingDataOutputBuilder::new();
        let mut state = create_test_parseident(vec![158],output_builder);
        let _next_state = state.transition().unwrap();

        let data = _next_state.take_results().unwrap().1.pop().unwrap();
        assert_eq!(data.identifier.class, IdentifierClass::ContextSpecific);
        assert_eq!(data.identifier.tag_number.to_usize().unwrap(), 30);
    }

    #[test]
    fn test_parse_identifier_tagnumber_multiple(){
        let mut output_builder = EncodingDataOutputBuilder::new();
        let mut state = create_test_parseident(vec![31, 248, 188, 158, 15],output_builder);
        
        let _next_state = state.transition().unwrap();

        let data = _next_state.take_results().unwrap().1.pop().unwrap();
        assert_eq!(data.identifier.tag_number, 4042322160);
    }

    #[test]
    fn test_parse_identifier_tagnumber_morethan4bytes(){
        let mut output_builder = EncodingDataOutputBuilder::new();
        let mut state = create_test_parseident(vec![31, 248, 188, 158, 143, 15],output_builder);
        
        assert!(state.transition().is_err());
    }

    #[test]
    fn test_parse_length_1byte(){
        let mut output_builder = create_test_output_builder_w_id();
        let mut state = create_test_parselength(vec![42],output_builder);
        
        let _next_state = state.transition().unwrap();

        let data = _next_state.take_results().unwrap().1.pop().unwrap();
        assert_eq!(data.length.as_ref().unwrap().length.to_usize().unwrap(), 42);
    }

    #[test]
    fn test_parse_length_3bytes(){
        let mut output_builder = create_test_output_builder_w_id();
        let mut state = create_test_parselength(vec![0x83, 0x11, 0x11, 0x11],output_builder);
        
        let _next_state = state.transition().unwrap();

        let data = _next_state.take_results().unwrap().1.pop().unwrap();
        assert_eq!(data.length.as_ref().unwrap().length, 1_118_481);
    }

    #[test]
    fn test_parse_length_morethan4bytes(){
        let mut output_builder = create_test_output_builder_w_id();
        let mut state = create_test_parselength(vec![0x85, 0x11, 0x11, 0x11, 0x11, 0x11],output_builder);
        
        assert!(state.transition().is_err());
    }

    #[test]
    fn test_parse_content_raw(){
        let mut output_builder = create_test_output_builder_w_id();
        output_builder.add_length(Length::new(4));
        let mut state = create_test_parsecontent(vec![1,2,3,4],output_builder);
        
        let _next_state = state.transition().unwrap();

        let data = _next_state.take_results().unwrap().1.pop().unwrap();
        assert!(matches!(data.content.as_ref().unwrap(), Content::Raw(_)));
        if let Content::Raw(len) = data.content.unwrap(){
            assert_eq!(len.len(), 4);
        }
    }

    #[test]
    fn test_parse_content_boolean_true(){
        let mut output_builder = create_test_output_builder_w_universal_prim_id(1);
        output_builder.add_length(Length::new(1));
        let mut state = create_test_parsecontent(vec![0xff],output_builder);
        
        let _next_state = state.transition().unwrap();

        let data = _next_state.take_results().unwrap().1.pop().unwrap();
        match data.content.unwrap() {
            Content::Primitive(PrimitiveContent::Boolean(val)) => {
                assert!(val);
            }
            v => panic!("{:#?}", v) 
        }
    }

    #[test]
    fn test_parse_content_boolean_false(){
        let mut output_builder = create_test_output_builder_w_universal_prim_id(1);
        output_builder.add_length(Length::new(1));
        let mut state = create_test_parsecontent(vec![0xfe],output_builder);
        
        let _next_state = state.transition().unwrap();

        let data = _next_state.take_results().unwrap().1.pop().unwrap();
        match data.content.unwrap() {
            Content::Primitive(PrimitiveContent::Boolean(val)) => {
                assert!(!val);
            }
            v => panic!("{:#?}", v) 
        }
    }

    #[test]
    fn test_parse_content_boolean_wronglength(){
        let mut output_builder = create_test_output_builder_w_universal_prim_id(1);
        output_builder.add_length(Length::new(2));
        let mut state = create_test_parsecontent(vec![0xfe],output_builder);
        
        assert!(state.transition().is_err());
    }

    #[test]
    fn test_parse_content_int(){
        let mut output_builder = create_test_output_builder_w_universal_prim_id(2);
        output_builder.add_length(Length::new(4));
        let mut state = create_test_parsecontent(vec![0xff, 0xff, 0xff, 0xff],output_builder);
        
        let _next_state = state.transition().unwrap();

        let data = _next_state.take_results().unwrap().1.pop().unwrap();
        match data.content.unwrap() {
            Content::Primitive(PrimitiveContent::Integer(val)) => {
                assert_eq!(val, BigInt::from(-1));
            }
            v => panic!("{:#?}", v) 
        }
    }

    #[test]
    fn test_parse_content_int_wronglength(){
        let mut output_builder = create_test_output_builder_w_universal_prim_id(2);
        output_builder.add_length(Length::new(0));
        let mut state = create_test_parsecontent(vec![0xfe],output_builder);
        
        assert!(state.transition().is_err());
    }
}