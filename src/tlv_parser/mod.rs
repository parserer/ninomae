
use std::{io::{Error, Read}, iter::{Peekable, Enumerate}, rc::Rc, cell::RefCell};

use num::{BigUint, One, Zero};

use self::{output_builder::EncodingDataRcel, tlv::{EncodingData, Identifier, Length, Content, DataType, IdentifierClass}};
use self::output_builder::EncodingDataOutputBuilder;

pub mod tlv;
pub mod output_builder;

type StateInput = Peekable<Enumerate<Box<dyn Iterator<Item = u8>>>>;
type TransitionResult = Result<Box<dyn IState>, TLVParseError>;

trait IState{
    fn transition(&self, input: &mut StateInput, output_builder: &mut EncodingDataOutputBuilder) -> TransitionResult;
    fn is_finished(&self) -> bool{
        false
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
    _input: StateInput,
    _state: Box<dyn IState>,
    _output_builder: EncodingDataOutputBuilder,
}

impl TLVParser {
    pub fn new(input: Box<dyn Iterator<Item = u8>>)-> Result<TLVParser, Error>{
        return Ok(TLVParser{
            _input: input.enumerate().peekable(),
            _state: Box::new(InitialState),
            _output_builder: EncodingDataOutputBuilder::new()
        })
    }
    pub fn parse(&mut self) -> Result<Vec<EncodingData>, TLVParseError>{
        loop {
            if self._state.is_finished(){
                return Ok(self._output_builder.take_result());
            }
            self._state = self._state.transition(&mut self._input, &mut self._output_builder)?;    
        }
    }
}

struct FinishedState;
impl IState for FinishedState{
    fn transition(&self, input: &mut StateInput,output_builder: &mut EncodingDataOutputBuilder) -> TransitionResult {
        return Ok(Box::new(FinishedState))
    }
    fn is_finished(&self) -> bool {
        true
    }
}

/// This state does not consume input, will just peek and determine whether
///  to continue parsing or not
struct InitialState;
impl IState for InitialState{
    fn transition(&self, input: &mut StateInput,output_builder: &mut EncodingDataOutputBuilder) -> TransitionResult{
        match input.peek(){
            Some(_) => return Ok(Box::new(InitialState)),
            _=> return Ok(Box::new(FinishedState))
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

struct ParseIdentifier;
impl IState for ParseIdentifier{
    fn transition(&self, input: &mut StateInput,output_builder: &mut EncodingDataOutputBuilder) -> TransitionResult{
        let (_pos, next) = input.next().ok_or(TLVParseError::new("Error parsing Identifier. Unexpected EOF"))?;
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
                let ( mut _pos, mut next) = input.next().ok_or(TLVParseError::new("Error parsing Identifier. Unexpected EOF"))?;
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
                    (_pos ,next) = input.next().ok_or(TLVParseError::new("Error parsing Identifier. Unexpected EOF"))?;
                }
                // use le(little endian) to switch byte order
                u32::from_le_bytes(tag_number)
            },
            // tag on single byte
            _ => (next & 0b0001_1111) as u32,  
        };
        // output identifier
        output_builder.add_identifier(Identifier{
            class:identifier_class,
            data_type,
            tag_number,
        });
        return Ok(Box::new(ParseLength))
    }
}

struct ParseLength;
impl IState for ParseLength{
    fn transition(&self, input: &mut StateInput,output_builder: &mut EncodingDataOutputBuilder) -> TransitionResult{
        let (_pos, next) = input.next().ok_or(TLVParseError::new("Error parsing Length. Unexpected EOF"))?;
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
                let (_pos, next) = input.next().ok_or(TLVParseError::new("Error parsing Identifier. Unexpected EOF"))?;
                length[i as usize] = next;
            }
            let length = Length{length: u32::from_le_bytes(length)};
            is_length_zero = length.length.is_zero();
            output_builder.add_length(length);
        } else {
            // length on one byte
            let length = Length{length: (next & 0b0111_1111) as u32};
            is_length_zero = length.length.is_zero();
            output_builder.add_length(length);
            
        }
        if is_length_zero{
            return Ok(Box::new(InitialState))
        } else {
            return Ok(Box::new(ParseContent))
        }
    }
}


struct ParseContent;
impl ParseContent {
    fn parse_raw(&self, input: &mut StateInput, length: &Length, output_builder: &mut EncodingDataOutputBuilder)
    -> Result<(), TLVParseError>{
        if length.length.is_zero() {return Ok(());}

        let mut content = Vec::new();
        let mut count = 0;
        while count < length.length {
            let (_pos, next) = input.next().ok_or(TLVParseError::new("Error parsing Content. Unexpected EOF"))?;
            content.push(next);
            count += 1;
        }
        output_builder.add_content(Content::Raw(content));
        return Ok(());
    }
}
impl IState for ParseContent{
    fn transition(&self, input: &mut StateInput, output_builder: &mut EncodingDataOutputBuilder) -> TransitionResult {
        // check prev tag, whether it is constructed or not
        let cur_data = output_builder.get_cur_data().ok_or(TLVParseError::new("Parsing content without ownner"))?;

        if cur_data.borrow().identifier.data_type == DataType::Primitive{
            let length = cur_data.borrow().length.clone().ok_or(TLVParseError::new("Owner does not have length defined"))?;
            // parse primitive value
            match self.parse_raw(input, &length, output_builder){
                Ok(())=>(),
                Err(e) => return Err(e)
            };
        }

        return  Ok(Box::new(ParseIdentifier));    
    }
}
#[cfg(test)]
mod test{

    use std::{any::{Any, TypeId}, ops::Deref, vec};

    use num::{BigInt, FromPrimitive, ToPrimitive, BigUint, Zero, traits::ToBytes};

    use crate::tlv_parser::{tlv::{DataType, IdentifierClass, Length}, ParseContent, ParseLength};

    use super::{ParseIdentifier, IState, output_builder::EncodingDataOutputBuilder, StateInput, tlv::{Content, Identifier}};


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

    #[test]
    fn test_parse_identifier_universal_primitive(){
        let mut input = create_input(vec![0]);
        let state = ParseIdentifier;
        let mut output_builder = EncodingDataOutputBuilder::new();
        let _next_state = state.transition(&mut input, &mut output_builder).unwrap();

        let data = output_builder.take_result().pop().unwrap();
        assert_eq!(data.identifier.class, IdentifierClass::Universal);
        assert_eq!(data.identifier.data_type, DataType::Primitive);
        assert!(data.identifier.tag_number.is_zero());
    }

    #[test]
    fn test_parse_identifier_app_constructed(){
        let mut input = create_input( vec![97]);
        let state = ParseIdentifier;
        let mut output_builder = EncodingDataOutputBuilder::new();
        let _next_state = state.transition(&mut input, &mut output_builder).unwrap();

        let data = output_builder.take_result().pop().unwrap();
        assert_eq!(data.identifier.class, IdentifierClass::Application);
        assert_eq!(data.identifier.data_type, DataType::Constructed);
        assert_eq!(data.identifier.tag_number.to_usize().unwrap(), 1);
    }

    #[test]
    fn test_parse_identifier_context_specific_tagnumber_single_max(){
        let mut input = create_input(vec![158]);
        let state = ParseIdentifier;
        let mut output_builder = EncodingDataOutputBuilder::new();
        let _next_state = state.transition(&mut input, &mut output_builder).unwrap();

        let data = output_builder.take_result().pop().unwrap();
        assert_eq!(data.identifier.class, IdentifierClass::ContextSpecific);
        assert_eq!(data.identifier.tag_number.to_usize().unwrap(), 30);
    }

    #[test]
    fn test_parse_identifier_tagnumber_multiple(){
        let mut input = create_input(vec![31, 248, 188, 158, 15]);
        let state = ParseIdentifier;
        let mut output_builder = EncodingDataOutputBuilder::new();
        let _next_state = state.transition(&mut input, &mut output_builder).unwrap();

        let data = output_builder.take_result().pop().unwrap();
        assert_eq!(data.identifier.tag_number, 4042322160);
    }

    #[test]
    fn test_parse_identifier_tagnumber_morethan4bytes(){
        let mut input = create_input(vec![31, 248, 188, 158, 143, 15]);
        let state = ParseIdentifier;
        let mut output_builder = EncodingDataOutputBuilder::new();
        assert!(state.transition(&mut input, &mut output_builder).is_err());
    }

    #[test]
    fn test_parse_length_1byte(){
        let mut input = create_input(vec![42]);
        let state = ParseLength;
        let mut output_builder = create_test_output_builder_w_id();
        let _next_state = state.transition(&mut input, &mut output_builder).unwrap();

        let data = output_builder.take_result().pop().unwrap();
        assert_eq!(data.length.as_ref().unwrap().length.to_usize().unwrap(), 42);
    }

    #[test]
    fn test_parse_length_3bytes(){
        let mut input = create_input(vec![0x83, 0x11, 0x11, 0x11]);
        let state = ParseLength;
        let mut output_builder = create_test_output_builder_w_id();
        let _next_state = state.transition(&mut input, &mut output_builder).unwrap();

        let data = output_builder.take_result().pop().unwrap();
        assert_eq!(data.length.as_ref().unwrap().length, 1_118_481);
    }

    #[test]
    fn test_parse_length_morethan4bytes(){
        let mut input = create_input(vec![0x85, 0x11, 0x11, 0x11, 0x11, 0x11]);
        let state = ParseLength;
        let mut output_builder = create_test_output_builder_w_id();
        assert!(state.transition(&mut input, &mut output_builder).is_err());
    }

    #[test]
    fn test_parse_content_raw(){
        let mut input = create_input(vec![1,2,3,4]);
        let state = ParseContent;
        let mut output_builder = create_test_output_builder_w_id();
        output_builder.add_length(Length::new(4));
        let _next_state = state.transition(&mut input, &mut output_builder).unwrap();

        let data = output_builder.take_result().pop().unwrap();
        assert!(matches!(data.content.as_ref().unwrap(), Content::Raw(_)));
        if let Content::Raw(len) = data.content.unwrap(){
            assert_eq!(len.len(), 4);
        }
    }
}