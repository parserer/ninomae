use std::{io::Error, iter::{Peekable, Enumerate}, rc::Rc, cell::RefCell};

use self::tlv::{EncodingData, Identifier, Length, Content, DataType, IdentifierClass};
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
        let tag_number : Vec<u8> = match next & 0b0001_1111{
            0b0001_1111 => {
                // IS THIS CORRECT IMPLEM? THERE IS NO CLEAR EXAMPLE IN SPEC
                // tag number on multiple bytes
                //  take until bit 8 is 0
                let mut tag_number = Vec::new();
                // 
                let ( mut _pos, mut next) = input.next().ok_or(TLVParseError::new("Error parsing Identifier. Unexpected EOF"))?;
                let mut shift_needed = 1;
                loop {
                    let cur_num = (next << 1) as u8;
                    if let Some(prev) = tag_number.last_mut(){
                        if shift_needed == 8 {
                            // just append in this case and rest shift_needed
                            tag_number.push(cur_num);
                            shift_needed = 1;
                        } else {
                            // discard bit 8 and take needed bits
                            let mut bits_to_add_to_prev = cur_num & BIT_MASK_MSB[shift_needed];
                            bits_to_add_to_prev >>= 8-shift_needed;
                            // or bits with prev byte
                            *prev = *prev | bits_to_add_to_prev;
                            
                            if shift_needed != 7{
                                tag_number.push(cur_num<<shift_needed);
                            }
                            shift_needed += 1;
                        }
                    } else {
                        tag_number.push(cur_num);
                        shift_needed = 1;
                    }
                    // when bit 8  is 0 break
                    if (next & 0b1000_0000) == 0 {
                        break
                    }
                    (_pos ,next) = input.next().ok_or(TLVParseError::new("Error parsing Identifier. Unexpected EOF"))?;
                }
                tag_number
            },
            _ => vec![next as u8 & 0b0001_1111],  
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
        let next = input.next().ok_or(TLVParseError::new("Error parsing Identifier. Unexpected EOF"))?;

        todo!()
    }
}

#[cfg(test)]
mod test{

    use std::{any::{Any, TypeId}, ops::Deref};

    use crate::tlv_parser::{ParseLength, tlv::{IdentifierClass, DataType}};

    use super::{ParseIdentifier, IState, output_builder::EncodingDataOutputBuilder, StateInput};


    fn create_input(input: Vec<u8>) -> StateInput{
        input.iter().for_each(|b|{
            println!("{:b}",b)
        });
        println!("--");
        let iter : Box<dyn Iterator<Item = u8>>= Box::new(input.into_iter());
        iter.enumerate().peekable()
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
        assert_eq!(*data.identifier.tag_number.first().unwrap(), 0);
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
        assert_eq!(*data.identifier.tag_number.first().unwrap(), 1);
    }

    #[test]
    fn test_parse_identifier_context_specific_tagnumber_single_max(){
        let mut input = create_input(vec![158]);
        let state = ParseIdentifier;
        let mut output_builder = EncodingDataOutputBuilder::new();
        let _next_state = state.transition(&mut input, &mut output_builder).unwrap();

        let data = output_builder.take_result().pop().unwrap();
        assert_eq!(data.identifier.class, IdentifierClass::ContextSpecific);
        assert_eq!(*data.identifier.tag_number.first().unwrap(), 30);
    }

    #[test]
    fn test_parse_identifier_tagnumber_multiple(){
        let mut input = create_input(vec![31, 248, 188, 158, 143, 135, 195, 225, 240, 248, 0]);
        let state = ParseIdentifier;
        let mut output_builder = EncodingDataOutputBuilder::new();
        let _next_state = state.transition(&mut input, &mut output_builder).unwrap();

        let data = output_builder.take_result().pop().unwrap();
        data.identifier.tag_number.iter().for_each(|b|{
            println!("{:b}",b)
        });
    }
}