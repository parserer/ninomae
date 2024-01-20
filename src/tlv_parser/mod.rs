use std::{io::Error, iter::{Peekable, Enumerate}, rc::Rc, cell::RefCell};

use self::tlv::{EncodingData, Identifier, Length, Content, DataType};


pub mod tlv;

type StateInput = Peekable<Enumerate<Box<dyn Iterator<Item = u8>>>>;
type TransitionResult = Result<Box<dyn IState>, TLVParseError>;

trait IState{
    fn transition(&self, input: &mut StateInput, output_builder: &mut EncodingDataOutputBuilder) -> TransitionResult;
    fn is_finished(&self) -> bool{
        false
    }
}


struct EncodingDataOutputBuilder{
    _list_of_data: Option<Vec<Rc<RefCell<EncodingData>>>>,
    _current_data: Option<Rc<RefCell<EncodingData>>>
}
impl EncodingDataOutputBuilder {
    pub fn new()-> EncodingDataOutputBuilder{
        EncodingDataOutputBuilder{
            _list_of_data: Some(Vec::new()),
            _current_data: None
        }
    }

    fn _create_new_data(&mut self, identifier: Identifier){
        self._current_data = Some(Rc::new(RefCell::new(EncodingData{
            identifier,
            length: None,
            content: None
        })))
    }

    pub fn set_identifier(&mut self, identifier: Identifier){
        // check if current data length limit is reached or it is primitive
        //  if it is create new data
        //  otherwise, append to content of current data
        if let Some(cur_data) = &self._current_data{
            if cur_data.borrow().identifier.data_type == DataType::Primitive ||  cur_data.borrow().is_length_limit_reached(){
                self._create_new_data(identifier);
            } else {
                if let Some(content) = &mut cur_data.borrow_mut().content{
                    if let Content::Constructed(children) = content{
                        children.push(EncodingData{
                            identifier,
                            length: None,
                            content: None
                        })
                    }
                }
            }
        } else {
            self._create_new_data(identifier)
        }
    }
    pub fn set_length(&mut self, length: Length){

    }
    pub fn set_content(&mut self, content: Content){

    }

    pub fn take_result(&mut self)->Vec<EncodingData>{
        self._current_data=None;
        self._list_of_data.take().unwrap().into_iter().map(|data| Rc::try_unwrap(data).unwrap().into_inner()).collect()
    }
}


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

struct ParseIdentifier;
impl IState for ParseIdentifier{
    fn transition(&self, input: &mut StateInput,output_builder: &mut EncodingDataOutputBuilder) -> TransitionResult{
        let next = input.next().ok_or(TLVParseError::new("Error parsing Identifier. Unexpected EOF"))?;

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