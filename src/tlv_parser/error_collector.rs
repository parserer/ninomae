use std::fmt::Display;

use super::TLVParseError;



pub trait IErrorCollector<E: Display>{
    fn add(&mut self, error: E);
    fn take_errors(self) -> Vec<E>;
}

pub struct ErrorCollector{
    _errors : Vec<TLVParseError>
}
impl ErrorCollector {
    pub fn new()-> ErrorCollector{
        ErrorCollector{
            _errors: Vec::new()
        }
    }
}
impl IErrorCollector<TLVParseError> for ErrorCollector {
    fn add(&mut self, error: TLVParseError) {
        self._errors.push(error)
    }

    fn take_errors(self) -> Vec<TLVParseError> {
        return self._errors
    }
}