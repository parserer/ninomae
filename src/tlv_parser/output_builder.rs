use std::{rc::Rc, cell::RefCell};

use super::tlv::{Identifier, EncodingData, DataType, Content, Length};

///  This doesn't work! HOW TO DROP BORROW OF A STRUCT FIELD???
/// 
pub(super) struct EncodingDataOutputBuilder2<'a>{
    _list_of_data: Option<Vec<EncodingData>>,
    _current_data: Option<&'a mut EncodingData>
}
impl<'a> EncodingDataOutputBuilder2<'a> {
    pub fn new()-> EncodingDataOutputBuilder2<'a>{
        EncodingDataOutputBuilder2{
            _list_of_data: Some(Vec::new()),
            _current_data: None
        }
    }
    fn _create_new_data(&'a mut self, identifier: Identifier){
        self._list_of_data.as_mut().unwrap().push(EncodingData::new(identifier));
        self._current_data = Some(self._list_of_data.as_mut().unwrap().last_mut().unwrap());
    }

    pub fn set_identifier(&'a mut self, identifier: Identifier){
        // check if current data length limit is reached or it is primitive
        //  if it is create new data
        //  otherwise, append to content of current data
        if let Some(cur_data) = self._current_data.as_mut(){
            if cur_data.identifier.data_type == DataType::Primitive ||  cur_data.is_length_limit_reached(){
                self._create_new_data(identifier);
            } else {
                if let Some(content) = cur_data.content.as_mut(){
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
            self._create_new_data(identifier);
        }
    }
    pub fn set_length(&'a mut self, length: Length){

    }
    pub fn set_content(&'a mut self, content: Content){

    }

    pub fn drop_borrow(&'a mut self){
        self._current_data=None;
    }
    pub fn take_result<'b>(&'b mut self)->Vec<EncodingData>{
        self._current_data=None;
        return self._list_of_data.take().unwrap();
    }
}

pub(super) struct EncodingDataOutputBuilder{
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
        })));
        self._list_of_data.as_mut().unwrap().push(self._current_data.as_ref().unwrap().clone());
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
            self._create_new_data(identifier);
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

#[cfg(test)]
mod test {
    use std::result;

    use crate::tlv_parser::{tlv::{Identifier, IdentifierClass, DataType}, output_builder::{EncodingDataOutputBuilder, EncodingDataOutputBuilder2}};

    fn create_test_identifier() -> Identifier{
        Identifier{
            class: IdentifierClass::Universal,
            data_type: DataType::Primitive,
            tag_number: vec![01]
        }
    }

    #[test]
    fn test_set_id(){
        let mut builder = EncodingDataOutputBuilder::new();
        builder.set_identifier(create_test_identifier());
        let result = builder.take_result();

        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_set_id_twice(){
        let mut builder = EncodingDataOutputBuilder::new();
        builder.set_identifier(create_test_identifier());
        builder.set_identifier(create_test_identifier());
        let result = builder.take_result();

        assert_eq!(result.len(), 2);
    }

    // #[test]
    // fn test_set_id2(){
    //     let mut builder = EncodingDataOutputBuilder2::new();
    //     builder.set_identifier(create_test_identifier());
    //     let result = builder.take_result();

    //     assert_eq!(result.len(), 1);
    // }
}