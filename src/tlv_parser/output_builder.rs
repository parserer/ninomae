use std::{rc::Rc, cell::RefCell};

use super::tlv::{Identifier, EncodingData, DataType, Content, Length};

///  This doesn't work! HOW TO DROP BORROW OF A STRUCT FIELD???
/// 
/// 
// #[deprecated]
// pub(super) struct EncodingDataOutputBuilder2<'a>{
//     _list_of_data: Option<Vec<EncodingData>>,
//     _current_data: Option<&'a mut EncodingData>
// }
// impl<'a> EncodingDataOutputBuilder2<'a> {
//     pub fn new()-> EncodingDataOutputBuilder2<'a>{
//         EncodingDataOutputBuilder2{
//             _list_of_data: Some(Vec::new()),
//             _current_data: None
//         }
//     }
//     fn _create_new_data(&'a mut self, identifier: Identifier){
//         self._list_of_data.as_mut().unwrap().push(EncodingData::new(identifier));
//         self._current_data = Some(self._list_of_data.as_mut().unwrap().last_mut().unwrap());
//     }

//     pub fn set_identifier(&'a mut self, identifier: Identifier){
//         // check if current data length limit is reached or it is primitive
//         //  if it is create new data
//         //  otherwise, append to content of current data
//         if let Some(cur_data) = self._current_data.as_mut(){
//             if cur_data.identifier.data_type == DataType::Primitive ||  cur_data.is_length_limit_reached(){
//                 self._create_new_data(identifier);
//             } else {
//                 if let Some(content) = cur_data.content.as_mut(){
//                     if let Content::Constructed(children) = content{
//                         children.push(EncodingData{
//                             identifier,
//                             length: None,
//                             content: None
//                         })
//                     }
//                 }
//             }
//         } else {
//             self._create_new_data(identifier);
//         }
//     }
//     pub fn set_length(&'a mut self, length: Length){

//     }
//     pub fn set_content(&'a mut self, content: Content){

//     }

//     pub fn drop_borrow(&'a mut self){
//         self._current_data=None;
//     }
//     pub fn take_result<'b>(&'b mut self)->Vec<EncodingData>{
//         self._current_data=None;
//         return self._list_of_data.take().unwrap();
//     }
// }


pub type EncodingDataRcel = Rc<RefCell<EncodingData>>;

pub(super) struct EncodingDataOutputBuilder{
    _list_of_data: Option<Vec<EncodingDataRcel>>,
    _current_data: Option<EncodingDataRcel>
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

    pub fn add_identifier(&mut self, identifier: Identifier){
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
                    } else {
                        panic!("Something went wrong, data type is constructed, but content type is not of Constructed type")
                    }
                }
            }
        } else {
            self._create_new_data(identifier);
        }
    }
    pub fn add_length(&mut self, length: Length){
        let cur_data = self._current_data.as_ref().expect("Something went wrong, trying to add length when current data is none");
        cur_data.borrow_mut().length = Some(length);
    }
    pub fn add_content(&mut self, content: Content){
        let cur_data = self._current_data.as_ref().expect("Something went wrong, trying to add content when current data is none");
        cur_data.borrow_mut().content = Some(content);
    }   

    pub fn take_result(mut self)->Vec<EncodingData>{
        self._current_data=None;
        self._list_of_data.take().unwrap().into_iter().map(|data| Rc::try_unwrap(data).unwrap().into_inner()).collect()
    }

    pub fn get_cur_data(&self) -> Option<Rc<RefCell<EncodingData>>>{
        return self._current_data.clone()
    }
}

#[cfg(test)]
mod test {
    

    use crate::tlv_parser::{tlv::{Identifier, IdentifierClass, DataType, Length, Content, PrimitiveContent}, output_builder::EncodingDataOutputBuilder};

    fn create_test_identifier() -> Identifier{
        Identifier{
            class: IdentifierClass::Universal,
            data_type: DataType::Primitive,
            tag_number: 1
        }
    }

    fn create_test_length() -> Length{
        Length { length : 0}
    }

    fn create_test_content() -> Content{
        Content::Primitive(PrimitiveContent::Boolean(false))
    }

    #[test]
    fn test_add_id(){
        let mut builder = EncodingDataOutputBuilder::new();
        builder.add_identifier(create_test_identifier());
        let result = builder.take_result();

        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_add_id_twice(){
        let mut builder = EncodingDataOutputBuilder::new();
        builder.add_identifier(create_test_identifier());
        builder.add_identifier(create_test_identifier());
        let result = builder.take_result();

        assert_eq!(result.len(), 2);
    }


    #[test]
    fn test_add_length(){
        let mut builder = EncodingDataOutputBuilder::new();
        builder.add_identifier(create_test_identifier());
        builder.add_length(create_test_length());
        let result = builder.take_result();

        assert_eq!(result.len(), 1);
        assert!(result.first().as_ref().unwrap().length.is_some());
    }

    #[test]
    fn test_add_content(){
        let mut builder = EncodingDataOutputBuilder::new();
        builder.add_identifier(create_test_identifier());
        builder.add_content(create_test_content());
        let result = builder.take_result();

        assert_eq!(result.len(), 1);
        assert!(result.first().as_ref().unwrap().content.is_some());
    }

    #[test]
    fn test_add_after_second_id(){
        let mut builder = EncodingDataOutputBuilder::new();
        builder.add_identifier(create_test_identifier());
        builder.add_identifier(create_test_identifier());
        builder.add_length(create_test_length());
        builder.add_content(create_test_content());
        let result = builder.take_result();

        assert_eq!(result.len(), 2);
        assert!(result.last().as_ref().unwrap().length.is_some());
        assert!(result.last().as_ref().unwrap().content.is_some());
    }

    // #[test]
    // fn test_set_id2(){
    //     let mut builder = EncodingDataOutputBuilder2::new();
    //     builder.set_identifier(create_test_identifier());
    //     let result = builder.take_result();

    //     assert_eq!(result.len(), 1);
    // }
}