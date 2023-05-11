
/*******************************************************************************
*   (c) 2018 - 2023 Zondax AG
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/
use std::{ffi::{c_char, CStr, CString, c_int}, str::FromStr, ptr};
use candid::parser::value::IDLValue;
use candid::IDLArgs;
use libc::c_void;

use crate::{RetPtr, AnyErr};

#[no_mangle]
pub extern "C" fn idl_args_to_text(idl_args: *const c_void) -> *mut c_char {

    let boxed = unsafe { Box::from_raw(idl_args as *mut IDLArgs) };
    let idl_str = boxed.to_string() + "\0";

    let arr = idl_str.as_bytes();
    Box::into_raw(arr.to_owned().into_boxed_slice()) as *mut c_char
}

#[no_mangle]
pub extern "C" fn idl_args_from_text(
    text: *const c_char,
    error_ret: RetPtr<u8>,
) -> *const c_void {
    let text = unsafe { CStr::from_ptr(text).to_str().map_err(AnyErr::from) };

    let idl_value = text.and_then(|text| IDLArgs::from_str(text).map_err(AnyErr::from));

     match idl_value {
        Ok(t) => {
            // Pass empty error string to error_ret
            let empty_error = CString::new("").expect("Failed to create empty CString");
            let error_str = empty_error.into_raw() as *const u8;
            let error_len = 0;
            error_ret(error_str, error_len);
            Box::into_raw(Box::new(t)) as *mut c_void
        }
        Err(e) => {
            let err_str = e.to_string();
            let c_string = CString::new(err_str.clone()).expect("Failed to convert to CString");
            let error_str = c_string.into_raw()  as *const u8;
            let error_len = err_str.len() as c_int;
            error_ret(error_str, error_len);
            ptr::null_mut() as *mut c_void
        }
    }
}


#[cfg(test)]
mod tests {
    use candid::Principal;
    use super::*;
    use std::ops::Deref;

    const IDL_VALUES: [IDLValue; 3] = [
        IDLValue::Bool(true),
        IDLValue::Principal(Principal::anonymous()),
        IDLValue::Int32(-12),
    ];

    const IDL_ARGS_TEXT: &str = r#"(true, principal "2vxsx-fae", -12 : int32)"#;
    const IDL_ARGS_TEXT_C: &str = "(true, principal \"2vxsx-fae\", -12 : int32)\0";

    const IDL_ARGS_BYTES: &[u8] = &[
        68, 73, 68, 76, 0, 3, 126, 104, 117, 1, 1, 1, 4, 244, 255, 255, 255,
    ];

    extern "C" fn error_ret(_data: *const u8, _len: c_int) {}

    #[test]
    fn idl_args_to_text_should_work() {

        let idl_args = IDLArgs::new(&IDL_VALUES);

        let idl_args_boxed = Box::new(idl_args);
        let ptr = Box::into_raw(idl_args_boxed);

        let result = idl_args_to_text(ptr as *const c_void);
        
        let c_str = unsafe { CStr::from_ptr(result as *const i8) };
        let str = c_str.to_str().unwrap();

        assert_eq!(IDL_ARGS_TEXT, str);

    }

    #[test]
    fn idl_args_from_text_should_work() {

        let ptr = idl_args_from_text(
                IDL_ARGS_TEXT_C.as_ptr() as *const c_char,
                error_ret
        );

        let boxed = unsafe { Box::from_raw(ptr as *mut IDLArgs) };
        assert_eq!(&IDLArgs::new(&IDL_VALUES), boxed.as_ref());
    }

}
