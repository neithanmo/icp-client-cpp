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
use std::{ffi::{CString, c_char, c_int, CStr}, ptr};
use candid::Principal;
use crate::{RetPtr};
#[repr(C)]
pub struct PrincipalRet<T> {
    ptr: *mut T,
    len: usize,
}

/// Construct a Principal of the IC management canister
#[no_mangle]
pub extern "C" fn principal_management_canister( ) -> PrincipalRet<u8> {
    let principal = Principal::management_canister();
    let arr = principal.as_ref();
    let len = arr.len();
    let ptr = Box::into_raw(arr.to_owned().into_boxed_slice()) as *mut u8;
    PrincipalRet { ptr, len }
}

/// Construct a self-authenticating ID from public key
#[no_mangle]
pub extern "C" fn principal_self_authenticating(
    public_key: *const u8,
    public_key_len: c_int) -> PrincipalRet<u8> {
    let public_key = unsafe { std::slice::from_raw_parts(public_key, public_key_len as usize) };
    let principal = Principal::self_authenticating(public_key);

    let arr = principal.as_ref();
    let len = arr.len();
    let ptr = Box::into_raw(arr.to_owned().into_boxed_slice()) as *mut u8;
    PrincipalRet { ptr, len }
}

/// Construct an anonymous ID
#[no_mangle]
pub extern "C" fn principal_anonymous() -> PrincipalRet<u8> {
    // Create an anonymous principal
    let principal = Principal::anonymous();
    let arr = principal.as_ref();
    let len = arr.len();
    let ptr = Box::into_raw(arr.to_owned().into_boxed_slice()) as *mut u8;
    PrincipalRet { ptr, len }
}

/// Construct a Principal from a slice of bytes.
#[no_mangle]
pub extern "C" fn principal_from_slice(
    bytes: *const u8,
    bytes_len: c_int ) -> PrincipalRet<u8> {
    
    //Compute Slice of bytes
    let slice = unsafe { std::slice::from_raw_parts(bytes, bytes_len as usize) };
    let principal = Principal::from_slice(slice);
    let arr = principal.as_ref();
    let len = arr.len();
    let ptr = Box::into_raw(arr.to_owned().into_boxed_slice()) as *mut u8;
    PrincipalRet { ptr, len }
}

/// Construct a Principal from a slice of bytes.
#[no_mangle]
pub extern "C" fn principal_try_from_slice(
    bytes: *const u8,
    bytes_len: c_int,
    error_ret: RetPtr<u8>
) -> PrincipalRet<u8> {
    //Compute Slice of bytes
    let slice = unsafe { std::slice::from_raw_parts(bytes, bytes_len as usize) };
    let principal_tmp = Principal::try_from_slice(slice);

    match principal_tmp {
        Ok(principal) => {
            // Pass empty error string to error_ret
            let empty_error = CString::new("").expect("Failed to create empty CString");
            let error_str = empty_error.into_raw() as *const u8;
            let error_len = 0;
            error_ret(error_str, error_len);

            let arr = principal.as_ref();
            let len = arr.len();
            let ptr = Box::into_raw(arr.to_owned().into_boxed_slice()) as *mut u8;
            PrincipalRet { ptr, len }

        }

        Err(e) => {
            let err_str = e.to_string();
            let c_string = CString::new(err_str.clone()).expect("Failed to convert to CString");
            let error_str = c_string.into_raw()  as *const u8;
            let error_len = err_str.len() as c_int;
            error_ret(error_str, error_len);

            let ptr = ptr::null_mut() as *mut u8;
            let len = 0;
            PrincipalRet { ptr, len }
        }
    }
}

/// Parse a Principal from text representation.
#[no_mangle]
pub extern "C" fn principal_from_text(
    text: *const c_char,
    error_ret: RetPtr<u8>) -> PrincipalRet<u8> {

    let text_cstr = unsafe {
        assert!(!text.is_null());
        CStr::from_ptr(text)
    };
    let text_str = text_cstr.to_str().unwrap();

    let principal_tmp = Principal::from_text(text_str);
    match principal_tmp {
        Ok(principal) => {
            // Pass empty error string to error_ret
            let empty_error = CString::new("").expect("Failed to create empty CString");
            let error_str = empty_error.into_raw() as *const u8;
            let error_len = 0;
            error_ret(error_str, error_len);

            let arr = principal.as_ref();
            let len = arr.len();
            let ptr = Box::into_raw(arr.to_owned().into_boxed_slice()) as *mut u8;
            PrincipalRet { ptr, len }
        }

        Err(e) => {
            let err_str = e.to_string();
            let c_string = CString::new(err_str.clone()).expect("Failed to convert to CString");
            let error_str = c_string.into_raw()  as *const u8;
            let error_len = err_str.len() as c_int;
            error_ret(error_str, error_len);

            let ptr = ptr::null_mut() as *mut u8;
            let len = 0;
            PrincipalRet { ptr, len }
        }
    }
}

/// Return the textual representation of Principal.
#[no_mangle]
pub extern "C" fn principal_to_text(
    bytes: *const u8,
    bytes_len: *const c_int,
    error_ret: RetPtr<u8>
) -> PrincipalRet<u8> {

    let slice = unsafe { std::slice::from_raw_parts(bytes, bytes_len as usize) };
    let principal_tmp = Principal::try_from_slice(slice);

    match principal_tmp {
        Ok(principal) => {
            // Pass empty error string to error_ret
            let empty_error = CString::new("").expect("Failed to create empty CString");
            let error_str = empty_error.into_raw() as *const u8;
            let error_len = 0;
            error_ret(error_str, error_len);

            let arr = CString::new(principal.to_text()).expect("Failed to convert to CString");
            let len = arr.as_bytes().len();
            let ptr = arr.into_raw() as *mut u8;
            PrincipalRet { ptr, len }
        }
        Err(e) => {
            let err_str = e.to_string();
            let c_string = CString::new(err_str.clone()).expect("Failed to convert to CString");
            let error_str = c_string.into_raw()  as *const u8;
            let error_len = err_str.len() as c_int;
            error_ret(error_str, error_len);

            let ptr = ptr::null_mut() as *mut u8;
            let len = 0;
            PrincipalRet { ptr, len }
        }
    }

}

#[no_mangle]
pub extern "C" fn principal_free(ptr: *mut u8) {
    if !ptr.is_null() {
        unsafe {
            drop(Box::from_raw(ptr));
        }
    }
}

mod tests{
    #[allow(unused)]
    use core::slice;
    #[allow(unused)]
    use std::ffi::CStr;

    #[allow(unused)]
    use super::*;

    #[test]
    fn test_principal_anonymous() {
        let principal = principal_anonymous();
        let slice = unsafe { std::slice::from_raw_parts(principal.ptr, principal.len as usize) };
        assert_eq!(slice.len(), 1);
        assert_eq!(slice[0], 4);
    }

    #[test]
    fn test_principal_management_canister() {
        let principal = principal_management_canister();
        assert_eq!(principal.len, 0);
    }

    #[test]
    fn test_principal_self_authenticating() {
        const PK: [u8; 32] = [
            0x11, 0xaa, 0x11, 0xaa, 0x11, 0xaa, 0x11, 0xaa, 0x11,
            0xaa, 0x11, 0xaa, 0x11, 0xaa, 0xaa, 0x11, 0xaa, 0x11,
            0xaa, 0x11, 0xaa, 0x11, 0xaa, 0x11, 0xaa, 0x11, 0xaa,
            0x11, 0x11, 0xaa, 0x11, 0xaa,
        ];
        const PRINCIPAL: [u8; 29] = [
            0x9e, 0x3a, 0xde, 0x5f, 0xe2 ,0x5a, 0x80, 0x89, 0x4d,
            0x27, 0x04, 0xe8, 0x44, 0xff, 0xf8, 0x80, 0x30, 0x75,
            0x06, 0x93, 0x09, 0x86, 0xed, 0xf5, 0x4c, 0xc4, 0xfb,
            0xad, 0x02,
        ];

        let principal = principal_self_authenticating(PK.as_ptr(), PK.len() as c_int);
        let slice = unsafe { std::slice::from_raw_parts(principal.ptr, principal.len as usize) };

        assert_eq!(slice, &PRINCIPAL[..]);
    }

    #[test]
    fn test_principal_to_text() {
        const TEXT: &[u8; 8] = b"aaaaa-aa";

        extern "C" fn error_ret(_data: *const u8, _len: c_int) {}

        let principal = principal_to_text([0u8; 0].as_ptr(), 0 as *const i32,error_ret);
        let slice = unsafe { std::slice::from_raw_parts(principal.ptr, principal.len as usize) };

        assert_eq!(slice, TEXT);
    }

    #[test]
    fn test_principal_from_text() {
        const ANONYMOUS_TEXT: &[u8; 28] = b"rrkah-fqaaa-aaaaa-aaaaq-cai\0";
        const BYTES: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 1, 1, 1];

        extern "C" fn error_ret(_data: *const u8, _len: c_int) {}

        let principal = principal_from_text(ANONYMOUS_TEXT.as_ptr() as *const c_char, error_ret);
        let slice = unsafe { std::slice::from_raw_parts(principal.ptr, principal.len as usize) };

        assert_eq!(slice, BYTES);
    }

}
