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
#![allow(non_snake_case)]

use std::{ffi::{c_char, CStr, CString}};
use cty::{c_int};
use ic_agent::{identity::{AnonymousIdentity, BasicIdentity, Secp256k1Identity}, Identity, Signature};
use k256::SecretKey;
use ring::signature::Ed25519KeyPair;
use crate::{AnyErr, RetPtr};


#[allow(dead_code)]
#[repr(C)]
#[derive(Debug, Eq, PartialEq, Copy, Clone, Hash)]
pub enum IdentityType {
    /// anonym
    Anonym = 0,
    /// basic
    Basic = 1,
    /// secp256k1
    Secp256k1 = 2,
}

/// Dummy
#[no_mangle]
pub extern "C" fn identity_type(id_type: IdentityType) -> IdentityType{
    id_type
}


/// The anonymous identity.
#[no_mangle]
pub extern "C" fn identity_anonymous( ) -> *mut c_char {
    let anonymous_id = Box::new(AnonymousIdentity {});
    let identity: *mut c_char = Box::into_raw(anonymous_id) as *mut c_char;
    identity
}

/// Create a BasicIdentity from reading a PEM Content
#[no_mangle]
pub extern "C" fn identity_basic_from_pem(
    pem_data: *const c_char,
    error_ret: RetPtr<u8>) -> *mut c_char {

    let pem_cstr = unsafe {
        assert!(!pem_data.is_null());
        CStr::from_ptr(pem_data)
    };
    let pem_str = pem_cstr.to_str().map_err(AnyErr::from);
    let basic_id =
        pem_str.and_then(|pem_str| BasicIdentity::from_pem(pem_str.as_bytes()).map_err(AnyErr::from));

    match basic_id {
        Ok(identity) => {
            // Pass empty error string to error_ret
            let empty_error = CString::new("").expect("Failed to create empty CString");
            let error_str = empty_error.into_raw() as *const u8;
            let error_len = 0;
            error_ret(error_str, error_len);
            
            let identity_tmp: *mut c_char = Box::into_raw(Box::new(identity)) as *mut c_char;
            identity_tmp
        }
        Err(e) => {
            let err_str = e.to_string();
            let c_string = CString::new(err_str.clone()).expect("Failed to convert to CString");

            // Pass error string to error_ret
            let error_str = c_string.into_raw()  as *const u8;
            let error_len = err_str.len() as c_int;
            error_ret(error_str, error_len);

            let empty_string = CString::new("").expect("Failed to create empty CString");
            empty_string.into_raw()
        }
    }
}


/// Create a BasicIdentity from a KeyPair from the ring crate.
#[no_mangle]
pub extern "C" fn identity_basic_from_key_pair(
    public_key: *const u8,
    private_key_seed: *const u8,
    error_ret: RetPtr<u8>) -> *mut c_char {

    let public_key_slice =  unsafe {std::slice::from_raw_parts(public_key as *const u8, 32)};
    let private_key_seed_slice =  unsafe {std::slice::from_raw_parts(private_key_seed as *const u8, 32)};

    match Ed25519KeyPair::from_seed_and_public_key(private_key_seed_slice, public_key_slice) {
        Ok(key_pair) => {
            // Pass empty error string to error_ret
            let empty_error = CString::new("").expect("Failed to create empty CString");
            let error_str = empty_error.into_raw() as *const u8;
            let error_len = 0;
            error_ret(error_str, error_len);

            let basic_id = BasicIdentity::from_key_pair(key_pair);
            let identity_tmp: *mut c_char = Box::into_raw(Box::new(basic_id)) as *mut c_char;
            identity_tmp
        }
        Err(e) => {
            let err_str = e.to_string();
            let c_string = CString::new(err_str.clone()).expect("Failed to convert to CString");

            // Pass error string to error_ret
            let error_str = c_string.into_raw()  as *const u8;
            let error_len = err_str.len() as c_int;
            error_ret(error_str, error_len);

            let empty_string = CString::new("").expect("Failed to create empty CString");
            empty_string.into_raw()
        }
    }
}

/// Creates an identity from a PEM certificate.
#[no_mangle]
pub extern "C" fn identity_secp256k1_from_pem(
    pem_data: *const c_char,
    error_ret: RetPtr<u8>) -> *mut c_char {

    let pem_cstr = unsafe {
        assert!(!pem_data.is_null());
        CStr::from_ptr(pem_data)
    };
    let pem_str = pem_cstr.to_str().map_err(AnyErr::from);
    let basic_id =
        pem_str.and_then(|pem_str| Secp256k1Identity::from_pem(pem_str.as_bytes()).map_err(AnyErr::from));

    match basic_id {
        Ok(identity) => {
            // Pass empty error string to error_ret
            let empty_error = CString::new("").expect("Failed to create empty CString");
            let error_str = empty_error.into_raw() as *const u8;
            let error_len = 0;
            error_ret(error_str, error_len);
            let identity_tmp: *mut c_char = Box::into_raw(Box::new(identity)) as *mut c_char;
            identity_tmp
        }
        Err(e) => {
            let err_str = e.to_string();
            let c_string = CString::new(err_str.clone()).expect("Failed to convert to CString");

            // Pass error string to error_ret
            let error_str = c_string.into_raw()  as *const u8;
            let error_len = err_str.len() as c_int;
            error_ret(error_str, error_len);

            let empty_string = CString::new("").expect("Failed to create empty CString");
            empty_string.into_raw()
        }
    }
}

/// Creates an identity from a private key.
#[no_mangle]
pub extern "C" fn identity_secp256k1_from_private_key(
    private_key: *const c_char,
    pk_len: usize) -> *mut c_char {

    let pk = unsafe { std::slice::from_raw_parts(private_key as *const u8, pk_len) };
    let pk = SecretKey::from_be_bytes(pk).unwrap();

    let anonymous_id = Box::new(Secp256k1Identity::from_private_key(pk));
    let identity: *mut c_char = Box::into_raw(anonymous_id) as *mut c_char;
    identity
}

/// Returns a sender, ie. the Principal ID that is used to sign a request.
/// Only one sender can be used per request.
#[no_mangle]
pub extern "C" fn identity_sender(
    id_ptr: *mut c_char,
    idType: IdentityType,
    error_ret: RetPtr<u8>) -> *mut c_char {

    unsafe {
        match idType {
            IdentityType::Anonym => {
                let boxed = Box::from_raw(id_ptr as *mut AnonymousIdentity);
                let principal = boxed.sender();
                    match principal {
                        Ok(principal) => {
                            // Pass empty error string to error_ret
                            let empty_error = CString::new("").expect("Failed to create empty CString");
                            let error_str = empty_error.into_raw() as *const u8;
                            let error_len = 0;
                            error_ret(error_str, error_len);

                            let c_string = CString::new(principal.as_slice()).expect("CString conversion failed.");
                            let c_string_ptr = c_string.into_raw();
                            c_string_ptr as *mut c_char
                        }

                        Err(e) => {
                            let err_str = e.to_string();
                            let c_string = CString::new(err_str.clone()).expect("Failed to convert to CString");

                            // Pass error string to error_ret
                            let error_str = c_string.into_raw()  as *const u8;
                            let error_len = err_str.len() as c_int;
                            error_ret(error_str, error_len);

                            let empty_string = CString::new("").expect("Failed to create empty CString");
                            empty_string.into_raw()
                        }
                    }
            }
            IdentityType::Basic => {
                let boxed = Box::from_raw(id_ptr as *mut BasicIdentity);
                let principal = boxed.sender();
                    match principal {
                        Ok(principal) => {
                            // Pass empty error string to error_ret
                            let empty_error = CString::new("").expect("Failed to create empty CString");
                            let error_str = empty_error.into_raw() as *const u8;
                            let error_len = 0;
                            error_ret(error_str, error_len);

                            let c_string = CString::new(principal.as_slice()).expect("CString conversion failed.");
                            let c_string_ptr = c_string.into_raw();
                            c_string_ptr as *mut c_char
                        }

                        Err(e) => {
                            let err_str = e.to_string();
                            let c_string = CString::new(err_str.clone()).expect("Failed to convert to CString");

                            // Pass error string to error_ret
                            let error_str = c_string.into_raw()  as *const u8;
                            let error_len = err_str.len() as c_int;
                            error_ret(error_str, error_len);

                            let empty_string = CString::new("").expect("Failed to create empty CString");
                            empty_string.into_raw()
                        }
                    }
            }
            IdentityType::Secp256k1 => {
                let boxed = Box::from_raw(id_ptr as *mut Secp256k1Identity);
                let principal = boxed.sender();
                    match principal {
                        Ok(principal) => {
                            // Pass empty error string to error_ret
                            let empty_error = CString::new("").expect("Failed to create empty CString");
                            let error_str = empty_error.into_raw() as *const u8;
                            let error_len = 0;
                            error_ret(error_str, error_len);

                            let c_string = CString::new(principal.as_slice()).expect("CString conversion failed.");
                            let c_string_ptr = c_string.into_raw();
                            c_string_ptr as *mut c_char
                        }

                        Err(e) => {
                            let err_str = e.to_string();
                            let c_string = CString::new(err_str.clone()).expect("Failed to convert to CString");

                            // Pass error string to error_ret
                            let error_str = c_string.into_raw()  as *const u8;
                            let error_len = err_str.len() as c_int;
                            error_ret(error_str, error_len);

                            let empty_string = CString::new("").expect("Failed to create empty CString");
                            empty_string.into_raw()
                        }
                    }
            }
        }
    }
}

/// Sign a blob, the concatenation of the domain separator & request ID,
/// creating the sender signature.>
#[no_mangle]
pub extern "C" fn identity_sign(
    bytes: *const u8,
    bytes_len: c_int,
    id_ptr: *mut c_char,
    idType: IdentityType,
    pubkey_ret: RetPtr<u8>,
    error_ret: RetPtr<u8>,
) -> *mut c_char {

    unsafe {
        match idType {
            IdentityType::Anonym => {
                let boxed = Box::from_raw(id_ptr as *mut AnonymousIdentity);
                let blob = std::slice::from_raw_parts(bytes, bytes_len as usize);
                let signature = boxed.sign(blob);

                match signature {
                    Ok(Signature {
                        public_key,
                        signature,
                    }) => {
                        // Pass empty error string to error_ret
                        let empty_error = CString::new("").expect("Failed to create empty CString");
                        let error_str = empty_error.into_raw() as *const u8;
                        let error_len = 0;
                        error_ret(error_str, error_len);

                        let public_key = public_key.unwrap_or_default();
                        let signature = signature.unwrap_or_default();

                        let arr = public_key.as_slice();
                        let len = arr.len() as c_int;
                        pubkey_ret(arr.as_ptr(), len);

                        let c_string = CString::new(signature.as_slice()).expect("CString conversion failed.");
                        let c_string_ptr = c_string.into_raw();
                        c_string_ptr as *mut c_char
                    }
                    Err(err) => {
                        let err_str = err.to_string();
                        let c_string = CString::new(err_str.clone()).expect("Failed to convert to CString");

                        // Pass error string to error_ret
                        let error_str = c_string.into_raw()  as *const u8;
                        let error_len = err_str.len() as c_int;
                        error_ret(error_str, error_len);

                        let empty_string = CString::new("").expect("Failed to create empty CString");
                        empty_string.into_raw()
                    }
                }
            }
            IdentityType::Basic => {
                let boxed = Box::from_raw(id_ptr as *mut BasicIdentity);
                let blob = std::slice::from_raw_parts(bytes, bytes_len as usize);
                let signature = boxed.sign(blob);

                match signature {
                    Ok(Signature {
                        public_key,
                        signature,
                    }) => {
                        // Pass empty error string to error_ret
                        let empty_error = CString::new("").expect("Failed to create empty CString");
                        let error_str = empty_error.into_raw() as *const u8;
                        let error_len = 0;
                        error_ret(error_str, error_len);

                        let public_key = public_key.unwrap_or_default();
                        let signature = signature.unwrap_or_default();

                        let arr = public_key.as_slice();
                        let len = arr.len() as c_int;
                        pubkey_ret(arr.as_ptr(), len);

                        let c_string = CString::new(signature.as_slice()).expect("CString conversion failed.");
                        let c_string_ptr = c_string.into_raw();
                        c_string_ptr as *mut c_char
                    }
                    Err(err) => {
                        let err_str = err.to_string();
                        let c_string = CString::new(err_str.clone()).expect("Failed to convert to CString");

                        // Pass error string to error_ret
                        let error_str = c_string.into_raw()  as *const u8;
                        let error_len = err_str.len() as c_int;
                        error_ret(error_str, error_len);

                        let empty_string = CString::new("").expect("Failed to create empty CString");
                        empty_string.into_raw()
                    }
                }
            }
            IdentityType::Secp256k1 => {
                let boxed = Box::from_raw(id_ptr as *mut Secp256k1Identity);
                let blob = std::slice::from_raw_parts(bytes, bytes_len as usize);
                let signature = boxed.sign(blob);

                match signature {
                    Ok(Signature {
                        public_key,
                        signature,
                    }) => {
                        // Pass empty error string to error_ret
                        let empty_error = CString::new("").expect("Failed to create empty CString");
                        let error_str = empty_error.into_raw() as *const u8;
                        let error_len = 0;
                        error_ret(error_str, error_len);

                        let public_key = public_key.unwrap_or_default();
                        let signature = signature.unwrap_or_default();

                        let arr = public_key.as_slice();
                        let len = arr.len() as c_int;
                        pubkey_ret(arr.as_ptr(), len);

                        let c_string = CString::new(signature.as_slice()).expect("CString conversion failed.");
                        let c_string_ptr = c_string.into_raw();
                        c_string_ptr as *mut c_char
                    }
                    Err(err) => {
                        let err_str = err.to_string();
                        let c_string = CString::new(err_str.clone()).expect("Failed to convert to CString");

                        // Pass error string to error_ret
                        let error_str = c_string.into_raw()  as *const u8;
                        let error_len = err_str.len() as c_int;
                        error_ret(error_str, error_len);

                        let empty_string = CString::new("").expect("Failed to create empty CString");
                        empty_string.into_raw()
                    }
                }
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn identity_free(ptr: *mut c_char) {
    let boxed = unsafe { Box::from_raw(ptr ) };

    drop(boxed);
}

#[cfg(test)]
mod tests {
    use candid::Principal;
    use ic_agent::{Identity};

    #[allow(unused)]
    use super::*;
    const BASIC_ID_FILE: &'static str = "-----BEGIN PRIVATE KEY-----
MFMCAQEwBQYDK2VwBCIEIL9r4XBKsg4pquYBHY6rgfzuBsvCy89tgqDfDpofXRBP
oSMDIQBCkE1NL4X43clXS1LFauiceiiKW9NhjVTEpU6LpH9Qcw==
-----END PRIVATE KEY-----\0";

    const SECP256K1_ID_FILE: &str = "-----BEGIN EC PARAMETERS-----
BgUrgQQACg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIAgy7nZEcVHkQ4Z1Kdqby8SwyAiyKDQmtbEHTIM+WNeBoAcGBSuBBAAK
oUQDQgAEgO87rJ1ozzdMvJyZQ+GABDqUxGLvgnAnTlcInV3NuhuPv4O3VGzMGzeB
N3d26cRxD99TPtm8uo2OuzKhSiq6EQ==
-----END EC PRIVATE KEY-----\0";

    #[test]
    fn test_identity_anonymous() {

        let identity =identity_anonymous();
        assert!(!identity.is_null());

        unsafe {
             let boxed = Box::from_raw(identity as *mut AnonymousIdentity);
             assert_eq!(boxed.sender(), Ok(Principal::anonymous()));
        }
    }

    #[test]
    fn test_identity_sender() {
        let identity = identity_anonymous();
        unsafe {
             let boxed = Box::from_raw(identity as *mut AnonymousIdentity);
             assert_eq!(boxed.sender(), Ok(Principal::anonymous()));
        }
        
        extern "C" fn error_ret(_data: *const u8, _len: c_int) {}

        let principal = identity_sender(identity, IdentityType::Anonym, error_ret);
        assert!(!principal.is_null());
    }

    #[test]
    fn test_identity_basic_from_pem() {

        extern "C" fn error_ret(_data: *const u8, _len: c_int) {}

        let id = identity_basic_from_pem(
                BASIC_ID_FILE.as_ptr() as *const c_char,
                error_ret
            );
        assert!(!id.is_null());

        unsafe {
            let boxed = Box::from_raw(id as *mut BasicIdentity);
            let basic = BasicIdentity::from_pem(BASIC_ID_FILE.as_bytes()).unwrap();
            assert_eq!(boxed.sender(), basic.sender());
        }
    }

    #[test]
    fn test_identity_secp256k1_from_pem() {
        extern "C" fn error_ret(_data: *const u8, _len: c_int) {}

        let id = identity_secp256k1_from_pem(
                SECP256K1_ID_FILE.as_ptr() as *const c_char,
                error_ret
            );

        unsafe {
            let boxed = Box::from_raw(id as *mut Secp256k1Identity);
            let secp = Secp256k1Identity::from_pem(SECP256K1_ID_FILE.as_bytes()).unwrap();
            assert_eq!(boxed.sender(), secp.sender());
        }
    }
}
