extern crate lazy_static;

mod module;
mod pkcs11;

use lazy_static::lazy_static;
use module::{Error, Module, Result};
use pkcs11::*;
use std::ops;
use std::sync;

fn err_not_implemented(name: &str) -> CK_RV {
    eprintln!("{}() not implemented", name);
    return CKR_FUNCTION_FAILED as CK_RV;
}

lazy_static! {
    // The module as a global singleton held by a mutex. This its set through calls to C_Initialize
    // and cleaned up by C_Finalize.
    //
    // Use result_to_rv_with_mod to access this.
    static ref MODULE: sync::Mutex<Option<Module>> = sync::Mutex::new(None);
}

// Helper function to convert a function that returns a result to a CK_RV, logging any errors. The
// fn_name should be the corresponding PKCS #11 function this is called by, for example
// "C_GetInfo".
fn result_to_rv<F>(fn_name: &str, f: F) -> CK_RV
where
    F: ops::FnOnce() -> Result<()>,
{
    return match f() {
        Ok(()) => CKR_OK as CK_RV,
        Err(err) => {
            eprintln!("{}() {}", fn_name, err);
            err.rv()
        }
    };
}

// Helper function that allows mutable access to the global Module, while also converting the
// Result to a CK_RV suitable to be returned from a PKCS #11 function. Similar to result_to_rv(),
// fn_name should be the corresponding PKCS #11 function.
//
// ```
// return result_to_rv_with_mod("C_GetSlotList", |mod| {
//     // Use "mod" to retrieve the slot list.
//     // ...
//
//     return Ok(());
// });
// ```
fn result_to_rv_with_mod<F>(fn_name: &str, f: F) -> CK_RV
where
    F: ops::FnOnce(&mut Module) -> Result<()>,
{
    return result_to_rv(fn_name, || {
        let mut o = MODULE
            .lock()
            .map_err(|err| errorf!(CKR_GENERAL_ERROR, "failed to acquire lock: {}", err))?;
        let mut m = o.as_mut().ok_or(errorf!(
            CKR_CRYPTOKI_NOT_INITIALIZED,
            "module not initialized"
        ))?;
        return f(&mut m);
    });
}

static mut FUNC_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: CK_VERSION { major: 0, minor: 0 },
    C_Initialize: Some(C_Initialize),
    C_Finalize: Some(C_Finalize),
    C_GetInfo: Some(C_GetInfo),
    C_GetFunctionList: Some(C_GetFunctionList),
    C_GetSlotList: Some(C_GetSlotList),
    C_GetSlotInfo: Some(C_GetSlotInfo),
    C_GetTokenInfo: Some(C_GetTokenInfo),
    C_GetMechanismList: Some(C_GetMechanismList),
    C_GetMechanismInfo: Some(C_GetMechanismInfo),
    C_InitToken: Some(C_InitToken),
    C_InitPIN: Some(C_InitPIN),
    C_SetPIN: Some(C_SetPIN),
    C_OpenSession: Some(C_OpenSession),
    C_CloseSession: Some(C_CloseSession),
    C_CloseAllSessions: Some(C_CloseAllSessions),
    C_GetSessionInfo: Some(C_GetSessionInfo),
    C_GetOperationState: Some(C_GetOperationState),
    C_SetOperationState: Some(C_SetOperationState),
    C_Login: Some(C_Login),
    C_Logout: Some(C_Logout),
    C_CreateObject: Some(C_CreateObject),
    C_CopyObject: Some(C_CopyObject),
    C_DestroyObject: Some(C_DestroyObject),
    C_GetObjectSize: Some(C_GetObjectSize),
    C_GetAttributeValue: Some(C_GetAttributeValue),
    C_SetAttributeValue: Some(C_SetAttributeValue),
    C_FindObjectsInit: Some(C_FindObjectsInit),
    C_FindObjects: Some(C_FindObjects),
    C_FindObjectsFinal: Some(C_FindObjectsFinal),
    C_EncryptInit: Some(C_EncryptInit),
    C_Encrypt: Some(C_Encrypt),
    C_EncryptUpdate: Some(C_EncryptUpdate),
    C_EncryptFinal: Some(C_EncryptFinal),
    C_DecryptInit: Some(C_DecryptInit),
    C_Decrypt: Some(C_Decrypt),
    C_DecryptUpdate: Some(C_DecryptUpdate),
    C_DecryptFinal: Some(C_DecryptFinal),
    C_DigestInit: Some(C_DigestInit),
    C_Digest: Some(C_Digest),
    C_DigestUpdate: Some(C_DigestUpdate),
    C_DigestKey: Some(C_DigestKey),
    C_DigestFinal: Some(C_DigestFinal),
    C_SignInit: Some(C_SignInit),
    C_Sign: Some(C_Sign),
    C_SignUpdate: Some(C_SignUpdate),
    C_SignFinal: Some(C_SignFinal),
    C_SignRecoverInit: Some(C_SignRecoverInit),
    C_SignRecover: Some(C_SignRecover),
    C_VerifyInit: Some(C_VerifyInit),
    C_Verify: Some(C_Verify),
    C_VerifyUpdate: Some(C_VerifyUpdate),
    C_VerifyFinal: Some(C_VerifyFinal),
    C_VerifyRecoverInit: Some(C_VerifyRecoverInit),
    C_VerifyRecover: Some(C_VerifyRecover),
    C_DigestEncryptUpdate: Some(C_DigestEncryptUpdate),
    C_DecryptDigestUpdate: Some(C_DecryptDigestUpdate),
    C_SignEncryptUpdate: Some(C_SignEncryptUpdate),
    C_DecryptVerifyUpdate: Some(C_DecryptVerifyUpdate),
    C_GenerateKey: Some(C_GenerateKey),
    C_GenerateKeyPair: Some(C_GenerateKeyPair),
    C_WrapKey: Some(C_WrapKey),
    C_UnwrapKey: Some(C_UnwrapKey),
    C_DeriveKey: Some(C_DeriveKey),
    C_SeedRandom: Some(C_SeedRandom),
    C_GenerateRandom: Some(C_GenerateRandom),
    C_GetFunctionStatus: Some(C_GetFunctionStatus),
    C_CancelFunction: Some(C_CancelFunction),
    C_WaitForSlotEvent: Some(C_WaitForSlotEvent),
};

#[no_mangle]
pub extern "C" fn C_Initialize(init_args: CK_VOID_PTR) -> CK_RV {
    return result_to_rv("C_Initialize", || {
        if !init_args.is_null() {
            let args = unsafe { *(init_args as CK_C_INITIALIZE_ARGS_PTR) };
            if args.flags & (CKF_LIBRARY_CANT_CREATE_OS_THREADS as u64) != 0 {
                return Err(errorf!(
                    CKR_NEED_TO_CREATE_THREADS,
                    "library requires use of OS threads"
                ));
            }
        }

        let m = Module::new()
            .map_err(|err| errorf!(CKR_FUNCTION_FAILED, "failed to initialize module: {}", err))?;

        let mut o = MODULE
            .lock()
            .map_err(|err| errorf!(CKR_GENERAL_ERROR, "failed to acquire lock: {}", err))?;
        *o = Some(m);
        return Ok(());
    });
}

#[no_mangle]
pub extern "C" fn C_GetInfo(_info_ptr: CK_INFO_PTR) -> CK_RV {
    return err_not_implemented("C_GetInfo");
}

#[no_mangle]
pub extern "C" fn C_GetSlotInfo(_slot_id: CK_SLOT_ID, _slot_info_ptr: CK_SLOT_INFO_PTR) -> CK_RV {
    return err_not_implemented("C_GetSlotInfo");
}

#[no_mangle]
pub extern "C" fn C_GetTokenInfo(_slot_id: CK_SLOT_ID, _info_ptr: CK_TOKEN_INFO_PTR) -> CK_RV {
    return err_not_implemented("C_GetTokenInfo");
}

#[no_mangle]
pub extern "C" fn C_GetFunctionList(function_list: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    unsafe {
        *function_list = &mut FUNC_LIST as CK_FUNCTION_LIST_PTR;
    }
    return CKR_OK as CK_RV;
}

#[no_mangle]
extern "C" fn C_GetMechanismList(
    _slot_id: CK_SLOT_ID,
    _mechanism_list_ptr: CK_MECHANISM_TYPE_PTR,
    _count_ptr: CK_ULONG_PTR,
) -> CK_RV {
    return err_not_implemented("C_GetMechanismList");
}

#[no_mangle]
extern "C" fn C_GetMechanismInfo(
    _slot_id: CK_SLOT_ID,
    _typ: CK_MECHANISM_TYPE,
    _info_ptr: CK_MECHANISM_INFO_PTR,
) -> CK_RV {
    return err_not_implemented("C_GetMechanismInfo");
}

#[no_mangle]
pub extern "C" fn C_GetSlotList(
    _token_present: CK_BBOOL,
    _slot_list_ptr: CK_SLOT_ID_PTR,
    _count_ptr: CK_ULONG_PTR,
) -> CK_RV {
    return err_not_implemented("C_GetSlotList");
}

#[no_mangle]

pub extern "C" fn C_OpenSession(
    _slot_id: CK_SLOT_ID,
    _flags: CK_FLAGS,
    _app_ptr: CK_VOID_PTR,
    _notify: CK_NOTIFY,
    _h_ptr: CK_SESSION_HANDLE_PTR,
) -> CK_RV {
    return err_not_implemented("C_OpenSession");
}

#[no_mangle]
pub extern "C" fn C_CloseSession(_h: CK_SESSION_HANDLE) -> CK_RV {
    return err_not_implemented("C_CloseSession");
}

#[no_mangle]
pub extern "C" fn C_CloseAllSessions(_slot_id: CK_SLOT_ID) -> CK_RV {
    return err_not_implemented("C_CloseAllSession");
}

#[no_mangle]
pub extern "C" fn C_Finalize(_reserved: CK_VOID_PTR) -> CK_RV {
    return result_to_rv("C_Finalize", || {
        let mut o = MODULE
            .lock()
            .map_err(|err| errorf!(CKR_GENERAL_ERROR, "failed to acquire lock: {}", err))?;
        *o = None;
        return Ok(());
    });
}

#[no_mangle]
pub extern "C" fn C_InitToken(
    _slot_id: CK_SLOT_ID,
    _pin_ptr: CK_UTF8CHAR_PTR,
    _pin_len: CK_ULONG,
    _label_ptr: CK_UTF8CHAR_PTR,
) -> CK_RV {
    return err_not_implemented("C_InitToken");
}

#[no_mangle]
pub extern "C" fn C_InitPIN(
    _h: CK_SESSION_HANDLE,
    _pin_ptr: CK_UTF8CHAR_PTR,
    _pin_len: CK_ULONG,
) -> CK_RV {
    return err_not_implemented("C_InitPIN");
}

#[no_mangle]
pub extern "C" fn C_SetPIN(
    _h: CK_SESSION_HANDLE,
    _old_pin_ptr: CK_UTF8CHAR_PTR,
    _old_pin_len: CK_ULONG,
    _new_pin_ptr: CK_UTF8CHAR_PTR,
    _new_pin_len: CK_ULONG,
) -> CK_RV {
    return err_not_implemented("C_SetPIN");
}

#[no_mangle]
pub extern "C" fn C_GetSessionInfo(_h: CK_SESSION_HANDLE, _info_ptr: CK_SESSION_INFO_PTR) -> CK_RV {
    return err_not_implemented("C_GetSessionInfo");
}

#[no_mangle]
pub extern "C" fn C_GetOperationState(
    _h: CK_SESSION_HANDLE,
    _operation_state_ptr: CK_BYTE_PTR,
    _operation_state_len_ptr: CK_ULONG_PTR,
) -> CK_RV {
    return err_not_implemented("C_GetOperationState");
}

#[no_mangle]
extern "C" fn C_SetOperationState(
    _h: CK_SESSION_HANDLE,
    _operation_state_ptr: CK_BYTE_PTR,
    _operation_state_len: CK_ULONG,
    _encryption_key_h: CK_OBJECT_HANDLE,
    _authentication_key_h: CK_OBJECT_HANDLE,
) -> CK_RV {
    return err_not_implemented("C_SetOperationState");
}

#[no_mangle]
pub extern "C" fn C_Login(
    _session_h: CK_SESSION_HANDLE,
    _user_type: CK_USER_TYPE,
    _pin_ptr: CK_UTF8CHAR_PTR,
    _pin_len: CK_ULONG,
) -> CK_RV {
    return err_not_implemented("C_Login");
}

#[no_mangle]
pub extern "C" fn C_Logout(_session_h: CK_SESSION_HANDLE) -> CK_RV {
    return err_not_implemented("C_Logout");
}

#[no_mangle]
pub extern "C" fn C_CreateObject(
    _session_h: CK_SESSION_HANDLE,
    _template_ptr: CK_ATTRIBUTE_PTR,
    _count: CK_ULONG,
    _obj_h_ptr: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    return err_not_implemented("C_CreateObject");
}

#[no_mangle]
pub extern "C" fn C_CopyObject(
    _session_h: CK_SESSION_HANDLE,
    _object_h: CK_OBJECT_HANDLE,
    _template_ptr: CK_ATTRIBUTE_PTR,
    _count: CK_ULONG,
    _new_object_h_ptr: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    return err_not_implemented("C_CopyObject");
}

#[no_mangle]
pub extern "C" fn C_DestroyObject(
    _session_h: CK_SESSION_HANDLE,
    _object_h: CK_OBJECT_HANDLE,
) -> CK_RV {
    return err_not_implemented("C_DestroyObject");
}

#[no_mangle]
pub extern "C" fn C_GetObjectSize(
    _session_h: CK_SESSION_HANDLE,
    _object_h: CK_OBJECT_HANDLE,
    _size_ptr: CK_ULONG_PTR,
) -> CK_RV {
    return err_not_implemented("C_GetObjectSize");
}

#[no_mangle]
pub extern "C" fn C_GetAttributeValue(
    _session_h: CK_SESSION_HANDLE,
    _object_h: CK_OBJECT_HANDLE,
    _template_ptr: CK_ATTRIBUTE_PTR,
    _count: CK_ULONG,
) -> CK_RV {
    return err_not_implemented("C_GetAttributeValue");
}

#[no_mangle]
pub extern "C" fn C_SetAttributeValue(
    _session_h: CK_SESSION_HANDLE,
    _object_h: CK_OBJECT_HANDLE,
    _template_ptr: CK_ATTRIBUTE_PTR,
    _count: CK_ULONG,
) -> CK_RV {
    return err_not_implemented("C_SetAttributeValue");
}

#[no_mangle]
pub extern "C" fn C_FindObjectsInit(
    _session_h: CK_SESSION_HANDLE,
    _template_ptr: CK_ATTRIBUTE_PTR,
    _count: CK_ULONG,
) -> CK_RV {
    return err_not_implemented("C_FindObjectsInit");
}

#[no_mangle]
pub extern "C" fn C_FindObjects(
    _session_h: CK_SESSION_HANDLE,
    _obj_h_ptr: CK_OBJECT_HANDLE_PTR,
    _max_object_count: CK_ULONG,
    _object_count_ptr: CK_ULONG_PTR,
) -> CK_RV {
    return err_not_implemented("C_FindObjects");
}

#[no_mangle]
pub extern "C" fn C_FindObjectsFinal(_session_h: CK_SESSION_HANDLE) -> CK_RV {
    return err_not_implemented("C_FindObjectsFinal");
}

#[no_mangle]
pub extern "C" fn C_EncryptInit(
    _session_h: CK_SESSION_HANDLE,
    _mechanism_ptr: CK_MECHANISM_PTR,
    _key_h: CK_OBJECT_HANDLE,
) -> CK_RV {
    return err_not_implemented("C_EncryptInit");
}

#[no_mangle]
pub extern "C" fn C_Encrypt(
    _session_h: CK_SESSION_HANDLE,
    _data_ptr: CK_BYTE_PTR,
    _data_len: CK_ULONG,
    _encrypted_data_ptr: CK_BYTE_PTR,
    _encrypted_data_len_ptr: CK_ULONG_PTR,
) -> CK_RV {
    return err_not_implemented("C_Encrypt");
}

#[no_mangle]
pub extern "C" fn C_EncryptUpdate(
    _session_h: CK_SESSION_HANDLE,
    _part_ptr: CK_BYTE_PTR,
    _part_len: CK_ULONG,
    _encrypted_part_ptr: CK_BYTE_PTR,
    _encrypted_part_len_ptr: CK_ULONG_PTR,
) -> CK_RV {
    return err_not_implemented("C_EncryptUpdate");
}

#[no_mangle]
pub extern "C" fn C_EncryptFinal(
    _session_h: CK_SESSION_HANDLE,
    _last_encrypted_part_ptr: CK_BYTE_PTR,
    _last_encrypted_part_len_ptr: CK_ULONG_PTR,
) -> CK_RV {
    return err_not_implemented("C_EncryptFinal");
}

#[no_mangle]
pub extern "C" fn C_DecryptInit(
    _session_h: CK_SESSION_HANDLE,
    _mechanism_ptr: CK_MECHANISM_PTR,
    _key_h: CK_OBJECT_HANDLE,
) -> CK_RV {
    return err_not_implemented("C_DecryptInit");
}

#[no_mangle]
pub extern "C" fn C_Decrypt(
    _session_h: CK_SESSION_HANDLE,
    _encrypted_data_ptr: CK_BYTE_PTR,
    _encrypted_data_len: CK_ULONG,
    _data_ptr: CK_BYTE_PTR,
    _data_len_ptr: CK_ULONG_PTR,
) -> CK_RV {
    return err_not_implemented("C_Decrypt");
}

#[no_mangle]
pub extern "C" fn C_DecryptUpdate(
    _session_h: CK_SESSION_HANDLE,
    _encrypted_part_ptr: CK_BYTE_PTR,
    _encrypted_part_len: CK_ULONG,
    _part_ptr: CK_BYTE_PTR,
    _part_len_ptr: CK_ULONG_PTR,
) -> CK_RV {
    return err_not_implemented("C_DecryptUpdate");
}

#[no_mangle]
pub extern "C" fn C_DecryptFinal(
    _session_h: CK_SESSION_HANDLE,
    _last_part_ptr: CK_BYTE_PTR,
    _last_part_len_ptr: CK_ULONG_PTR,
) -> CK_RV {
    return err_not_implemented("C_DecryptFinal");
}

#[no_mangle]
pub extern "C" fn C_DigestInit(
    _session_h: CK_SESSION_HANDLE,
    _mechanism_ptr: CK_MECHANISM_PTR,
) -> CK_RV {
    return err_not_implemented("C_DecryptFinal");
}

#[no_mangle]
pub extern "C" fn C_Digest(
    _session_h: CK_SESSION_HANDLE,
    _data_ptr: CK_BYTE_PTR,
    _data_len: CK_ULONG,
    _digest_ptr: CK_BYTE_PTR,
    _digest_len_ptr: CK_ULONG_PTR,
) -> CK_RV {
    return err_not_implemented("C_Digest");
}

#[no_mangle]
pub extern "C" fn C_DigestUpdate(
    _session_h: CK_SESSION_HANDLE,
    _part_ptr: CK_BYTE_PTR,
    _part_len: CK_ULONG,
) -> CK_RV {
    return err_not_implemented("C_DigestUpdate");
}

#[no_mangle]
pub extern "C" fn C_DigestKey(_session_h: CK_SESSION_HANDLE, _key_h: CK_OBJECT_HANDLE) -> CK_RV {
    return err_not_implemented("C_DigestKey");
}

#[no_mangle]
pub extern "C" fn C_DigestFinal(
    _session_h: CK_SESSION_HANDLE,
    _digest_ptr: CK_BYTE_PTR,
    _digest_len_ptr: CK_ULONG_PTR,
) -> CK_RV {
    return err_not_implemented("C_DigestFinal");
}

#[no_mangle]
pub extern "C" fn C_SignInit(
    _session_h: CK_SESSION_HANDLE,
    _mechanism_ptr: CK_MECHANISM_PTR,
    _key_h: CK_OBJECT_HANDLE,
) -> CK_RV {
    return err_not_implemented("C_SignInit");
}

#[no_mangle]
pub extern "C" fn C_Sign(
    _session_h: CK_SESSION_HANDLE,
    _data_ptr: CK_BYTE_PTR,
    _data_len: CK_ULONG,
    _signature_ptr: CK_BYTE_PTR,
    _signature_len_ptr: CK_ULONG_PTR,
) -> CK_RV {
    return err_not_implemented("C_Sign");
}

#[no_mangle]
pub extern "C" fn C_SignUpdate(
    _session_h: CK_SESSION_HANDLE,
    _part_ptr: CK_BYTE_PTR,
    _part_len: CK_ULONG,
) -> CK_RV {
    return err_not_implemented("C_SignUpdate");
}

#[no_mangle]
pub extern "C" fn C_SignFinal(
    _session_h: CK_SESSION_HANDLE,
    _signature_ptr: CK_BYTE_PTR,
    _signature_len_ptr: CK_ULONG_PTR,
) -> CK_RV {
    return err_not_implemented("C_SignFinal");
}

#[no_mangle]
pub extern "C" fn C_SignRecoverInit(
    _session_h: CK_SESSION_HANDLE,
    _mechanism_ptr: CK_MECHANISM_PTR,
    _key_h: CK_OBJECT_HANDLE,
) -> CK_RV {
    return err_not_implemented("C_SignRecoverInit");
}

#[no_mangle]
pub extern "C" fn C_SignRecover(
    _session_h: CK_SESSION_HANDLE,
    _data_ptr: CK_BYTE_PTR,
    _data_len: CK_ULONG,
    _signature_ptr: CK_BYTE_PTR,
    _signature_len_ptr: CK_ULONG_PTR,
) -> CK_RV {
    return err_not_implemented("C_SignRecover");
}

#[no_mangle]
pub extern "C" fn C_VerifyInit(
    _session_h: CK_SESSION_HANDLE,
    _mechanism_ptr: CK_MECHANISM_PTR,
    _key_h: CK_OBJECT_HANDLE,
) -> CK_RV {
    return err_not_implemented("C_VerifyInit");
}

#[no_mangle]
pub extern "C" fn C_Verify(
    _session_h: CK_SESSION_HANDLE,
    _data_ptr: CK_BYTE_PTR,
    _data_len: CK_ULONG,
    _signature_ptr: CK_BYTE_PTR,
    _signature_len: CK_ULONG,
) -> CK_RV {
    return err_not_implemented("C_Verify");
}

#[no_mangle]
pub extern "C" fn C_VerifyUpdate(
    _session_h: CK_SESSION_HANDLE,
    _part_ptr: CK_BYTE_PTR,
    _part_len: CK_ULONG,
) -> CK_RV {
    return err_not_implemented("C_VerifyUpdate");
}

#[no_mangle]
pub extern "C" fn C_VerifyFinal(
    _session_h: CK_SESSION_HANDLE,
    _signature_ptr: CK_BYTE_PTR,
    _signature_len: CK_ULONG,
) -> CK_RV {
    return err_not_implemented("C_VerifyFinal");
}

#[no_mangle]
pub extern "C" fn C_VerifyRecoverInit(
    _session_h: CK_SESSION_HANDLE,
    _mechanism_ptr: CK_MECHANISM_PTR,
    _key_h: CK_OBJECT_HANDLE,
) -> CK_RV {
    return err_not_implemented("C_VerifyRecoverInit");
}

#[no_mangle]
pub extern "C" fn C_VerifyRecover(
    _session_h: CK_SESSION_HANDLE,
    _signature_ptr: CK_BYTE_PTR,
    _signature_len: CK_ULONG,
    _data_ptr: CK_BYTE_PTR,
    _data_len_ptr: CK_ULONG_PTR,
) -> CK_RV {
    return err_not_implemented("C_VerifyRecover");
}

#[no_mangle]
pub extern "C" fn C_DigestEncryptUpdate(
    _session_h: CK_SESSION_HANDLE,
    _part_ptr: CK_BYTE_PTR,
    _part_len: CK_ULONG,
    _encrypted_part_ptr: CK_BYTE_PTR,
    _encrypted_part_len_ptr: CK_ULONG_PTR,
) -> CK_RV {
    return err_not_implemented("C_DigestEncryptUpdate");
}

#[no_mangle]
pub extern "C" fn C_DecryptDigestUpdate(
    _session_h: CK_SESSION_HANDLE,
    _encrypted_part_ptr: CK_BYTE_PTR,
    _encrypted_part_len: CK_ULONG,
    _part_ptr: CK_BYTE_PTR,
    _part_len_ptr: CK_ULONG_PTR,
) -> CK_RV {
    return err_not_implemented("C_DecryptDigestUpdate");
}

#[no_mangle]
pub extern "C" fn C_SignEncryptUpdate(
    _session_h: CK_SESSION_HANDLE,
    _part_ptr: CK_BYTE_PTR,
    _part_len: CK_ULONG,
    _encrypted_part_ptr: CK_BYTE_PTR,
    _encrypted_part_len_ptr: CK_ULONG_PTR,
) -> CK_RV {
    return err_not_implemented("C_SignEncryptUpdate");
}

#[no_mangle]
pub extern "C" fn C_DecryptVerifyUpdate(
    _session_h: CK_SESSION_HANDLE,
    _encrypted_part_ptr: CK_BYTE_PTR,
    _encrypted_part_len: CK_ULONG,
    _part_ptr: CK_BYTE_PTR,
    _part_len_ptr: CK_ULONG_PTR,
) -> CK_RV {
    return err_not_implemented("C_DecryptVerifyUpdate");
}

#[no_mangle]
pub extern "C" fn C_GenerateKey(
    _session_h: CK_SESSION_HANDLE,
    _mechanism_ptr: CK_MECHANISM_PTR,
    _template_ptr: CK_ATTRIBUTE_PTR,
    _count: CK_ULONG,
    _key_h_ptr: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    return err_not_implemented("C_GenerateKey");
}

#[no_mangle]
pub extern "C" fn C_GenerateKeyPair(
    _session_h: CK_SESSION_HANDLE,
    _mechanism_ptr: CK_MECHANISM_PTR,
    _public_key_template_ptr: CK_ATTRIBUTE_PTR,
    _public_key_attribute_count: CK_ULONG,
    _private_key_template_ptr: CK_ATTRIBUTE_PTR,
    _private_key_attribute_count: CK_ULONG,
    _public_key_h_ptr: CK_OBJECT_HANDLE_PTR,
    _private_key_h_ptr: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    return err_not_implemented("C_GenerateKeyPair");
}

#[no_mangle]
pub extern "C" fn C_WrapKey(
    _session_h: CK_SESSION_HANDLE,
    _mechanism_ptr: CK_MECHANISM_PTR,
    _wrapping_key_h: CK_OBJECT_HANDLE,
    _key_h: CK_OBJECT_HANDLE,
    _wrapped_key_ptr: CK_BYTE_PTR,
    _wrapped_key_len_ptr: CK_ULONG_PTR,
) -> CK_RV {
    return err_not_implemented("C_WrapKey");
}

#[no_mangle]
pub extern "C" fn C_UnwrapKey(
    _session_h: CK_SESSION_HANDLE,
    _mechanism_ptr: CK_MECHANISM_PTR,
    _unwrapping_key_h: CK_OBJECT_HANDLE,
    _wrapped_key_ptr: CK_BYTE_PTR,
    _wrapped_key_len: CK_ULONG,
    _template_ptr: CK_ATTRIBUTE_PTR,
    _attribute_count: CK_ULONG,
    _key_h_ptr: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    return err_not_implemented("C_UnwrapKey");
}

#[no_mangle]
pub extern "C" fn C_DeriveKey(
    _session_h: CK_SESSION_HANDLE,
    _mechanism_ptr: CK_MECHANISM_PTR,
    _base_key_h: CK_OBJECT_HANDLE,
    _template_ptr: CK_ATTRIBUTE_PTR,
    _attribute_count: CK_ULONG,
    _key_h_ptr: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    return err_not_implemented("C_DeriveKey");
}

#[no_mangle]
pub extern "C" fn C_SeedRandom(
    _session_h: CK_SESSION_HANDLE,
    _seed_ptr: CK_BYTE_PTR,
    _seed_len: CK_ULONG,
) -> CK_RV {
    return err_not_implemented("C_SeedRandom");
}

#[no_mangle]
pub extern "C" fn C_GenerateRandom(
    _session_h: CK_SESSION_HANDLE,
    _random_data_ptr: CK_BYTE_PTR,
    _random_data_len: CK_ULONG,
) -> CK_RV {
    return err_not_implemented("C_GenerateRandom");
}

#[no_mangle]
pub extern "C" fn C_GetFunctionStatus(_session_h: CK_SESSION_HANDLE) -> CK_RV {
    return err_not_implemented("C_GetFunctionStatus");
}

#[no_mangle]
pub extern "C" fn C_CancelFunction(_session_h: CK_SESSION_HANDLE) -> CK_RV {
    return err_not_implemented("C_CancelFunction");
}

#[no_mangle]
pub extern "C" fn C_WaitForSlotEvent(
    _flags: CK_FLAGS,
    _slot_ptr: CK_SLOT_ID_PTR,
    _reserved_ptr: CK_VOID_PTR,
) -> CK_RV {
    return err_not_implemented("C_WaitForSlotEvent");
}
