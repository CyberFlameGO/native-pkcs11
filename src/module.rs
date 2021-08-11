use crate::pkcs11::*;
use std::fmt;
use std::fmt::Debug;
use std::result;

// TODO(bweeks): replace with real session handling.
const DEFAULT_SESSION_HANDLE: CK_SESSION_HANDLE = 1;

// A PKCS #11 error with associated context.
#[derive(Debug)]
pub struct Error {
    code: CK_RV,
    msg: String,
}

impl Error {
    // Create a new error with an associated debug message. The code argument uses Info to allow
    // CK_RV types that are u32.
    //
    // TODO(ericchiang): remove the Into convertion if we update the error type to match CK_RV.
    //
    // ```
    // return Err(module::Error::new(CKR_GENERAL_ERROR, "we hit a general error"));
    // ```
    pub fn new<T: Into<CK_RV>>(code: T, msg: String) -> Self {
        return Error {
            code: code.into(),
            msg: msg,
        };
    }

    // Returns the PKCS #11 specific return value for this error.
    pub fn rv(&self) -> CK_RV {
        return self.code;
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        return write!(f, "{}", self.msg);
    }
}

#[macro_export]
macro_rules! errorf{
    ($rc:expr, $($arg:tt)*) => (Error::new($rc, format!($($arg)*)));
}

// A result type that uses a PKCS #11 error.
pub type Result<T> = result::Result<T, Error>;

// The core PKCS #11 module.
pub struct Module {
    session: Option<Session>,
}

impl Module {
    pub fn new() -> Result<Self> {
        return Ok(Module { session: None });
    }

    pub fn new_session(&mut self, slot_id: CK_SLOT_ID) -> Result<CK_SESSION_HANDLE> {
        if self.session.is_some() {
            return Err(errorf!(CKR_SESSION_COUNT, "too many exisiting sessions"));
        }
        self.session = Some(Session { slot_id });
        Ok(DEFAULT_SESSION_HANDLE)
    }

    pub fn close_session(&mut self, h: CK_SESSION_HANDLE) -> Result<()> {
        if h != DEFAULT_SESSION_HANDLE {
            return Err(errorf!(
                CKR_SESSION_HANDLE_INVALID,
                "{} is not a valid session handle",
                h
            ));
        }

        match &self.session {
            Some(_) => {
                self.session = None;
            }
            None => {
                return Err(errorf!(
                    CKR_SESSION_HANDLE_INVALID,
                    "{} is not a valid session handle",
                    h
                ));
            }
        }
        Ok(())
    }

    pub fn close_all_sessions(&mut self) -> Result<()> {
        self.session = None;
        Ok(())
    }

    pub fn get_session_info(&mut self, h: CK_SESSION_HANDLE) -> Result<CK_SESSION_INFO> {
        if h != DEFAULT_SESSION_HANDLE {
            return Err(errorf!(
                CKR_SESSION_HANDLE_INVALID,
                "{} is not a valid session handle",
                h
            ));
        }

        let s = self.session.as_ref().ok_or(errorf!(
            CKR_SESSION_HANDLE_INVALID,
            "{} is not a valid session handle",
            h
        ))?;

        return Ok(CK_SESSION_INFO {
            slotID: s.slot_id,
            state: CKS_RO_USER_FUNCTIONS,
            flags: CKF_SERIAL_SESSION,
            ulDeviceError: 0,
        });
    }
}

struct Session {
    slot_id: CK_SLOT_ID,
}
