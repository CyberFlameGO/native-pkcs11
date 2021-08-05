use crate::pkcs11::*;
use std::fmt;
use std::result;

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
pub struct Module {}

impl Module {
    pub fn new() -> Result<Self> {
        return Ok(Module {});
    }
}
