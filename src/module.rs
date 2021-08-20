// Copyright 2021 Google LLC
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     https://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::pkcs11::*;
#[cfg(feature = "openssl")]
use openssl::pkey;
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
        Error {
            code: code.into(),
            msg,
        }
    }

    // Returns the PKCS #11 specific return value for this error.
    pub fn rv(&self) -> CK_RV {
        self.code
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
        Ok(Module { session: None })
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

        let s = self.session.as_ref().ok_or_else(|| {
            errorf!(
                CKR_SESSION_HANDLE_INVALID,
                "{} is not a valid session handle",
                h
            )
        })?;

        Ok(CK_SESSION_INFO {
            slotID: s.slot_id,
            state: CKS_RO_USER_FUNCTIONS,
            flags: CKF_SERIAL_SESSION,
            ulDeviceError: 0,
        })
    }
}

struct Session {
    slot_id: CK_SLOT_ID,
}

struct Attribute {
    typ: CK_ATTRIBUTE_TYPE,
    val: Vec<u8>,
}

#[allow(dead_code)]
fn get_attribute_val(attrs: &[Attribute], typ: CK_ATTRIBUTE_TYPE) -> Option<Vec<u8>> {
    for a in attrs.iter() {
        if a.typ == typ {
            return Some(a.val.clone());
        }
    }
    None
}

#[cfg(feature = "openssl")]
fn pub_key_attributes(b: &[u8]) -> Result<Vec<Attribute>> {
    let mut attrs = Vec::new();
    attrs.push(Attribute {
        typ: CKA_VALUE,
        val: b.to_vec(),
    });

    let pub_key = pkey::PKey::public_key_from_der(b)
        .map_err(|err| errorf!(CKR_GENERAL_ERROR, "parse public key: {}", err))?;

    match pub_key.id() {
        pkey::Id::RSA => {
            let rsa_pub_key = pub_key
                .rsa()
                .map_err(|err| errorf!(CKR_GENERAL_ERROR, "parse rsa public key: {}", err))?;
            let mut a = rsa_pub_key_attributes(rsa_pub_key).map_err(|err| {
                errorf!(CKR_GENERAL_ERROR, "parse rsa public attributes: {}", err)
            })?;
            attrs.append(&mut a);
        }
        pkey::Id::EC => return Err(errorf!(CKR_GENERAL_ERROR, "ECDSA keys not supported",)),
        _ => {
            return Err(errorf!(
                CKR_GENERAL_ERROR,
                "unsupported key type {:?}",
                pub_key.id()
            ))
        }
    };
    return Ok(attrs);
}

#[cfg(feature = "openssl")]
fn rsa_pub_key_attributes(
    pub_key: openssl::rsa::Rsa<openssl::pkey::Public>,
) -> Result<Vec<Attribute>> {
    let mut attrs = Vec::new();

    // Calculate N and E values for the public key.
    // https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/os/pkcs11-curr-v2.40-os.html#_Toc228894631
    attrs.push(Attribute {
        typ: CKA_MODULUS,
        val: pub_key.n().to_vec(),
    });
    attrs.push(Attribute {
        typ: CKA_PUBLIC_EXPONENT,
        val: pub_key.e().to_vec(),
    });

    // Size of the key in bits, encoded as big endian.
    // https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/os/pkcs11-curr-v2.40-os.html#_Toc228894631
    let modulus_size = (pub_key.size() * 8)
        .to_be_bytes()
        .iter()
        .skip_while(|&&b| b == 0) // Filter leading zeros.
        .map(|&b| b)
        .collect();
    attrs.push(Attribute {
        typ: CKA_MODULUS_BITS,
        val: modulus_size,
    });

    // RFC 3279, 2.3 Public Key Algorithms
    //
    // pkcs-1 OBJECT IDENTIFIER ::== { iso(1) member-body(2) us(840)
    //    rsadsi(113549) pkcs(1) 1 }
    //
    // rsaEncryption OBJECT IDENTIFIER ::== { pkcs1-1 1 }
    //
    // Generated with a Go program:
    //
    // asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1})
    attrs.push(Attribute {
        typ: CKA_OBJECT_ID,
        val: vec![
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
        ],
    });

    return Ok(attrs);
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "openssl")]
    #[test]
    fn test_pub_key_attributes() {
        let data = include_bytes!("testdata/rsa_pub.der");
        let attrs = pub_key_attributes(data).unwrap();

        let mod_bits = get_attribute_val(&attrs, CKA_MODULUS_BITS).unwrap();
        assert_eq!(mod_bits, vec![0x08, 0x00]); // 2048 in hex.

        // E and N gold values taken from the output of the following command:
        //
        //   openssl pkey --text --inform=DER --pubin -in=testdata/rsa_pub.der
        //
        let e = get_attribute_val(&attrs, CKA_PUBLIC_EXPONENT).unwrap();
        assert_eq!(e, vec![0x01, 0x00, 0x01]);

        let n = get_attribute_val(&attrs, CKA_MODULUS).unwrap();
        assert_eq!(
            n,
            vec![
                0x97, 0xa5, 0xc3, 0xfa, 0x6b, 0x86, 0x7a, 0xf3, 0xb6, 0x5e, 0x49, 0x03, 0x86, 0xf8,
                0x52, 0xa2, 0xb5, 0xc7, 0x50, 0x59, 0x93, 0xca, 0x49, 0x10, 0x07, 0xb5, 0xe9, 0xef,
                0xd9, 0x72, 0x0a, 0xbd, 0x95, 0x87, 0x8e, 0x70, 0x85, 0x75, 0xdc, 0xb2, 0x66, 0xd4,
                0x14, 0xda, 0x93, 0xf6, 0xb7, 0x44, 0x5e, 0xab, 0xeb, 0x6c, 0xac, 0x54, 0x65, 0x4a,
                0x68, 0x87, 0x06, 0x09, 0xe3, 0x2c, 0x7b, 0xa0, 0x6f, 0x42, 0x78, 0xfb, 0xf7, 0xab,
                0x36, 0x41, 0x55, 0x92, 0x30, 0x12, 0xbe, 0x1c, 0x7a, 0x55, 0xa6, 0x00, 0xbc, 0x95,
                0xd3, 0x19, 0x78, 0x5f, 0x72, 0x0d, 0x30, 0xb9, 0x02, 0xbe, 0x1e, 0x2d, 0x7a, 0x2c,
                0x26, 0xb2, 0x62, 0x67, 0xd3, 0xdd, 0xf5, 0x9d, 0x2c, 0xa7, 0x65, 0x67, 0xde, 0x5e,
                0x9b, 0x3b, 0x2d, 0x1f, 0xbc, 0x8a, 0xcc, 0x10, 0xad, 0x21, 0xbf, 0xe1, 0x2e, 0x14,
                0xed, 0x52, 0xc4, 0x3d, 0x4b, 0x5d, 0x98, 0x33, 0x61, 0x32, 0x08, 0x63, 0xb6, 0x3a,
                0x80, 0x90, 0x88, 0x82, 0x94, 0xc6, 0x65, 0xd8, 0xdf, 0x6b, 0xa9, 0xa2, 0x92, 0xcb,
                0x55, 0xda, 0xa3, 0xd7, 0xa5, 0xeb, 0xe8, 0x7b, 0x8a, 0x6b, 0x2d, 0x9d, 0xcd, 0xef,
                0xcc, 0x62, 0x88, 0x09, 0x70, 0xc1, 0xd9, 0x05, 0x97, 0xcc, 0x64, 0x4d, 0x58, 0xf1,
                0xf9, 0xa7, 0x1c, 0x14, 0x52, 0xb0, 0xf5, 0xcf, 0x90, 0xb5, 0xfd, 0x4a, 0x0a, 0x9d,
                0x34, 0x39, 0xcd, 0xf3, 0xec, 0x28, 0x8c, 0x3d, 0x8d, 0xc2, 0x65, 0x55, 0xdc, 0x4d,
                0x99, 0xba, 0xee, 0xc5, 0xfb, 0xdd, 0xa5, 0xce, 0x2a, 0x05, 0x5c, 0xd7, 0x62, 0xb5,
                0xe6, 0x58, 0xec, 0xb9, 0xa0, 0x8c, 0x65, 0xd8, 0x36, 0xbd, 0xa1, 0x02, 0xfd, 0xc8,
                0xea, 0xf5, 0xd6, 0x44, 0xe1, 0x01, 0x56, 0x11, 0xf9, 0x65, 0x5a, 0x38, 0x96, 0x98,
                0xc7, 0xd0, 0x61, 0x57,
            ]
        );
    }
}
