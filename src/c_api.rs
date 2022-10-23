use crate::*;
use anyhow;
use core::slice;
use easy_ffi::easy_ffi;
use errno::{set_errno, Errno};
use futures::executor;
use hex;
use std::collections::BTreeMap;
use std::ffi::*;
use std::mem;
use std::os::raw::c_char;
use std::os::raw::c_int;
use std::ptr;
const EINVAL: i32 = 22;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct CHttpClient {
    base_url: *mut c_char,
    region_name: *mut c_char,
}

impl From<HttpClient> for CHttpClient {
    fn from(value: HttpClient) -> Self {
        let base_url = str2ptr(value.base_url.as_str());
        let region_name = str2ptr(value.region_name);
        Self {
            base_url,
            region_name,
        }
    }
}

impl Into<HttpClient> for CHttpClient {
    fn into(self) -> HttpClient {
        let base_url = ptr2str(self.base_url).to_string();
        let region_name = ptr2str(self.region_name);
        HttpClient {
            base_url,
            region_name,
        }
    }
}

easy_ffi!(fn_void_pointer =>
    |err| {
        set_errno(Errno(EINVAL));
        return ();
    }
    |panic_val| {
        set_errno(Errno(EINVAL));
        match panic_val.downcast_ref::<&'static str>() {
            Some(s) => panic!("sommelier-drive-client-panic: {}",s),
            None => panic!("sommelier-drive-client-panic without an error message"),
        }
    }
);

fn_void_pointer!(
    fn registerUser(
        client: CHttpClient,
        data_pk_str: *mut c_char,
        keyword_pk_str: *mut c_char,
    ) -> Result<(), anyhow::Error> {
        let client: HttpClient = client.into();
        let fut_result = async { register_user(&client).await };
        let self_user_info = executor::block_on(fut_result)?;

        Ok(())
    }
);

fn str2ptr(str: &str) -> *mut c_char {
    let c_str = CString::new(str).unwrap();
    c_str.into_raw()
}

fn ptr2str<'a>(ptr: *mut c_char) -> &'a str {
    let cstr = unsafe { CStr::from_ptr(ptr) };
    cstr.to_str().unwrap()
}
