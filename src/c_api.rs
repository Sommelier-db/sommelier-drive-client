use crate::*;
use anyhow;
use c_vec::CSlice;
use c_vec::CVec;
use core::slice;
use easy_ffi::easy_ffi;
use errno::{set_errno, Errno};
use serde_json;
use sommelier_drive_cryptos::PemString;
use sommelier_drive_cryptos::PkeSecretKey;
use std::ffi::*;
use std::mem;
use std::os::raw::c_char;
use std::os::raw::c_int;
use std::ptr;
use tokio::runtime::Runtime;
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

#[repr(C)]
#[derive(Debug, Clone)]
pub struct CUserInfo {
    id: u64,
    data_sk: *mut c_char,
    keyword_sk: *mut c_char,
}

impl TryFrom<SelfUserInfo> for CUserInfo {
    type Error = anyhow::Error;
    fn try_from(value: SelfUserInfo) -> Result<Self, Self::Error> {
        let data_sk = str2ptr(value.data_sk.to_string()?.as_str());
        let keyword_sk = str2ptr(serde_json::to_string(&value.keyword_sk)?.as_str());
        Ok(Self {
            id: value.id,
            data_sk,
            keyword_sk,
        })
    }
}

impl TryInto<SelfUserInfo> for CUserInfo {
    type Error = anyhow::Error;
    fn try_into(self) -> Result<SelfUserInfo, Self::Error> {
        let data_sk = PkeSecretKey::from_str(ptr2str(self.data_sk))?;
        let keyword_sk = serde_json::from_str(ptr2str(self.keyword_sk))?;
        Ok(SelfUserInfo {
            id: self.id,
            data_sk,
            keyword_sk,
        })
    }
}

#[no_mangle]
pub extern "C" fn freeUserInfo(value: CUserInfo) {
    mem::forget(value.data_sk);
    mem::forget(value.keyword_sk);
}

easy_ffi!(fn_user_info =>
    |err| {
        set_errno(Errno(EINVAL));
        return CUserInfo {
            id: 0,
            data_sk: ptr::null_mut(),
            keyword_sk: ptr::null_mut()
        };
    }
    |panic_val| {
        set_errno(Errno(EINVAL));
        match panic_val.downcast_ref::<&'static str>() {
            Some(s) => panic!("sommelier-drive-client-panic: {}",s),
            None => panic!("sommelier-drive-client-panic without an error message"),
        }
    }
);

fn_user_info!(
    fn registerUser(
        client: CHttpClient,
        filepath: *mut c_char,
    ) -> Result<CUserInfo, anyhow::Error> {
        let client: HttpClient = client.into();
        let filepath = ptr2str(filepath);
        let fut_result = async { register_user(&client, filepath).await };
        let rt = Runtime::new()?;
        let self_user_info = rt.block_on(fut_result)?;
        let user_info = CUserInfo::try_from(self_user_info)?;
        Ok(user_info)
    }
);

#[repr(C)]
#[derive(Debug, Clone)]
pub struct CPublicKeys {
    data_pk: *mut c_char,
    keyword_pk: *mut c_char,
}

#[no_mangle]
pub extern "C" fn freePublicKeys(value: CPublicKeys) {
    mem::forget(value.data_pk);
    mem::forget(value.keyword_pk);
}

easy_ffi!(fn_public_keys=>
    |err| {
        set_errno(Errno(EINVAL));
        return CPublicKeys {
            data_pk: ptr::null_mut(),
            keyword_pk: ptr::null_mut()
        };
    }
    |panic_val| {
        set_errno(Errno(EINVAL));
        match panic_val.downcast_ref::<&'static str>() {
            Some(s) => panic!("sommelier-drive-client-panic: {}",s),
            None => panic!("sommelier-drive-client-panic without an error message"),
        }
    }
);

fn_public_keys!(
    fn getPublicKeys(client: CHttpClient, user_id: u64) -> Result<CPublicKeys, anyhow::Error> {
        let client: HttpClient = client.into();
        let fut_result = async { get_user_public_keys(&client, user_id).await };
        let rt = Runtime::new()?;
        let (data_pk, keyword_pk) = rt.block_on(fut_result)?;

        let pks = CPublicKeys {
            data_pk: str2ptr(data_pk.to_string()?.as_str()),
            keyword_pk: str2ptr(serde_json::to_string(&keyword_pk)?.as_str()),
        };
        Ok(pks)
    }
);

easy_ffi!(fn_char_pointer =>
    |err| {
        set_errno(Errno(EINVAL));
        return ptr::null_mut()
    }
    |panic_val| {
        set_errno(Errno(EINVAL));
        match panic_val.downcast_ref::<&'static str>() {
            Some(s) => panic!("sommelier-drive-client-panic: {}",s),
            None => panic!("sommelier-drive-client-panic without an error message"),
        }
    }
);

fn_char_pointer!(
    fn getFilePathWithId(
        client: CHttpClient,
        user_info: CUserInfo,
        path_id: u64,
    ) -> Result<*mut c_char, anyhow::Error> {
        let client = client.into();
        let user_info = user_info.try_into()?;
        let fut_result = async { get_filepath_with_id(&client, &user_info, path_id).await };
        let rt = Runtime::new()?;
        let filepath = rt.block_on(fut_result)?;
        let filepath_ptr = str2ptr(filepath.as_str());
        Ok(filepath_ptr)
    }
);

#[repr(C)]
#[derive(Debug, Clone)]
pub struct CPathVec {
    ptr: *mut *mut c_char,
    len: usize,
}

#[no_mangle]
pub extern "C" fn freePathVec(value: CPathVec) {
    mem::drop(value.ptr);
}

easy_ffi!(fn_path_vec =>
    |err| {
        set_errno(Errno(EINVAL));
        return CPathVec {
            ptr: ptr::null_mut(),
            len: 0
        };
    }
    |panic_val| {
        set_errno(Errno(EINVAL));
        match panic_val.downcast_ref::<&'static str>() {
            Some(s) => panic!("sommelier-drive-client-panic: {}",s),
            None => panic!("sommelier-drive-client-panic without an error message"),
        }
    }
);

fn_path_vec!(
    fn getChildrenPathes(
        client: CHttpClient,
        user_info: CUserInfo,
        cur_path: *mut c_char,
    ) -> Result<CPathVec, anyhow::Error> {
        let client = client.into();
        let user_info = user_info.try_into()?;
        let cur_path = ptr2str(cur_path);
        let fut_result = async { get_children_pathes(&client, &user_info, cur_path).await };
        let rt = Runtime::new()?;
        let filepath_vec = rt.block_on(fut_result)?;
        let len = filepath_vec.len();
        let mut filepath_strs = filepath_vec
            .iter()
            .map(|path| str2ptr(path))
            .collect::<Vec<*mut c_char>>();
        let ptr = filepath_strs.as_mut_ptr();
        mem::forget(filepath_strs);
        Ok(CPathVec { ptr, len })
    }
);

fn_path_vec!(
    fn searchDescendantPathes(
        client: CHttpClient,
        user_info: CUserInfo,
        cur_path: *mut c_char,
    ) -> Result<CPathVec, anyhow::Error> {
        let client = client.into();
        let user_info = user_info.try_into()?;
        let cur_path = ptr2str(cur_path);
        let fut_result = async { search_descendant_pathes(&client, &user_info, cur_path).await };
        let rt = Runtime::new()?;
        let filepath_vec = rt.block_on(fut_result)?;
        let len = filepath_vec.len();
        let mut filepath_strs = filepath_vec
            .iter()
            .map(|path| str2ptr(path))
            .collect::<Vec<*mut c_char>>();
        let ptr = filepath_strs.as_mut_ptr();
        mem::forget(filepath_strs);
        Ok(CPathVec { ptr, len })
    }
);

easy_ffi!(fn_int =>
    |err| {
        set_errno(Errno(EINVAL));
        return -1;
    }
    |panic_val| {
        set_errno(Errno(EINVAL));
        match panic_val.downcast_ref::<&'static str>() {
            Some(s) => panic!("sommelier-drive-client-panic: {}",s),
            None => panic!("sommelier-drive-client-panic without an error message"),
        }
    }
);

fn_int!(
    fn isExistFilepath(
        client: CHttpClient,
        user_info: CUserInfo,
        filepath: *mut c_char,
    ) -> Result<c_int, anyhow::Error> {
        let client = client.into();
        let user_info = user_info.try_into()?;
        let filepath = ptr2str(filepath);
        let fut_result = async { is_exist_filepath(&client, &user_info, filepath).await };
        let rt = Runtime::new()?;
        let is_exist = rt.block_on(fut_result)?;
        if is_exist {
            Ok(1)
        } else {
            Ok(0)
        }
    }
);

#[repr(C)]
#[derive(Debug, Clone)]
pub struct CContentsData {
    is_file: c_int,
    num_readable_users: usize,
    readable_user_path_ids: *mut u64,
    file_bytes_ptr: *const u8,
    file_bytes_len: usize,
}

impl From<ContentsData> for CContentsData {
    fn from(mut value: ContentsData) -> Self {
        let readable_user_path_ids_ptr = value.readable_user_path_ids.as_mut_ptr();
        mem::forget(value.readable_user_path_ids);
        let file_bytes_len = value.file_bytes.len();
        let file_bytes_ptr = value.file_bytes.as_mut_ptr();
        mem::forget(value.file_bytes);
        Self {
            is_file: if value.is_file { 1 } else { 0 },
            num_readable_users: value.num_readable_users,
            readable_user_path_ids: readable_user_path_ids_ptr,
            file_bytes_ptr,
            file_bytes_len,
        }
    }
}

impl Into<ContentsData> for CContentsData {
    fn into(self) -> ContentsData {
        let readable_user_path_ids =
            unsafe { CVec::new(self.readable_user_path_ids, self.num_readable_users) }.into();
        let file_bytes = unsafe { CSlice::new(self.file_bytes_ptr, self.file_bytes_len) }.into();
        ContentsData {
            is_file: self.is_file == 1,
            num_readable_users: self.num_readable_users,
            readable_user_path_ids,
            file_bytes,
        }
    }
}

#[no_mangle]
pub extern "C" fn freeContentsData(value: CContentsData) {
    mem::drop(value.readable_user_path_ids);
    mem::drop(value.file_bytes_ptr);
}

easy_ffi!(fn_contents_data =>
    |err| {
        set_errno(Errno(EINVAL));
        return CContentsData {
            is_file: -1,
            num_readable_users: 0,
            readable_user_path_ids: ptr::null_mut(),
            file_bytes_ptr: ptr::null_mut(),
            file_bytes_len: 0,
        };
    }
    |panic_val| {
        set_errno(Errno(EINVAL));
        match panic_val.downcast_ref::<&'static str>() {
            Some(s) => panic!("sommelier-drive-client-panic: {}",s),
            None => panic!("sommelier-drive-client-panic without an error message"),
        }
    }
);

fn_contents_data!(
    fn openFilepath(
        client: CHttpClient,
        user_info: CUserInfo,
        filepath: *mut c_char,
    ) -> Result<CContentsData, anyhow::Error> {
        let client = client.into();
        let user_info = user_info.try_into()?;
        let filepath = ptr2str(filepath);
        let fut_result = async { open_filepath(&client, &user_info, filepath).await };
        let rt = Runtime::new()?;
        let contents_data = rt.block_on(fut_result)?;
        Ok(CContentsData::from(contents_data))
    }
);

easy_ffi!(fn_result_int =>
    |err| {
        set_errno(Errno(EINVAL));
        return 0;
    }
    |panic_val| {
        set_errno(Errno(EINVAL));
        match panic_val.downcast_ref::<&'static str>() {
            Some(s) => panic!("sommelier-drive-client-panic: {}",s),
            None => panic!("sommelier-drive-client-panic without an error message"),
        }
    }
);

fn_result_int!(
    fn addFile(
        client: CHttpClient,
        user_info: CUserInfo,
        filepath: *mut c_char,
        file_bytes_ptr: *const u8,
        file_bytes_len: usize,
    ) -> Result<c_int, anyhow::Error> {
        let client = client.into();
        let user_info = user_info.try_into()?;
        let filepath = ptr2str(filepath);
        let file_bytes = unsafe { CSlice::new(file_bytes_ptr, file_bytes_len) }.into();
        let fut_result = async { add_file(&client, &user_info, filepath, file_bytes).await };
        let rt = Runtime::new()?;
        rt.block_on(fut_result)?;
        Ok(1)
    }
);

fn_result_int!(
    fn addDirectory(
        client: CHttpClient,
        user_info: CUserInfo,
        filepath: *mut c_char,
    ) -> Result<c_int, anyhow::Error> {
        let client = client.into();
        let user_info = user_info.try_into()?;
        let filepath = ptr2str(filepath);
        let fut_result = async { add_directory(&client, &user_info, filepath).await };
        let rt = Runtime::new()?;
        rt.block_on(fut_result)?;
        Ok(1)
    }
);

fn_result_int!(
    fn addReadPermission(
        client: CHttpClient,
        user_info: CUserInfo,
        filepath: *mut c_char,
        new_user_id: u64,
    ) -> Result<c_int, anyhow::Error> {
        let client = client.into();
        let user_info = user_info.try_into()?;
        let filepath = ptr2str(filepath);
        let fut_result =
            async { add_read_permission(&client, &user_info, filepath, new_user_id).await };
        let rt = Runtime::new()?;
        rt.block_on(fut_result)?;
        Ok(1)
    }
);

fn_result_int!(
    fn modifyFile(
        client: CHttpClient,
        user_info: CUserInfo,
        filepath: *mut c_char,
        new_file_bytes_ptr: *const u8,
        new_file_bytes_len: usize,
    ) -> Result<c_int, anyhow::Error> {
        let client = client.into();
        let user_info = user_info.try_into()?;
        let filepath = ptr2str(filepath);
        /*let file_bytes =
        unsafe { slice::from_raw_parts(new_file_bytes_ptr, new_file_bytes_len) }.to_vec();*/
        let file_bytes = unsafe { CSlice::new(new_file_bytes_ptr, new_file_bytes_len) }.into();
        let fut_result = async { modify_file(&client, &user_info, filepath, file_bytes).await };
        let rt = Runtime::new()?;
        rt.block_on(fut_result)?;
        Ok(1)
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
