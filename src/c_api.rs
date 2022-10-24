use crate::*;
use anyhow;
use core::slice;
use easy_ffi::easy_ffi;
use errno::{set_errno, Errno};
use serde_json;
use sommelier_drive_cryptos::JsonString;
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

easy_ffi!(fn_void =>
    |err| {
        set_errno(Errno(EINVAL));
    }
    |panic_val| {
        set_errno(Errno(EINVAL));
        match panic_val.downcast_ref::<&'static str>() {
            Some(s) => panic!("sommelier-drive-client-panic: {}",s),
            None => panic!("sommelier-drive-client-panic without an error message"),
        }
    }
);

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
    fn registerUser(client: CHttpClient) -> Result<CUserInfo, anyhow::Error> {
        let client: HttpClient = client.into();
        let fut_result = async { register_user(&client).await };
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

easy_ffi!(fn_int_pointer =>
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

fn_int_pointer!(
    fn getChildrenPathes(
        client: CHttpClient,
        user_info: CUserInfo,
        cur_path: *mut c_char,
        result_pathes: *mut *mut c_char,
    ) -> Result<c_int, anyhow::Error> {
        let client = client.into();
        let user_info = user_info.try_into()?;
        let cur_path = ptr2str(cur_path);
        let fut_result = async { get_children_pathes(&client, &user_info, cur_path).await };
        let rt = Runtime::new()?;
        let filepath_vec = rt.block_on(fut_result)?;
        let len = filepath_vec.len();
        let result_pathes = unsafe { slice::from_raw_parts_mut(result_pathes, 0) };
        for (i, filepath) in filepath_vec.into_iter().enumerate() {
            result_pathes[i] = str2ptr(filepath.as_str());
        }
        Ok(len as c_int)
    }
);

fn_int_pointer!(
    fn searchDescendantPathes(
        client: CHttpClient,
        user_info: CUserInfo,
        cur_path: *mut c_char,
        result_pathes: *mut *mut c_char,
    ) -> Result<c_int, anyhow::Error> {
        let client = client.into();
        let user_info = user_info.try_into()?;
        let cur_path = ptr2str(cur_path);
        let fut_result = async { search_descendant_pathes(&client, &user_info, cur_path).await };
        let rt = Runtime::new()?;
        let filepath_vec = rt.block_on(fut_result)?;
        let len = filepath_vec.len();
        let result_pathes = unsafe { slice::from_raw_parts_mut(result_pathes, 0) };
        for (i, filepath) in filepath_vec.into_iter().enumerate() {
            result_pathes[i] = str2ptr(filepath.as_str());
        }
        Ok(len as c_int)
    }
);

fn_int_pointer!(
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
    num_writeable_users: usize,
    readable_user_ids: *mut u64,
    writeable_user_ids: *mut u64,
    file_bytes_ptr: *const u8,
    file_bytes_len: usize,
}

impl From<ContentsData> for CContentsData {
    fn from(mut value: ContentsData) -> Self {
        let readable_user_ids_ptr = value.readable_user_ids.as_mut_ptr();
        mem::forget(value.readable_user_ids);
        let writeable_user_ids_ptr = value.writeable_user_ids.as_mut_ptr();
        mem::forget(value.writeable_user_ids);
        let file_bytes_ptr = value.file_bytes.as_ptr();
        let file_bytes_len = value.file_bytes.len();
        mem::forget(value.file_bytes);
        Self {
            is_file: if value.is_file { 1 } else { 0 },
            num_readable_users: value.num_readable_users,
            num_writeable_users: value.num_writeable_users,
            readable_user_ids: readable_user_ids_ptr,
            writeable_user_ids: writeable_user_ids_ptr,
            file_bytes_ptr,
            file_bytes_len,
        }
    }
}

impl Into<ContentsData> for CContentsData {
    fn into(self) -> ContentsData {
        let readable_user_ids =
            unsafe { slice::from_raw_parts(self.readable_user_ids, self.num_readable_users) }
                .to_vec();
        let writeable_user_ids =
            unsafe { slice::from_raw_parts(self.writeable_user_ids, self.num_writeable_users) }
                .to_vec();
        let file_bytes =
            unsafe { slice::from_raw_parts(self.file_bytes_ptr, self.file_bytes_len) }.to_vec();
        ContentsData {
            is_file: self.is_file == 1,
            num_readable_users: self.num_readable_users,
            num_writeable_users: self.num_writeable_users,
            readable_user_ids,
            writeable_user_ids,
            file_bytes,
        }
    }
}

easy_ffi!(fn_contents_data =>
    |err| {
        set_errno(Errno(EINVAL));
        return CContentsData {
            is_file: -1,
            num_readable_users: 0,
            num_writeable_users: 0,
            readable_user_ids: ptr::null_mut(),
            writeable_user_ids: ptr::null_mut(),
            file_bytes_ptr: ptr::null(),
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
        Ok(contents_data.into())
    }
);

fn_void!(
    fn addFile(
        client: CHttpClient,
        user_info: CUserInfo,
        cur_dir: *mut c_char,
        filename: *mut c_char,
        file_bytes_ptr: *const u8,
        file_bytes_len: usize,
    ) -> Result<(), anyhow::Error> {
        let client = client.into();
        let user_info = user_info.try_into()?;
        let cur_dir = ptr2str(cur_dir);
        let filename = ptr2str(filename);
        let file_bytes = unsafe { slice::from_raw_parts(file_bytes_ptr, file_bytes_len) }.to_vec();
        let fut_result =
            async { add_file(&client, &user_info, cur_dir, filename, file_bytes).await };
        let rt = Runtime::new()?;
        rt.block_on(fut_result)?;
        Ok(())
    }
);

fn_void!(
    fn addDirectory(
        client: CHttpClient,
        user_info: CUserInfo,
        cur_dir: *mut c_char,
        filename: *mut c_char,
    ) -> Result<(), anyhow::Error> {
        let client = client.into();
        let user_info = user_info.try_into()?;
        let cur_dir = ptr2str(cur_dir);
        let filename = ptr2str(filename);
        let fut_result = async { add_directory(&client, &user_info, cur_dir, filename).await };
        let rt = Runtime::new()?;
        rt.block_on(fut_result)?;
        Ok(())
    }
);

fn_void!(
    fn addReadPermission(
        client: CHttpClient,
        user_info: CUserInfo,
        filepath: *mut c_char,
        new_user_id: u64,
    ) -> Result<(), anyhow::Error> {
        let client = client.into();
        let user_info = user_info.try_into()?;
        let filepath = ptr2str(filepath);
        let fut_result =
            async { add_read_permission(&client, &user_info, filepath, new_user_id).await };
        let rt = Runtime::new()?;
        rt.block_on(fut_result)?;
        Ok(())
    }
);

fn_void!(
    fn modifyFile(
        client: CHttpClient,
        user_info: CUserInfo,
        filepath: *mut c_char,
        new_file_bytes_ptr: *const u8,
        new_file_bytes_len: usize,
    ) -> Result<(), anyhow::Error> {
        let client = client.into();
        let user_info = user_info.try_into()?;
        let filepath = ptr2str(filepath);
        let file_bytes =
            unsafe { slice::from_raw_parts(new_file_bytes_ptr, new_file_bytes_len) }.to_vec();
        let fut_result = async { modify_file(&client, &user_info, filepath, file_bytes).await };
        let rt = Runtime::new()?;
        rt.block_on(fut_result)?;
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
