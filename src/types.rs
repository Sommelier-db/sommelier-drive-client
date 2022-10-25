use paired::bls12_381::Bls12;
use rust_searchable_pke::pecdk;
use serde::{Deserialize, Serialize};
//use sommelier_drive_cryptos::{FilePathCT, PkePublicKey};

pub type DBInt = u64;
pub type KeywordSK = pecdk::SecretKey<Bls12>;
pub type KeywordPK = pecdk::PublicKey<Bls12>;
pub type KeywordCT = pecdk::Ciphertext<Bls12>;
pub type Trapdoor = pecdk::Trapdoor<Bls12>;

pub const MAX_NUM_KEYWORD: usize = 64;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserTableRecord {
    #[serde(rename = "userId")]
    pub user_id: DBInt,
    #[serde(rename = "dataPK")]
    pub data_pk: String,
    #[serde(rename = "keywordPK")]
    pub keyword_pk: String,
    #[serde(rename = "nonce")]
    pub nonce: DBInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PathTableRecord {
    #[serde(rename = "pathId")]
    pub path_id: DBInt,
    #[serde(rename = "userId")]
    pub user_id: DBInt,
    #[serde(rename = "permissionHash")]
    pub permission_hash: String,
    #[serde(rename = "dataCT")]
    pub data_ct: String,
    #[serde(rename = "keywordCT")]
    pub keyword_ct: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SharedKeyTableRecord {
    #[serde(rename = "sharedKeyId")]
    pub shared_key_id: DBInt,
    #[serde(rename = "pathId")]
    pub path_id: DBInt,
    #[serde(rename = "sharedKeyCT")]
    pub shared_key_ct: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorizationSeedTableRecord {
    #[serde(rename = "authorizationSeedId")]
    pub authorization_seed_id: DBInt,
    #[serde(rename = "pathId")]
    pub path_id: DBInt,
    #[serde(rename = "authorizationSeedCT")]
    pub authorization_seed_ct: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContentsTableReocrd {
    #[serde(rename = "contentsId")]
    pub contents_id: DBInt,
    #[serde(rename = "sharedKeyHash")]
    pub shared_key_hash: String,
    #[serde(rename = "authorizationPK")]
    pub authorization_pk: String,
    #[serde(rename = "nonce")]
    pub nonce: DBInt,
    #[serde(rename = "contentsCT")]
    pub contents_ct: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WritePermissionTableRecord {
    #[serde(rename = "wPermissionId")]
    pub w_permission_id: DBInt,
    #[serde(rename = "pathId")]
    pub path_id: DBInt,
    #[serde(rename = "userId")]
    pub user_id: DBInt,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContentsData {
    pub is_file: bool,
    pub num_readable_users: usize,
    pub num_writeable_users: usize,
    pub readable_user_path_ids: Vec<DBInt>,
    pub writeable_user_path_ids: Vec<DBInt>,
    pub file_bytes: Vec<u8>,
}

use bytes::{Buf, BufMut};
impl ContentsData {
    const MAX_BYTE_SIZE: usize = 1048576 * 2;
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut p = &bytes[..];
        let is_file = p.get_u8() == 1u8;
        let num_readable_users = p.get_u64() as usize;
        let num_writeable_users = p.get_u64() as usize;
        let mut readable_user_path_ids = Vec::with_capacity(num_readable_users);
        for _ in 0..num_readable_users {
            let user_id = p.get_u64();
            readable_user_path_ids.push(user_id);
        }
        let mut writeable_user_path_ids = Vec::with_capacity(num_writeable_users);
        for _ in 0..num_writeable_users {
            let user_id = p.get_u64();
            writeable_user_path_ids.push(user_id);
        }
        let mut file_bytes = Vec::new();
        file_bytes.put(&mut p.take(Self::MAX_BYTE_SIZE));
        assert!(p.has_remaining());
        Self {
            is_file,
            num_readable_users,
            num_writeable_users,
            readable_user_path_ids,
            writeable_user_path_ids,
            file_bytes,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.put_u8(if self.is_file { 1u8 } else { 0u8 });
        buf.put_u64(self.num_readable_users as u64);
        buf.put_u64(self.num_writeable_users as u64);
        for i in 0..self.num_readable_users {
            buf.put_u64(self.readable_user_path_ids[i]);
        }
        for i in 0..self.num_writeable_users {
            buf.put_u64(self.writeable_user_path_ids[i]);
        }
        for file_byte in self.file_bytes.iter() {
            buf.put_u8(*file_byte);
        }
        buf
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn contents_data_test() {
        let test_data = ContentsData {
            is_file: true,
            num_readable_users: 2,
            num_writeable_users: 2,
            readable_user_path_ids: vec![1, 2],
            writeable_user_path_ids: vec![1, 2],
            file_bytes: vec![7; 32],
        };
        let test_data_bytes = test_data.to_bytes();
        let recovered_data = ContentsData::from_bytes(&test_data_bytes);
        assert_eq!(test_data, recovered_data)
    }
}
