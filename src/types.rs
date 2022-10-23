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
    pub(crate) user_id: DBInt,
    pub(crate) data_pk: String,
    pub(crate) keyword_pk: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PathTableRecord {
    pub(crate) path_id: DBInt,
    pub(crate) user_id: DBInt,
    pub(crate) permission_hash: String,
    pub(crate) data_ct: String,
    pub(crate) keyword_ct: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SharedKeyTableRecord {
    pub(crate) shared_key_id: DBInt,
    pub(crate) path_id: DBInt,
    pub(crate) shared_key_ct: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContentsTableReocrd {
    pub(crate) contents_id: DBInt,
    pub(crate) shared_key_hash: String,
    pub(crate) contents_ct: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WritePermissionTableRecord {
    pub(crate) write_permission_id: DBInt,
    pub(crate) path_id: DBInt,
    pub(crate) user_id: DBInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContentsData {
    pub(crate) is_file: bool,
    pub(crate) num_readable_users: usize,
    pub(crate) num_writeable_users: usize,
    pub(crate) readable_user_ids: Vec<DBInt>,
    pub(crate) writeable_user_ids: Vec<DBInt>,
    pub(crate) file_bytes: Vec<u8>,
}

use bytes::{Buf, BufMut};
impl ContentsData {
    const MAX_BYTE_SIZE: usize = 1048576 * 2;
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut p = &bytes[..];
        let is_file = p.get_u8() == 1u8;
        let num_readable_users = p.get_u64() as usize;
        let num_writeable_users = p.get_u64() as usize;
        let mut readable_user_ids = Vec::with_capacity(num_readable_users);
        for _ in 0..num_readable_users {
            let user_id = p.get_u64();
            readable_user_ids.push(user_id);
        }
        let mut writeable_user_ids = Vec::with_capacity(num_writeable_users);
        for _ in 0..num_writeable_users {
            let user_id = p.get_u64();
            writeable_user_ids.push(user_id);
        }
        let mut file_bytes = Vec::new();
        file_bytes.put(&mut p.take(Self::MAX_BYTE_SIZE));
        assert!(p.has_remaining());
        Self {
            is_file,
            num_readable_users,
            num_writeable_users,
            readable_user_ids,
            writeable_user_ids,
            file_bytes,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.put_u8(if self.is_file { 1u8 } else { 0u8 });
        buf.put_u64(self.num_readable_users as u64);
        buf.put_u64(self.num_writeable_users as u64);
        for i in 0..self.num_readable_users {
            buf.put_u64(self.readable_user_ids[i]);
        }
        for i in 0..self.num_writeable_users {
            buf.put_u64(self.writeable_user_ids[i]);
        }
        for file_byte in self.file_bytes.iter() {
            buf.put_u8(*file_byte);
        }
        buf
    }
}
