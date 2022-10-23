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
