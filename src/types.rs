use paired::bls12_381::Bls12;
use rust_searchable_pke::pecdk;
use serde::{Deserialize, Serialize};
//use sommelier_drive_cryptos::{FilePathCT, PkePublicKey};

pub type DBInt = u64;
pub type KeywordPK = pecdk::PublicKey<Bls12>;
pub type KeywordCT = pecdk::Ciphertext<Bls12>;
pub type Trapdoor = pecdk::Trapdoor<Bls12>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserTableRecord {
    user_id: DBInt,
    data_pk: String,
    keyword_pk: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PathTableRecord {
    path_id: DBInt,
    user_id: DBInt,
    permission_hash: String,
    data_ct: String,
    keyword_ct: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SharedKeyTableRecord {
    shared_key_id: DBInt,
    path_id: DBInt,
    shared_key_ct: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContentsTableReocrd {
    contents_id: DBInt,
    shared_key_hash: String,
    contents_ct: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WritePermissionTableRecord {
    write_permission_id: DBInt,
    path_id: DBInt,
    user_id: DBInt,
}
