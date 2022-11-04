use crate::types::{
    ContentsTableReocrd, DBInt, KeywordCT, KeywordPK, PathTableRecord, SharedKeyTableRecord,
    Trapdoor, UserTableRecord,
};
use aes_gcm::aead::OsRng;
use anyhow::Result;
use reqwest_wasm::{
    self,
    header::{HeaderValue, AUTHORIZATION},
    RequestBuilder,
};
use serde_json::json;
use serde_json::{self, Value};
use sommelier_drive_cryptos::{
    gen_signature, pke_derive_secret_key_from_seeed, pke_gen_public_key, AuthorizationSeed,
    AuthorizationSeedCT, FilePathCT, HashDigest, HexString, PemString, PkePublicKey, PkeSecretKey,
};
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone)]
pub struct HttpClient {
    pub(crate) base_url: String,
    pub(crate) region_name: &'static str,
}

impl HttpClient {
    pub fn new(base_url: &str, region_name: &'static str) -> Self {
        Self {
            base_url: base_url.to_string(),
            region_name,
        }
    }

    pub async fn get_user(&self, user_id: DBInt) -> Result<UserTableRecord> {
        let url = self.base_url.to_string() + "/user";
        let client = reqwest_wasm::Client::new();
        let mut map = HashMap::<&str, Value>::new();
        map.insert("userId", json!(user_id));
        let record = client
            .get(url)
            .json(&map)
            .send()
            .await?
            .json::<UserTableRecord>()
            .await?;
        Ok(record)
    }

    pub async fn post_user(
        &self,
        data_pk: &PkePublicKey,
        keyword_pk: &KeywordPK,
        data_ct: &FilePathCT,
        keyword_ct: &KeywordCT,
    ) -> Result<DBInt> {
        let url = self.base_url.to_string() + "/user";
        let client = reqwest_wasm::Client::new();

        let mut map = HashMap::<&str, Value>::new();
        map.insert("dataPK", json!(data_pk.to_string()?));
        map.insert("keywordPK", json!(serde_json::to_string(&keyword_pk)?));
        map.insert("dataCT", json!(data_ct.to_string()));
        map.insert("keywordCT", json!(serde_json::to_string(keyword_ct)?));
        let res = client.post(url).json(&map).send().await?;
        let text = res.text().await?;
        Ok(DBInt::from_str_radix(&text, 10)?)
    }

    pub async fn get_filepath(&self, path_id: DBInt) -> Result<PathTableRecord> {
        let url = self.base_url.to_string() + "/file-path";
        let client = reqwest_wasm::Client::new();
        let mut map = HashMap::<&str, Value>::new();
        map.insert("pathId", json!(path_id));
        let record = client
            .get(&url)
            .json(&map)
            .send()
            .await?
            .json::<PathTableRecord>()
            .await?;
        Ok(record)
    }

    pub async fn get_children_file_pathes(
        &self,
        permission_hash: &HashDigest,
    ) -> Result<Vec<PathTableRecord>> {
        let url = self.base_url.to_string() + "/file-path/children";
        let client = reqwest_wasm::Client::new();
        let mut map = HashMap::<&str, Value>::new();
        map.insert("permissionHash", json!(permission_hash.to_string()));
        let records = client
            .get(&url)
            .json(&map)
            .send()
            .await?
            .json::<Vec<PathTableRecord>>()
            .await?;
        Ok(records)
    }

    pub async fn search_file_pathes(
        &self,
        user_id: DBInt,
        td: &Trapdoor,
    ) -> Result<Vec<PathTableRecord>> {
        let url = self.base_url.to_string() + "/file-path/search";
        let client = reqwest_wasm::Client::new();
        let mut map = HashMap::new();
        map.insert("userId", json!(user_id));
        map.insert("trapdoor", json!(serde_json::to_string(td)?));
        let records = client
            .get(url)
            .json(&map)
            .send()
            .await?
            .json::<Vec<PathTableRecord>>()
            .await?;
        Ok(records)
    }

    pub async fn post_file_path(
        &self,
        sk: &PkeSecretKey,
        read_user_id: DBInt,
        permission_hash: &HashDigest,
        data_ct: &FilePathCT,
        keyword_ct: &KeywordCT,
    ) -> Result<DBInt> {
        let url = self.base_url.to_string() + "/file-path";
        let client = reqwest_wasm::Client::new();

        let read_user_id_str = read_user_id.to_string();
        let permission_hash_str: String = permission_hash.to_string();
        let data_ct_str = data_ct.to_string();
        let keyword_ct_str = serde_json::to_string(&keyword_ct)?;

        let mut map_for_post = HashMap::new();

        for (key, val_json, val_str) in [
            ("readUserId", json!(read_user_id), read_user_id_str.as_str()),
            (
                "permissionHash",
                json!(permission_hash_str),
                permission_hash_str.as_str(),
            ),
            ("dataCT", json!(data_ct_str), data_ct_str.as_str()),
            ("keywordCT", json!(keyword_ct_str), keyword_ct_str.as_str()),
        ] {
            map_for_post.insert(key, val_json);
        }

        let res = client.post(&url).json(&map_for_post).send().await?;
        let text = res.text().await?;
        Ok(DBInt::from_str_radix(&text, 10)?)
    }

    pub async fn get_shared_key(&self, path_id: DBInt) -> Result<SharedKeyTableRecord> {
        let url = self.base_url.to_string() + "/shared-key";
        let client = reqwest_wasm::Client::new();
        let mut map = HashMap::<&str, Value>::new();
        map.insert("pathId", json!(path_id));
        let record = client
            .get(&url)
            .json(&map)
            .send()
            .await?
            .json::<SharedKeyTableRecord>()
            .await?;
        Ok(record)
    }

    pub async fn post_shared_key(
        &self,
        sk: &PkeSecretKey,
        path_id: DBInt,
        shared_key_ct: &[u8],
    ) -> Result<DBInt> {
        let url = self.base_url.to_string() + "/shared-key";
        let client = reqwest_wasm::Client::new();

        let path_id_str = path_id.to_string();
        let ct_str = hex::encode(shared_key_ct);

        let mut map_for_post = HashMap::new();
        for (key, val_json, val_str) in [
            ("pathId", json!(path_id), path_id_str.as_str()),
            ("ct", json!(ct_str), ct_str.as_str()),
        ] {
            map_for_post.insert(key, val_json);
        }

        let res = client.post(&url).json(&map_for_post).send().await?;
        let text = res.text().await?;
        Ok(DBInt::from_str_radix(&text, 10)?)
    }

    pub async fn get_contents(&self, shared_key_hash: &HashDigest) -> Result<ContentsTableReocrd> {
        let url = self.base_url.to_string() + "/contents";
        let client = reqwest_wasm::Client::new();
        let mut map = HashMap::<&str, Value>::new();
        map.insert("sharedKeyHash", json!(shared_key_hash.to_string()));
        let record = client
            .get(&url)
            .json(&map)
            .send()
            .await?
            .json::<ContentsTableReocrd>()
            .await?;
        Ok(record)
    }

    pub async fn post_contents(
        &self,
        shared_key_hash: &HashDigest,
        contents_ct: &[u8],
    ) -> Result<DBInt> {
        let url = self.base_url.to_string() + "/contents";
        let client = reqwest_wasm::Client::new();

        let shared_key_hash_str = shared_key_hash.to_string();
        let ct_str = hex::encode(contents_ct);

        let mut map_for_post = HashMap::new();
        for (key, val_json, val_str) in [
            (
                "sharedKeyHash",
                json!(shared_key_hash_str),
                shared_key_hash_str.as_str(),
            ),
            ("ct", json!(ct_str), ct_str.as_str()),
        ] {
            map_for_post.insert(key, val_json);
        }

        let res = client.post(&url).json(&map_for_post).send().await?;
        let text = res.text().await?;
        Ok(DBInt::from_str_radix(&text, 10)?)
    }

    pub async fn put_contents(
        &self,
        shared_key_hash: &HashDigest,
        contents_ct: &[u8],
    ) -> Result<DBInt> {
        let url = self.base_url.to_string() + "/contents";
        let client = reqwest_wasm::Client::new();

        let shared_key_hash_str = shared_key_hash.to_string();
        let ct_str = hex::encode(contents_ct);

        let mut map_for_post = HashMap::new();
        let mut map_for_sign = BTreeMap::new();
        for (key, val_json, val_str) in [
            (
                "sharedKeyHash",
                json!(shared_key_hash_str),
                shared_key_hash_str.as_str(),
            ),
            ("ct", json!(ct_str), ct_str.as_str()),
        ] {
            map_for_post.insert(key, val_json);
            map_for_sign.insert(key, val_str);
        }

        let res = client.put(&url).json(&map_for_post).send().await?;
        let text = res.text().await?;
        Ok(DBInt::from_str_radix(&text, 10)?)
    }
}
