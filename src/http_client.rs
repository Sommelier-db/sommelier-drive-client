use crate::{
    types::{
        ContentsTableReocrd, DBInt, KeywordCT, KeywordPK, PathTableRecord, SharedKeyTableRecord,
        Trapdoor, UserTableRecord,
    },
    AuthorizationSeedTableRecord, WritePermissionTableRecord,
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

    pub async fn post_user(&self, data_pk: &PkePublicKey, keyword_pk: &KeywordPK) -> Result<DBInt> {
        let url = self.base_url.to_string() + "/user";
        let client = reqwest_wasm::Client::new();
        let mut map = HashMap::<&str, Value>::new();
        map.insert("dataPK", json!(data_pk.to_string()?));
        map.insert("keywordPK", json!(serde_json::to_string(&keyword_pk)?));
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
        write_user_id: DBInt,
        read_user_id: DBInt,
        permission_hash: &HashDigest,
        data_ct: &FilePathCT,
        keyword_ct: &KeywordCT,
    ) -> Result<DBInt> {
        let url = self.base_url.to_string() + "/file-path";
        let client = reqwest_wasm::Client::new();

        let write_user_id_str = write_user_id.to_string();
        let read_user_id_str = read_user_id.to_string();
        let permission_hash_str: String = permission_hash.to_string();
        let data_ct_str = data_ct.to_string();
        let keyword_ct_str = serde_json::to_string(&keyword_ct)?;

        let mut map_for_post = HashMap::new();

        let mut map_for_sign = BTreeMap::new();
        for (key, val_json, val_str) in [
            (
                "writeUserId",
                json!(write_user_id),
                write_user_id_str.as_str(),
            ),
            ("readUserId", json!(read_user_id), read_user_id_str.as_str()),
            (
                "premissionHash",
                json!(permission_hash_str),
                permission_hash_str.as_str(),
            ),
            ("dataCT", json!(data_ct_str), data_ct_str.as_str()),
            ("keywordCT", json!(keyword_ct_str), keyword_ct_str.as_str()),
        ] {
            map_for_post.insert(key, val_json);
            map_for_sign.insert(key, val_str);
        }

        let req_without_auth = client.post(&url).json(&map_for_post);
        let nonce = self.get_nonce_of_user_id(write_user_id).await?;
        let res = self
            .attach_signature(sk, req_without_auth, "POST", &url, nonce, map_for_sign)?
            .send()
            .await?;
        let text = res.text().await?;
        Ok(DBInt::from_str_radix(&text, 10)?)
    }

    pub async fn get_shared_key(&self, path_id: DBInt) -> Result<SharedKeyTableRecord> {
        let url = self.base_url.to_string() + "/shared-key";
        let client = reqwest_wasm::Client::new();
        let mut map = HashMap::<&str, String>::new();
        map.insert("pathId", path_id.to_string());
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
        write_user_id: DBInt,
        shared_key_ct: &[u8],
    ) -> Result<DBInt> {
        let url = self.base_url.to_string() + "/shared-key";
        let client = reqwest_wasm::Client::new();

        let write_user_id_str = write_user_id.to_string();
        let path_id_str = path_id.to_string();
        let ct_str = hex::encode(shared_key_ct);

        let mut map_for_post = HashMap::new();
        let mut map_for_sign = BTreeMap::new();
        for (key, val) in [
            ("writeUserId", write_user_id_str.as_str()),
            ("pathId", path_id_str.as_str()),
            ("ct", ct_str.as_str()),
        ] {
            map_for_post.insert(key, val);
            map_for_sign.insert(key, val);
        }

        let req_without_auth = client.post(&url).json(&map_for_post);
        let nonce = self.get_nonce_of_user_id(write_user_id).await?;
        let res = self
            .attach_signature(sk, req_without_auth, "POST", &url, nonce, map_for_sign)?
            .send()
            .await?;
        let text = res.text().await?;
        Ok(DBInt::from_str_radix(&text, 10)?)
    }

    pub async fn get_authorization_key(
        &self,
        path_id: DBInt,
    ) -> Result<AuthorizationSeedTableRecord> {
        let url = self.base_url.to_string() + "/authorization-seed";
        let client = reqwest_wasm::Client::new();
        let mut map = HashMap::<&str, String>::new();
        map.insert("pathId", path_id.to_string());
        let record = client
            .get(&url)
            .json(&map)
            .send()
            .await?
            .json::<AuthorizationSeedTableRecord>()
            .await?;
        Ok(record)
    }

    pub async fn post_authorization_seed(
        &self,
        sk: &PkeSecretKey,
        path_id: DBInt,
        write_user_id: DBInt,
        authorization_seed_ct: &AuthorizationSeedCT,
    ) -> Result<DBInt> {
        let url = self.base_url.to_string() + "/authorization-seed";
        let client = reqwest_wasm::Client::new();

        let write_user_id_str = write_user_id.to_string();
        let path_id_str = path_id.to_string();
        let ct_str = authorization_seed_ct.to_string();

        let mut map_for_post = HashMap::new();
        let mut map_for_sign = BTreeMap::new();
        for (key, val) in [
            ("writeUserId", write_user_id_str.as_str()),
            ("pathId", path_id_str.as_str()),
            ("ct", ct_str.as_str()),
        ] {
            map_for_post.insert(key, val);
            map_for_sign.insert(key, val);
        }

        let req_without_auth = client.post(&url).json(&map_for_post);
        let nonce = self.get_nonce_of_user_id(write_user_id).await?;
        let res = self
            .attach_signature(sk, req_without_auth, "POST", &url, nonce, map_for_sign)?
            .send()
            .await?;
        let text = res.text().await?;
        Ok(DBInt::from_str_radix(&text, 10)?)
    }

    pub async fn get_contents(&self, shared_key_hash: &HashDigest) -> Result<ContentsTableReocrd> {
        let url = self.base_url.to_string() + "/contents";
        let client = reqwest_wasm::Client::new();
        let mut map = HashMap::<&str, String>::new();
        map.insert("sharedKeyHash", shared_key_hash.to_string());
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
        authorization_seed: AuthorizationSeed,
        shared_key_hash: &HashDigest,
        contents_ct: &[u8],
    ) -> Result<DBInt> {
        let url = self.base_url.to_string() + "/contents";
        let client = reqwest_wasm::Client::new();

        let authorization_sk = pke_derive_secret_key_from_seeed(authorization_seed)?;
        let authorization_pk = pke_gen_public_key(&authorization_sk);
        let shared_key_hash_str = shared_key_hash.to_string();
        let pk_str = authorization_pk.to_string()?;
        let ct_str = hex::encode(contents_ct);

        let mut map_for_post = HashMap::new();
        let mut map_for_sign = BTreeMap::new();
        for (key, val) in [
            ("sharedKeyHash", shared_key_hash_str.as_str()),
            ("authorizationPK", pk_str.as_str()),
            ("ct", ct_str.as_str()),
        ] {
            map_for_post.insert(key, val);
            map_for_sign.insert(key, val);
        }

        let req_without_auth = client.post(&url).json(&map_for_post);

        let res = self
            .attach_signature(
                &authorization_sk,
                req_without_auth,
                "POST",
                &url,
                0,
                map_for_sign,
            )?
            .send()
            .await?;
        let text = res.text().await?;
        Ok(DBInt::from_str_radix(&text, 10)?)
    }

    pub async fn put_contents(
        &self,
        authorization_seed: AuthorizationSeed,
        shared_key_hash: &HashDigest,
        contents_ct: &[u8],
    ) -> Result<DBInt> {
        let url = self.base_url.to_string() + "/contents";
        let client = reqwest_wasm::Client::new();

        let authorization_sk = pke_derive_secret_key_from_seeed(authorization_seed)?;
        let shared_key_hash_str = shared_key_hash.to_string();
        let ct_str = hex::encode(contents_ct);

        let mut map_for_post = HashMap::new();
        let mut map_for_sign = BTreeMap::new();
        for (key, val) in [
            ("sharedKeyHash", shared_key_hash_str.as_str()),
            ("ct", ct_str.as_str()),
        ] {
            map_for_post.insert(key, val);
            map_for_sign.insert(key, val);
        }

        let req_without_auth = client.post(&url).json(&map_for_post);
        let pre_record = self.get_contents(shared_key_hash).await?;
        let nonce = pre_record.nonce;
        let res = self
            .attach_signature(
                &authorization_sk,
                req_without_auth,
                "PUT",
                &url,
                nonce,
                map_for_sign,
            )?
            .send()
            .await?;
        let text = res.text().await?;
        Ok(DBInt::from_str_radix(&text, 10)?)
    }

    pub async fn get_write_permission(&self, path_id: DBInt) -> Result<WritePermissionTableRecord> {
        let url = self.base_url.to_string() + "/write-permission";
        let client = reqwest_wasm::Client::new();
        let mut map = HashMap::<&str, String>::new();
        map.insert("pathId", path_id.to_string());
        let record = client
            .get(&url)
            .json(&map)
            .send()
            .await?
            .json::<WritePermissionTableRecord>()
            .await?;
        Ok(record)
    }

    pub async fn post_write_permission(
        &self,
        sk: &PkeSecretKey,
        write_user_id: DBInt,
        path_id: DBInt,
        user_id: DBInt,
    ) -> Result<DBInt> {
        let url = self.base_url.to_string() + "/write-permission";
        let client = reqwest_wasm::Client::new();

        let write_user_id_str = write_user_id.to_string();
        let path_id_str = path_id.to_string();
        let user_id_str = user_id.to_string();

        let mut map_for_post = HashMap::new();
        let mut map_for_sign = BTreeMap::new();
        for (key, val) in [
            ("writeUserId", write_user_id_str.as_str()),
            ("pathId", path_id_str.as_str()),
            ("userId", user_id_str.as_str()),
        ] {
            map_for_post.insert(key, val);
            map_for_sign.insert(key, val);
        }

        let req_without_auth = client.post(&url).json(&map_for_post);
        let nonce = self.get_nonce_of_user_id(write_user_id).await?;
        let res = self
            .attach_signature(sk, req_without_auth, "POST", &url, nonce, map_for_sign)?
            .send()
            .await?;
        let text = res.text().await?;
        Ok(DBInt::from_str_radix(&text, 10)?)
    }

    async fn get_nonce_of_user_id(&self, user_id: DBInt) -> Result<DBInt> {
        let record = self.get_user(user_id).await?;
        Ok(record.nonce)
    }

    fn attach_signature(
        &self,
        sk: &PkeSecretKey,
        request_builder: RequestBuilder,
        method: &str,
        url: &str,
        nonce: DBInt,
        map_for_sign: BTreeMap<&str, &str>,
    ) -> Result<RequestBuilder> {
        let mut rng = OsRng;
        let signature = gen_signature(
            sk,
            &self.region_name,
            method,
            url,
            nonce,
            map_for_sign,
            &mut rng,
        );
        let mut header_val = HeaderValue::from_str(&hex::encode(signature))?;
        header_val.set_sensitive(true);
        Ok(request_builder.header(AUTHORIZATION, header_val))
    }
}
