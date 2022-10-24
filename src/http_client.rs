use crate::types::{
    ContentsTableReocrd, DBInt, KeywordCT, KeywordPK, PathTableRecord, SharedKeyTableRecord,
    Trapdoor, UserTableRecord, WritePermissionTableRecord,
};
use aes_gcm::aead::OsRng;
use anyhow::Result;
use reqwest_wasm::{
    self,
    header::{HeaderValue, AUTHORIZATION},
    RequestBuilder,
};
use serde_json;
use sommelier_drive_cryptos::{
    gen_signature, FilePathCT, HashDigest, HexString, JsonString, PkePublicKey, PkeSecretKey,
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
        let url = self.base_url.to_string() + "/user/" + &user_id.to_string();
        let record = reqwest_wasm::get(&url)
            .await?
            .json::<UserTableRecord>()
            .await?;
        Ok(record)
    }

    pub async fn post_user(&self, data_pk: &PkePublicKey, keyword_pk: &KeywordPK) -> Result<DBInt> {
        let url = self.base_url.to_string() + "/user";
        let client = reqwest_wasm::Client::new();
        let mut map = HashMap::<String, String>::new();
        map.insert("dataPK".to_string(), data_pk.to_string()?);
        map.insert("keywordPK".to_string(), serde_json::to_string(&keyword_pk)?);
        let res = client.post(url).json(&map).send().await?;
        let text = res.text().await?;
        Ok(DBInt::from_str_radix(&text, 10)?)
    }

    pub async fn get_file_path(&self, path_id: DBInt) -> Result<PathTableRecord> {
        let url = self.base_url.to_string() + "/file-path/" + path_id.to_string().as_ref();
        let record = reqwest_wasm::get(&url)
            .await?
            .json::<PathTableRecord>()
            .await?;
        Ok(record)
    }

    pub async fn get_children_file_pathes(
        &self,
        permission_hash: &HashDigest,
    ) -> Result<Vec<PathTableRecord>> {
        let permission_hash_str: String = permission_hash.to_string();
        let url = self.base_url.to_string() + "/file-path/children/" + &permission_hash_str;
        let records = reqwest_wasm::get(&url)
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
        let url = self.base_url.to_string() + "/file-path/search/" + &user_id.to_string();
        let client = reqwest_wasm::Client::new();
        let mut map = HashMap::new();
        map.insert("trapdoor".to_string(), serde_json::to_string(td)?);
        let res = client.get(url).json(&map).send().await?;
        let records = res.json::<Vec<PathTableRecord>>().await?;
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
        for (key, val) in [
            ("writeUserId", write_user_id_str.as_str()),
            ("readUserId", read_user_id_str.as_str()),
            ("premissionHash", permission_hash_str.as_str()),
            ("dataCT", data_ct_str.as_str()),
            ("keywordCT", keyword_ct_str.as_str()),
        ] {
            map_for_post.insert(key, val);
            map_for_sign.insert(key, val);
        }

        let req_without_auth = client.post(&url).json(&map_for_post);
        let res = self
            .attach_signature(
                sk,
                req_without_auth,
                "POST",
                &url,
                write_user_id,
                map_for_sign,
            )
            .await?
            .send()
            .await?;
        let text = res.text().await?;
        Ok(DBInt::from_str_radix(&text, 10)?)
    }

    pub async fn get_shared_key(&self, path_id: DBInt) -> Result<SharedKeyTableRecord> {
        let url = self.base_url.to_string() + "/shared-key/?path-id=" + &path_id.to_string();
        let record = reqwest_wasm::get(&url)
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
        let url = self.base_url.to_string() + "/shared-key/" + &path_id.to_string();
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
        let res = self
            .attach_signature(
                sk,
                req_without_auth,
                "POST",
                &url,
                write_user_id,
                map_for_sign,
            )
            .await?
            .send()
            .await?;
        let text = res.text().await?;
        Ok(DBInt::from_str_radix(&text, 10)?)
    }

    pub async fn get_contents(&self, shared_key_hash: &HashDigest) -> Result<ContentsTableReocrd> {
        let shared_key_hash_str: String = shared_key_hash.to_string();
        let url = self.base_url.to_string()
            + "/contents/?shared-key-hash="
            + shared_key_hash_str.as_str();
        let record = reqwest_wasm::get(&url)
            .await?
            .json::<ContentsTableReocrd>()
            .await?;
        Ok(record)
    }

    pub async fn post_contents(
        &self,
        sk: &PkeSecretKey,
        write_user_id: DBInt,
        shared_key_hash: &HashDigest,
        contents_ct: &[u8],
    ) -> Result<DBInt> {
        let url = self.base_url.to_string() + "/contents";
        let client = reqwest_wasm::Client::new();

        let write_user_id_str = write_user_id.to_string();
        let shared_key_hash_str: String = shared_key_hash.to_string();
        let ct_str = hex::encode(contents_ct);

        let mut map_for_post = HashMap::new();
        let mut map_for_sign = BTreeMap::new();
        for (key, val) in [
            ("writeUserId", write_user_id_str.as_str()),
            ("sharedKeyHash", shared_key_hash_str.as_str()),
            ("ct", ct_str.as_str()),
        ] {
            map_for_post.insert(key, val);
            map_for_sign.insert(key, val);
        }

        let req_without_auth = client.post(&url).json(&map_for_post);
        let res = self
            .attach_signature(
                sk,
                req_without_auth,
                "POST",
                &url,
                write_user_id,
                map_for_sign,
            )
            .await?
            .send()
            .await?;
        let text = res.text().await?;
        Ok(DBInt::from_str_radix(&text, 10)?)
    }

    pub async fn put_contents(
        &self,
        sk: &PkeSecretKey,
        write_user_id: DBInt,
        shared_key_hash: &HashDigest,
        contents_ct: &[u8],
    ) -> Result<DBInt> {
        let shared_key_hash_str: String = shared_key_hash.to_string();
        let url = self.base_url.to_string()
            + "/contents/?shared-key-hash="
            + shared_key_hash_str.as_str();
        let client = reqwest_wasm::Client::new();

        let write_user_id_str = write_user_id.to_string();
        let ct_str = hex::encode(contents_ct);

        let mut map_for_post = HashMap::new();
        let mut map_for_sign = BTreeMap::new();
        for (key, val) in [
            ("writeUserId", write_user_id_str.as_str()),
            ("ct", ct_str.as_str()),
        ] {
            map_for_post.insert(key, val);
            map_for_sign.insert(key, val);
        }

        let req_without_auth = client.post(&url).json(&map_for_post);
        let res = self
            .attach_signature(
                sk,
                req_without_auth,
                "PUT",
                &url,
                write_user_id,
                map_for_sign,
            )
            .await?
            .send()
            .await?;
        let text = res.text().await?;
        Ok(DBInt::from_str_radix(&text, 10)?)
    }

    pub async fn get_write_permission(&self, path_id: DBInt) -> Result<WritePermissionTableRecord> {
        let url = self.base_url.to_string()
            + "/write-permission/?path-id="
            + path_id.to_string().as_str();
        let record = reqwest_wasm::get(&url)
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
        permitted_user_id: DBInt,
    ) -> Result<DBInt> {
        let url = self.base_url.to_string() + "/write-permission";
        let client = reqwest_wasm::Client::new();

        let write_user_id_str = write_user_id.to_string();
        let path_id_str = path_id.to_string();
        let permitted_user_id_str = permitted_user_id.to_string();

        let mut map_for_post = HashMap::new();
        let mut map_for_sign = BTreeMap::new();
        for (key, val) in [
            ("writeUserId", write_user_id_str.as_str()),
            ("pathId", path_id_str.as_str()),
            ("userId", permitted_user_id_str.as_str()),
        ] {
            map_for_post.insert(key, val);
            map_for_sign.insert(key, val);
        }

        let req_without_auth = client.post(&url).json(&map_for_post);
        let res = self
            .attach_signature(
                sk,
                req_without_auth,
                "POST",
                &url,
                write_user_id,
                map_for_sign,
            )
            .await?
            .send()
            .await?;
        let text = res.text().await?;
        Ok(DBInt::from_str_radix(&text, 10)?)
    }

    async fn attach_signature(
        &self,
        sk: &PkeSecretKey,
        request_builder: RequestBuilder,
        method: &str,
        url: &str,
        user_id: DBInt,
        map_for_sign: BTreeMap<&str, &str>,
    ) -> Result<RequestBuilder> {
        let mut rng = OsRng;
        let my_record = self.get_user(user_id).await?;
        let nonce = my_record.nonce;
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

#[cfg(test)]
mod test {
    use sommelier_drive_cryptos::{pke_gen_public_key, pke_gen_secret_key, verify_signature};

    use super::*;
    use tokio;

    #[tokio::test]
    async fn attach_signature_test() {
        let mut rng = OsRng;
        let sk = pke_gen_secret_key(&mut rng).unwrap();
        let base_url = "http://test.com";
        let client = reqwest_wasm::Client::new();
        let request_builder = client.post(base_url);
        let method = "POST";
        let url = base_url.to_string() + "/post";
        let user_id = 1;
        let mut map_for_sign = BTreeMap::new();
        map_for_sign.insert("key1", "value1");
        map_for_sign.insert("key2", "value2");
        let region_name = "attach_signature_test";
        let client = HttpClient::new(base_url, region_name);
        /*let signature_request = client
            .attach_signature(&sk, request_builder, method, &url, user_id, map_for_sign)
            .await
            .unwrap()
            .build()
            .unwrap();
        let signature_value = signature_request.headers().get(AUTHORIZATION).unwrap();
        let signature = hex::decode(signature_value.to_str().unwrap()).unwrap();*/
    }
}
