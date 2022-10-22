use crate::types::{
    ContentsTableReocrd, DBInt, KeywordCT, KeywordPK, PathTableRecord, SharedKeyTableRecord,
    Trapdoor, UserTableRecord, WritePermissionTable,
};
use anyhow::Result;
use paired::bls12_381::{Bls12, Fr};
use reqwest_wasm;
use rust_searchable_pke::pecdk;
use serde::{Deserialize, Serialize};
use serde_json;
use sommelier_drive_cryptos::{gen_signature, FilePathCT, HashDigest, PkePublicKey};
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone)]
pub struct HttpClient {
    base_url: String,
}

impl HttpClient {
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
        let mut map = HashMap::new();
        map.insert("dataPK".to_string(), serde_json::to_string(data_pk)?);
        map.insert("keywordPK".to_string(), serde_json::to_string(keyword_pk)?);
        let res = client.post(url).json(&map).send().await?;
        let text = res.text().await?;
        Ok(DBInt::from_str_radix(&text, 10)?)
    }

    pub async fn get_file_path(&self, path_id: &str) -> Result<PathTableRecord> {
        let url = self.base_url.to_string() + "/file-path/" + path_id;
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
        let permission_hash_str = permission_hash.to_string()?;
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

    /*pub async fn post_file_path(
        &self,
        path_id: &DBInt,
        write_user_id: DBInt,
        read_user_id: DBInt,
        permission_hash: &HashDigest,
        data_ct: &Vec<u8>,
        keyword_ct: &KeywordCT,
    ) -> Result<DBInt> {
        let url = self.base_url.to_string() + "/file-path/" + &path_id.to_string();
        let client = reqwest_wasm::Client::new();
        let mut map = HashMap::new();
        map.insert("writeUserId".to_string(), write_user_id.to_string());
    }*/
}
