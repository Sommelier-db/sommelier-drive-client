use crate::http_client::HttpClient;
use crate::types::*;
use aes_gcm::aead;
use anyhow::Result;
use rust_searchable_pke::pecdk;
use sommelier_drive_cryptos::{
    pke_gen_public_key, pke_gen_secret_key, JsonString, PkePublicKey, PkeSecretKey,
};

#[derive(Debug, Clone)]
pub struct SelfUserInfo {
    data_sk: PkeSecretKey,
    keyword_sk: KeywordSK,
    id: DBInt,
}

pub async fn register_user(client: &HttpClient) -> Result<SelfUserInfo> {
    let mut rng1 = aead::OsRng;
    let data_sk = pke_gen_secret_key(&mut rng1)?;
    let data_pk = pke_gen_public_key(&data_sk);
    let mut rng2 = rand_core::OsRng;
    let keyword_sk = KeywordSK::gen(&mut rng2, MAX_NUM_KEYWORD);
    let keyword_pk = keyword_sk.into_public_key(&mut rng2);
    let id = client.post_user(&data_pk, &keyword_pk).await?;
    Ok(SelfUserInfo {
        data_sk,
        keyword_sk,
        id,
    })
}

pub async fn get_user_public_keys(
    client: &HttpClient,
    user_id: DBInt,
) -> Result<(PkePublicKey, KeywordPK)> {
    let record = client.get_user(user_id).await?;
    let data_pk = PkePublicKey::from_str(&record.data_pk)?;
    let keyword_pk = serde_json::from_str(&record.keyword_pk)?;
    Ok((data_pk, keyword_pk))
}
