use crate::http_client::HttpClient;
use crate::types::*;
use aes_gcm::aead;
use anyhow::Result;
use sommelier_drive_cryptos::{
    pke_gen_public_key, pke_gen_secret_key, PemString, PkePublicKey, PkeSecretKey,
};

#[derive(Debug, Clone)]
pub struct SelfUserInfo {
    pub data_sk: PkeSecretKey,
    pub keyword_sk: KeywordSK,
    pub id: DBInt,
}

pub async fn register_user(client: &HttpClient) -> Result<SelfUserInfo> {
    let mut rng1 = aead::OsRng;
    let data_sk = pke_gen_secret_key(&mut rng1)?;
    let data_pk = pke_gen_public_key(&data_sk);
    let mut rng2 = rand_core::OsRng;
    let keyword_sk = KeywordSK::gen(&mut rng2, MAX_NUM_KEYWORD);
    let keyword_pk = keyword_sk.into_public_key();
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

#[cfg(test)]
mod test {
    use super::*;
    use aes_gcm::aead;
    use anyhow::Result;
    use httpmock::prelude::*;
    use sommelier_drive_cryptos::{pke_gen_public_key, pke_gen_secret_key, PemString};
    use tokio;

    #[tokio::test]
    async fn register_user_test() -> Result<()> {
        let server = MockServer::start_async().await;
        let region_name = "register_user_test";
        let client = HttpClient::new(server.base_url().as_str(), region_name);
        let user_id = 1;
        let mock = server.mock(|when, then| {
            when.method(POST)
                .path_matches(Regex::new("/user").unwrap())
                .header("content-type", "application/json");
            then.status(200)
                .header("content-type", "application/json")
                .body(user_id.to_string());
        });
        let user_info = register_user(&client).await?;
        println!("user_info {:?}", user_info);
        assert_eq!(user_info.id, user_id);
        mock.assert();
        Ok(())
    }

    #[tokio::test]
    async fn get_user_test() -> Result<()> {
        let mut rng1 = aead::OsRng;
        let data_sk = pke_gen_secret_key(&mut rng1)?;
        let data_pk = pke_gen_public_key(&data_sk);
        let mut rng2 = rand_core::OsRng;
        let keyword_sk = KeywordSK::gen(&mut rng2, MAX_NUM_KEYWORD);
        let keyword_pk = keyword_sk.into_public_key();
        let user_id = 1;
        let nonce = 1;

        let server = MockServer::start_async().await;
        let region_name = "get_user_test";
        let client = HttpClient::new(server.base_url().as_str(), region_name);
        let mock = server.mock(|when, then| {
            when.method(GET)
                .path_matches(Regex::new("/user").unwrap())
                .header("content-type", "application/json");
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&UserTableRecord {
                    user_id,
                    data_pk: data_pk.to_string().unwrap(),
                    keyword_pk: serde_json::to_string(&keyword_pk).unwrap(),
                    nonce,
                });
        });
        let (data_pk2, keyword_pk2) = get_user_public_keys(&client, user_id).await?;
        assert_eq!(data_pk.to_string()?, data_pk2.to_string()?);
        assert_eq!(
            serde_json::to_string(&keyword_pk).unwrap(),
            serde_json::to_string(&keyword_pk2).unwrap()
        );
        mock.assert();
        Ok(())
    }
}
