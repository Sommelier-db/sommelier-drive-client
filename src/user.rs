use std::env::split_paths;

use crate::http_client::HttpClient;
use crate::types::*;
use crate::utils::*;
use aes_gcm::aead;
use aes_gcm::aead::rand_core::RngCore as _;
use anyhow::Result;
use paired::bls12_381::Fr;
use rust_searchable_pke::expressions::gen_ciphertext_for_prefix_search;
use sommelier_drive_cryptos::*;

#[derive(Debug, Clone)]
pub struct SelfUserInfo {
    pub data_sk: PkeSecretKey,
    pub keyword_sk: KeywordSK,
    pub id: DBInt,
}

pub async fn register_user(client: &HttpClient, filepath: &str) -> Result<SelfUserInfo> {
    let mut rng1 = aead::OsRng;
    let data_sk = pke_gen_secret_key(&mut rng1)?;
    let data_pk = pke_gen_public_key(&data_sk);
    let mut rng2 = rand_core::OsRng;
    let keyword_sk = KeywordSK::gen(&mut rng2, MAX_NUM_KEYWORD);
    let keyword_pk = keyword_sk.into_public_key();
    let (filepath_cts, shared_key_cts, recovered_shared_key) =
        encrypt_new_path_for_multi_pks(&[data_pk.clone()], &filepath)?;
    let data_ct = filepath_cts[0].clone();
    let keyword_ct = gen_ciphertext_for_prefix_search::<_, Fr, _>(
        &keyword_pk,
        &client.region_name,
        filepath,
        &mut rand_core::OsRng,
    )?;
    let shared_key_ct = shared_key_cts[0].clone();

    // 1. User table & Path table & Write permission table
    let user_id = client
        .post_user(&data_pk, &keyword_pk, &data_ct, &keyword_ct)
        .await?;
    let user_info = SelfUserInfo {
        data_sk,
        keyword_sk,
        id: user_id,
    };
    let path_id = get_path_id_of_filepath(&client, &user_info, filepath)
        .await?
        .expect("The initial path id does not exist.");
    // 2. Shared key table
    client
        .post_shared_key(&user_info.data_sk, path_id, user_info.id, &shared_key_ct)
        .await?;
    // 3. Authorization code table
    let authorization_seed = gen_authorization_seed();
    let authorization_seed_ct = encrypt_authorization_seed(&data_pk, authorization_seed)?;
    client
        .post_authorization_seed(
            &user_info.data_sk,
            path_id,
            user_info.id,
            &authorization_seed_ct,
        )
        .await?;
    // 4. Contents table
    let new_contents_data = ContentsData {
        is_file: false,
        num_readable_users: 1,
        num_writeable_users: 1,
        readable_user_path_ids: vec![path_id],
        writeable_user_path_ids: vec![path_id],
        file_bytes: Vec::new(),
    };
    let contents_ct =
        encrypt_new_file_with_shared_key(&recovered_shared_key, &new_contents_data.to_bytes())?;
    client
        .post_contents(
            authorization_seed,
            &recovered_shared_key.shared_key_hash,
            &contents_ct,
        )
        .await?;
    // 5. Write permission table
    client
        .post_write_permission(&user_info.data_sk, user_info.id, path_id, user_info.id)
        .await?;

    Ok(user_info)
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

    /*#[tokio::test]
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
        let user_info = register_user(&client, "/a").await?;
        println!("user_info {:?}", user_info);
        assert_eq!(user_info.id, user_id);
        mock.assert();
        Ok(())
    }*/

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
