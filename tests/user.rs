use sommelier_drive_client::*;
mod utils;
use anyhow::Result;
use sommelier_drive_cryptos::{pke_gen_public_key, pke_gen_secret_key, PemString};
use tokio;
use utils::BASE_URL;

#[tokio::test]
async fn user_flow_test() -> Result<()> {
    let region_name = "register_user_test";
    let client = HttpClient::new(BASE_URL, region_name);
    let user_info = register_user(&client).await?;

    let (data_pk, keyword_pk) = get_user_public_keys(&client, user_info.id).await?;
    let data_pk_expected = pke_gen_public_key(&user_info.data_sk);
    let keyword_pk_expected = user_info.keyword_sk.into_public_key();
    assert_eq!(data_pk.to_string()?, data_pk_expected.to_string()?);
    assert_eq!(
        serde_json::to_string(&keyword_pk).unwrap(),
        serde_json::to_string(&keyword_pk_expected).unwrap()
    );
    Ok(())
}
