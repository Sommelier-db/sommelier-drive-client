use rust_searchable_pke::pecdk::*;
use sommelier_drive_client::*;
mod utils;
use aes_gcm::aead;
use anyhow::Result;
use sommelier_drive_client::*;
use sommelier_drive_cryptos::{pke_gen_public_key, pke_gen_secret_key, PemString};
use tokio;
use utils::BASE_URL;

#[tokio::test]
async fn add_file_flow_test() -> Result<()> {
    let region_name = "add_file_flow_test";
    let client = HttpClient::new(BASE_URL, region_name);
    let init_filepath = "/user2";
    let user_info = register_user(&client, init_filepath).await?;

    let test_text = b"Hello, Sommelier!";
    let cur_dir = init_filepath;
    let filename = "test.txt";
    let filepath = cur_dir.to_string() + "/" + filename;
    let is_exist_pre = is_exist_filepath(&client, &user_info, &filepath).await?;
    assert!(!is_exist_pre);
    add_file(&client, &user_info, &filepath, test_text.to_vec()).await?;
    let contents_data = open_filepath(&client, &user_info, &filepath).await?;
    assert!(contents_data.is_file);
    assert_eq!(contents_data.num_readable_users, 1);
    assert_eq!(contents_data.num_writeable_users, 1);
    assert_eq!(contents_data.file_bytes, test_text);
    assert_eq!(
        contents_data.readable_user_path_ids[0],
        contents_data.writeable_user_path_ids[0]
    );

    let got_path =
        get_filepath_with_id(&client, &user_info, contents_data.readable_user_path_ids[0]).await?;
    assert_eq!(got_path, filepath);

    let is_exist_after = is_exist_filepath(&client, &user_info, &filepath).await?;
    assert!(is_exist_after);
    Ok(())
}
