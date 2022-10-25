use std::collections::{HashMap, HashSet};

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
async fn touch_flow_test() -> Result<()> {
    let region_name = "touch_flow_test";
    let client = HttpClient::new(BASE_URL, region_name);
    let init_filepath = "/user1";
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

#[tokio::test]
async fn mkdir_flow_test() -> Result<()> {
    let region_name = "mkdir_flow_test";
    let client = HttpClient::new(BASE_URL, region_name);
    let init_filepath = "/user1";
    let user_info = register_user(&client, init_filepath).await?;

    let cur_dir = init_filepath;
    let dir_name = "tests";
    let filepath = cur_dir.to_string() + "/" + dir_name;
    let is_exist_pre = is_exist_filepath(&client, &user_info, &filepath).await?;
    assert!(!is_exist_pre);
    add_directory(&client, &user_info, &filepath).await?;
    let contents_data = open_filepath(&client, &user_info, &filepath).await?;
    assert!(!contents_data.is_file);
    assert_eq!(contents_data.num_readable_users, 1);
    assert_eq!(contents_data.num_writeable_users, 1);
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

#[tokio::test]
async fn ls_flow_test() -> Result<()> {
    let region_name = "ls_flow_test";
    let client = HttpClient::new(BASE_URL, region_name);
    let init_filepath = "/user1";
    let user_info = register_user(&client, init_filepath).await?;

    let cur_dir = init_filepath;
    let dir_names = vec!["hoge", "fuga", "foo", "bar"];
    let filepathes = dir_names
        .iter()
        .map(|dir_name| cur_dir.to_string() + "/" + *dir_name)
        .collect::<Vec<String>>();
    for filepath in filepathes.iter() {
        add_directory(&client, &user_info, &filepath).await?;
    }
    let children = get_children_pathes(&client, &user_info, &cur_dir).await?;
    assert_eq!(filepathes, children);
    Ok(())
}
/*
#[tokio::test]
async fn find_flow_test() -> Result<()> {
    let region_name = "find_flow_test";
    let client = HttpClient::new(BASE_URL, region_name);
    let init_filepath = "/user1";
    let user_info = register_user(&client, init_filepath).await?;

    let mut expected_descendants = HashSet::new();
    let dir_filepathes = vec!["/user1/hoge", "/user1/hoge/hogehoge"];
    for filepath in dir_filepathes.into_iter() {
        expected_descendants.insert(filepath);
        add_directory(&client, &user_info, filepath).await?;
    }

    let mut text_of_filepath = HashMap::new();
    for (filepath, text) in [
        ("/user1/root.txt", b"Hello from root !".to_vec()),
        ("/user1/hoge/hoge.txt", b"Hello from hoge!".to_vec()),
        (
            "/user1/hoge/hogehoge/hoge2.pdf",
            b"Hello from hogehoge?".to_vec(),
        ),
    ] {
        expected_descendants.insert(filepath);
        text_of_filepath.insert(filepath, text.clone());
        add_file(&client, &user_info, filepath, text).await?;
    }

    let descendants = search_descendant_pathes(&client, &user_info, init_filepath).await?;
    for exp in expected_descendants.iter() {
        assert!(descendants.contains(&exp.to_string()));
    }
    Ok(())
}*/
