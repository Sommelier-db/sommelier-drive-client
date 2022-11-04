use std::collections::HashMap;

use crate::http_client::HttpClient;
use crate::types::*;
use crate::user::SelfUserInfo;
use anyhow::Result;
use sommelier_drive_cryptos::*;
use std::path::{Path, PathBuf};

pub(crate) async fn get_path_id_of_filepath(
    client: &HttpClient,
    user_info: &SelfUserInfo,
    filepath: &str,
) -> Result<Option<DBInt>> {
    let (_, parent_filepath) = split_filepath(filepath)?;
    let permission_hash = compute_permission_hash(user_info.id, &parent_filepath);
    let records = client.get_children_file_pathes(&permission_hash).await?;
    let path_id = records
        .into_iter()
        .filter(
            |record| match decrypt_filepath_ct_str(&record.data_ct, &user_info.data_sk) {
                Ok(str) => str == filepath,
                Err(_) => false,
            },
        )
        .map(|record| record.path_id)
        .last();
    Ok(path_id)
}

pub(crate) async fn recover_shared_key_of_filepath(
    client: &HttpClient,
    user_info: &SelfUserInfo,
    filepath: &str,
) -> Result<RecoveredSharedKey> {
    let path_id = get_path_id_of_filepath(client, user_info, filepath)
        .await?
        .ok_or(anyhow::anyhow!(format!(
            "No file exists for the filepath {}",
            filepath
        )))?;

    let shared_key_record = client.get_shared_key(path_id).await?;
    let shared_key_ct = hex::decode(&shared_key_record.shared_key_ct)?;
    let recovered_shared_key = recover_shared_key(&user_info.data_sk, &shared_key_ct)?;
    Ok(recovered_shared_key)
}

pub(crate) fn decrypt_filepath_ct_str(ct_str: &str, data_sk: &PkeSecretKey) -> Result<String> {
    let filepath_ct = FilePathCT::from_str(&ct_str)?;
    let filepath = decrypt_filepath_ct(data_sk, &filepath_ct)?;
    Ok(filepath)
}

pub(crate) fn decrypt_contents_ct_str(
    ct_str: &str,
    shared_key: &SymmetricKey,
) -> Result<ContentsData> {
    let ct = hex::decode(ct_str)?;
    let contents_bytes = ske_decrypt(shared_key, &ct)?;
    let contents_data = ContentsData::from_bytes(&contents_bytes);
    Ok(contents_data)
}

pub(crate) fn split_filepath(filepath: &str) -> Result<(String, String)> {
    let path = Path::new(filepath);
    let file = path.file_name().ok_or(anyhow::anyhow!(format!(
        "The file name does not exist in {}",
        filepath
    )))?;
    let parent = path.parent().ok_or(anyhow::anyhow!(format!(
        "The parent name does not exist in {}",
        filepath
    )))?;
    let file = file.to_str().ok_or(anyhow::anyhow!(format!(
        "Fail to parse the file name {:?} to str.",
        file
    )))?;
    let parent = parent.to_str().ok_or(anyhow::anyhow!(format!(
        "Fail to parse the parent name {:?} to str.",
        file
    )))?;
    Ok((file.to_string(), parent.to_string()))
}
