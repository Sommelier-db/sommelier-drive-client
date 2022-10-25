use std::collections::HashMap;

use crate::http_client::HttpClient;
use crate::types::*;
use crate::user::SelfUserInfo;
use anyhow::Result;
use sommelier_drive_cryptos::*;

pub(crate) async fn get_path_id_of_filepath(
    client: &HttpClient,
    user_info: &SelfUserInfo,
    filepath: &str,
) -> Result<Option<DBInt>> {
    let (_, parent_filepath) = split_filepath(filepath);
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

    /*
    let mut rng = rand_core::OsRng;
    let td = gen_trapdoor_for_prefix_search_exact::<_, Fr, _>(
        &user_info.keyword_sk,
        &client.region_name,
        &filepath,
        &mut rng,
    )?;
    let records = client.search_file_pathes(user_info.id, &td).await?;
    let path_id = records[0].path_id;
    */
    let shared_key_record = client.get_shared_key(path_id).await?;
    let shared_key_ct = hex::decode(&shared_key_record.shared_key_ct)?;
    let recovered_shared_key = recover_shared_key(&user_info.data_sk, &shared_key_ct)?;
    Ok(recovered_shared_key)
}

pub(crate) async fn recover_authorization_seed_of_filepath(
    client: &HttpClient,
    user_info: &SelfUserInfo,
    filepath: &str,
) -> Result<AuthorizationSeed> {
    let path_id = get_path_id_of_filepath(client, user_info, filepath)
        .await?
        .ok_or(anyhow::anyhow!(format!(
            "No file exists for the filepath {}",
            filepath
        )))?;
    let authorization_record = client.get_authorization_key(path_id).await?;
    let authorization_seed_ct =
        AuthorizationSeedCT::from_str(&authorization_record.authorization_seed_ct)?;
    let authorization_seed =
        decrypt_authorization_seed_ct(&user_info.data_sk, &authorization_seed_ct)?;
    Ok(authorization_seed)
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

pub(crate) fn split_filepath(filepath: &str) -> (String, String) {
    let path_split: Vec<&str> = filepath.split('/').collect();
    let filename = path_split[path_split.len() - 1];
    let dir_name = path_split[0..(path_split.len() - 2)].concat();
    (filename.to_string(), dir_name)
}
