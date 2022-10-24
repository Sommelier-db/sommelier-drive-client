use std::collections::HashMap;

use crate::types::*;
use crate::user::SelfUserInfo;
use crate::{get_user_public_keys, http_client::HttpClient};
use anyhow::Result;
use paired::bls12_381::Fr;
use rust_searchable_pke::expressions::gen_ciphertext_for_prefix_search;
use rust_searchable_pke::expressions::gen_trapdoor_for_prefix_search;
use sommelier_drive_cryptos::*;

pub async fn get_filepath_with_id(
    client: &HttpClient,
    user_info: &SelfUserInfo,
    path_id: DBInt,
) -> Result<String> {
    let record = client.get_file_path(path_id).await?;
    Ok(decrypt_filepath_ct_str(
        &record.data_ct,
        &user_info.data_sk,
    )?)
}

pub async fn get_children_pathes(
    client: &HttpClient,
    user_info: &SelfUserInfo,
    cur_path: &str,
) -> Result<Vec<String>> {
    let permission_hash = compute_permission_hash(user_info.id, cur_path);
    let records = client.get_children_file_pathes(&permission_hash).await?;
    let pathfile_names = records
        .into_iter()
        .map(|record| decrypt_filepath_ct_str(&record.data_ct, &user_info.data_sk))
        .collect::<Result<Vec<String>>>()?;
    Ok(pathfile_names)
}

pub async fn search_descendant_pathes(
    client: &HttpClient,
    user_info: &SelfUserInfo,
    cur_path: &str,
) -> Result<Vec<String>> {
    let mut rng = rand_core::OsRng;
    let td = gen_trapdoor_for_prefix_search::<_, Fr, _>(
        &user_info.keyword_sk,
        &client.region_name,
        cur_path,
        &mut rng,
    )?;
    let records = client.search_file_pathes(user_info.id, &td).await?;
    let pathfile_names = records
        .into_iter()
        .map(|record| decrypt_filepath_ct_str(&record.data_ct, &user_info.data_sk))
        .collect::<Result<Vec<String>>>()?;
    Ok(pathfile_names)
}

pub async fn open_filepath(
    client: &HttpClient,
    user_info: &SelfUserInfo,
    filepath: &str,
) -> Result<ContentsData> {
    let recovered_shared_key = recover_shared_key_of_filepath(client, user_info, filepath).await?;
    let contents_record = client
        .get_contents(&recovered_shared_key.shared_key_hash)
        .await?;
    let contents_data = decrypt_contents_ct_str(
        &contents_record.contents_ct,
        &recovered_shared_key.shared_key,
    )?;
    Ok(contents_data)
}

pub async fn add_file(
    client: &HttpClient,
    user_info: &SelfUserInfo,
    cur_dir: &str,
    filename: &str,
    file_bytes: Vec<u8>,
) -> Result<()> {
    add_contents_generic(client, user_info, cur_dir, filename, true, file_bytes).await
}

pub async fn add_directory(
    client: &HttpClient,
    user_info: &SelfUserInfo,
    cur_dir: &str,
    filename: &str,
) -> Result<()> {
    add_contents_generic(client, user_info, cur_dir, filename, false, Vec::new()).await
}

async fn add_contents_generic(
    client: &HttpClient,
    user_info: &SelfUserInfo,
    cur_dir: &str,
    filename: &str,
    is_file: bool,
    file_bytes: Vec<u8>,
) -> Result<()> {
    let cur_dir_contents = open_filepath(client, user_info, cur_dir).await?;
    let readable_user_ids = cur_dir_contents.readable_user_ids;
    let writeable_user_ids = cur_dir_contents.writeable_user_ids;
    let num_readable_users = readable_user_ids.len();
    let num_writeable_users = writeable_user_ids.len();
    let filepath = cur_dir.to_string() + "/" + filename;
    let new_contents_data = ContentsData {
        is_file,
        num_readable_users,
        num_writeable_users,
        readable_user_ids,
        writeable_user_ids,
        file_bytes,
    };
    let mut data_pks = Vec::with_capacity(num_readable_users);
    let mut keyword_pks = Vec::with_capacity(num_readable_users);
    for i in 0..num_readable_users {
        let (data_pk, keyword_pk) =
            get_user_public_keys(client, new_contents_data.readable_user_ids[i]).await?;
        data_pks.push(data_pk);
        keyword_pks.push(keyword_pk);
    }
    let contents_bytes = new_contents_data.to_bytes();
    let file_ct = encrypt_new_file(&data_pks, &filepath, &contents_bytes)?;
    let mut rng = rand_core::OsRng;
    let data_sk = &user_info.data_sk;
    let write_user_id = user_info.id;

    // 1. Path table
    let mut path_id_of_user_id = HashMap::new();
    for i in 0..num_readable_users {
        let keyword_ct = gen_ciphertext_for_prefix_search::<_, Fr, _>(
            &keyword_pks[i],
            &client.region_name,
            &filepath,
            &mut rng,
        )?;
        let read_user_id = new_contents_data.readable_user_ids[i];
        let permission_hash = compute_permission_hash(read_user_id, cur_dir);
        let path_id = client
            .post_file_path(
                data_sk,
                write_user_id,
                read_user_id,
                &permission_hash,
                &file_ct.filepath_cts[i],
                &keyword_ct,
            )
            .await?;
        path_id_of_user_id.insert(read_user_id, path_id);
    }

    // 2. Shared key table
    for i in 0..num_readable_users {
        let read_user_id = new_contents_data.readable_user_ids[i];
        let shared_key_ct = &file_ct.shared_key_cts[i];
        client
            .post_shared_key(
                data_sk,
                path_id_of_user_id[&read_user_id],
                write_user_id,
                shared_key_ct,
            )
            .await?;
    }

    // 3. Contents table
    client
        .post_contents(
            data_sk,
            write_user_id,
            &file_ct.shared_key_hash,
            &file_ct.contents_ct,
        )
        .await?;

    /*
    // 4. Write permission table
    for i in 0..num_writeable_users {
        let permitted_user_id = new_contents_data.writeable_user_ids[i];
        let path_id = path_id_of_user_id[&permitted_user_id];
        client
            .post_write_permission(data_sk, write_user_id, path_id, permitted_user_id)
            .await?;
    }
    */
    Ok(())
}

pub async fn add_read_permission(
    client: &HttpClient,
    user_info: &SelfUserInfo,
    filepath: &str,
    new_user_id: DBInt,
) -> Result<()> {
    let (new_data_pk, new_keyword_pk) = get_user_public_keys(client, new_user_id).await?;
    let recovered_shared_key = recover_shared_key_of_filepath(client, user_info, filepath).await?;
    let permission_ct = add_permission(&new_data_pk, &recovered_shared_key, filepath)?;

    // 1. Path table
    let (_, parent_path) = split_filepath(filepath);
    let permission_hash = compute_permission_hash(new_user_id, &parent_path);
    let keyword_ct = gen_ciphertext_for_prefix_search::<_, Fr, _>(
        &new_keyword_pk,
        &client.region_name,
        filepath,
        &mut rand_core::OsRng,
    )?;

    let new_path_id = client
        .post_file_path(
            &user_info.data_sk,
            user_info.id,
            new_user_id,
            &permission_hash,
            &permission_ct.filepath_ct,
            &keyword_ct,
        )
        .await?;

    // 2. Shared key table
    client
        .post_shared_key(
            &user_info.data_sk,
            new_path_id,
            new_user_id,
            &permission_ct.shared_key_ct,
        )
        .await?;

    // 3. Contents table
    let pre_contents_record = client
        .get_contents(&recovered_shared_key.shared_key_hash)
        .await?;
    let mut new_contents = decrypt_contents_ct_str(
        &pre_contents_record.contents_ct.to_string(),
        &recovered_shared_key.shared_key,
    )?;
    new_contents.num_readable_users += 1;
    new_contents.readable_user_ids.push(new_user_id);
    let new_contents_ct =
        encrypt_new_file_with_shared_key(&recovered_shared_key, &new_contents.to_bytes())?;
    client
        .put_contents(
            &user_info.data_sk,
            user_info.id,
            &recovered_shared_key.shared_key_hash,
            &new_contents_ct,
        )
        .await?;
    Ok(())
}

pub async fn add_write_permission(
    client: &HttpClient,
    user_info: &SelfUserInfo,
    filepath: &str,
    new_user_id: DBInt,
) -> Result<()> {
    let recovered_shared_key = recover_shared_key_of_filepath(client, user_info, filepath).await?;

    // 1. Contents table
    let pre_contents_record = client
        .get_contents(&recovered_shared_key.shared_key_hash)
        .await?;
    let mut new_contents = decrypt_contents_ct_str(
        &pre_contents_record.contents_ct.to_string(),
        &recovered_shared_key.shared_key,
    )?;
    new_contents.num_writeable_users += 1;
    new_contents.writeable_user_ids.push(new_user_id);
    let new_contents_ct =
        encrypt_new_file_with_shared_key(&recovered_shared_key, &new_contents.to_bytes())?;
    client
        .put_contents(
            &user_info.data_sk,
            user_info.id,
            &recovered_shared_key.shared_key_hash,
            &new_contents_ct,
        )
        .await?;
    Ok(())
}

pub async fn modify_file(
    client: &HttpClient,
    user_info: &SelfUserInfo,
    filepath: &str,
    new_file_bytes: Vec<u8>,
) -> Result<()> {
    let recovered_shared_key = recover_shared_key_of_filepath(client, user_info, filepath).await?;
    let pre_contents_record = client
        .get_contents(&recovered_shared_key.shared_key_hash)
        .await?;
    let mut new_contents = decrypt_contents_ct_str(
        &pre_contents_record.contents_ct.to_string(),
        &recovered_shared_key.shared_key,
    )?;
    new_contents.is_file = true;
    new_contents.file_bytes = new_file_bytes;
    let new_contents_ct =
        encrypt_new_file_with_shared_key(&recovered_shared_key, &new_contents.to_bytes())?;
    client
        .put_contents(
            &user_info.data_sk,
            user_info.id,
            &recovered_shared_key.shared_key_hash,
            &new_contents_ct,
        )
        .await?;
    Ok(())
}

async fn get_path_id_of_filepath(
    client: &HttpClient,
    user_info: &SelfUserInfo,
    filepath: &str,
) -> Result<DBInt> {
    let (_, parent_filepath) = split_filepath(filepath);
    let permission_hash = compute_permission_hash(user_info.id, &parent_filepath);
    let records = client.get_children_file_pathes(&permission_hash).await?;
    let path_id: DBInt = records
        .into_iter()
        .filter(
            |record| match decrypt_filepath_ct_str(&record.data_ct, &user_info.data_sk) {
                Ok(str) => str == filepath,
                Err(_) => false,
            },
        )
        .map(|record| record.path_id)
        .last()
        .ok_or(anyhow::anyhow!(format!(
            "No file exists for the filepath {}",
            filepath
        )))?;
    Ok(path_id)
}

async fn recover_shared_key_of_filepath(
    client: &HttpClient,
    user_info: &SelfUserInfo,
    filepath: &str,
) -> Result<RecoveredSharedKey> {
    let path_id = get_path_id_of_filepath(client, user_info, filepath).await?;

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

fn decrypt_filepath_ct_str(ct_str: &str, data_sk: &PkeSecretKey) -> Result<String> {
    let filepath_ct = FilePathCT::from_str(&ct_str)?;
    let filepath = decrypt_filepath_ct(data_sk, &filepath_ct)?;
    Ok(filepath)
}

fn decrypt_contents_ct_str(ct_str: &str, shared_key: &SymmetricKey) -> Result<ContentsData> {
    let ct = hex::decode(ct_str)?;
    let contents_bytes = ske_decrypt(shared_key, &ct)?;
    let contents_data = ContentsData::from_bytes(&contents_bytes);
    Ok(contents_data)
}

fn split_filepath(filepath: &str) -> (String, String) {
    let path_split: Vec<&str> = filepath.split('/').collect();
    let filename = path_split[path_split.len() - 1];
    let dir_name = path_split[0..(path_split.len() - 2)].concat();
    (filename.to_string(), dir_name)
}
