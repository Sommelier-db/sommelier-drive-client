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
    let record = client.get_filepath(path_id).await?;
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

pub async fn is_exist_filepath(
    client: &HttpClient,
    user_info: &SelfUserInfo,
    filepath: &str,
) -> Result<bool> {
    let path_id = get_path_id_of_filepath(client, user_info, filepath).await?;
    match path_id {
        Some(_) => Ok(true),
        None => Ok(false),
    }
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
    filepath: &str,
    file_bytes: Vec<u8>,
) -> Result<()> {
    add_contents_generic(client, user_info, filepath, true, file_bytes).await
}

pub async fn add_directory(
    client: &HttpClient,
    user_info: &SelfUserInfo,
    filepath: &str,
) -> Result<()> {
    add_contents_generic(client, user_info, filepath, false, Vec::new()).await
}

async fn add_contents_generic(
    client: &HttpClient,
    user_info: &SelfUserInfo,
    filepath: &str,
    is_file: bool,
    file_bytes: Vec<u8>,
) -> Result<()> {
    let (filename, cur_dir) = split_filepath(filepath);
    let cur_dir_contents = open_filepath(client, user_info, cur_dir.as_str()).await?;
    let readable_user_path_ids = cur_dir_contents.readable_user_path_ids;
    let writeable_user_path_ids = cur_dir_contents.writeable_user_path_ids;
    let num_readable_users = readable_user_path_ids.len();
    let num_writeable_users = writeable_user_path_ids.len();
    let filepath = cur_dir.to_string() + "/" + filename.as_str();
    let new_contents_data = ContentsData {
        is_file,
        num_readable_users,
        num_writeable_users,
        readable_user_path_ids,
        writeable_user_path_ids,
        file_bytes,
    };
    let mut readbale_user_ids = Vec::with_capacity(num_readable_users);
    let mut data_pks = Vec::with_capacity(num_readable_users);
    let mut keyword_pks = Vec::with_capacity(num_readable_users);

    for i in 0..num_readable_users {
        let path_record = client
            .get_filepath(new_contents_data.readable_user_path_ids[i])
            .await?;
        readbale_user_ids.push(path_record.user_id);
        let (data_pk, keyword_pk) = get_user_public_keys(client, path_record.user_id).await?;
        data_pks.push(data_pk);
        keyword_pks.push(keyword_pk);
    }
    let contents_bytes = new_contents_data.to_bytes();
    let file_ct = encrypt_new_file(&data_pks, &filepath, &contents_bytes)?;
    let mut rng = rand_core::OsRng;
    let data_sk = &user_info.data_sk;
    let write_user_id = user_info.id;

    // 1. Path table
    let mut new_path_id_of_user_id = HashMap::new();
    for i in 0..num_readable_users {
        let keyword_ct = gen_ciphertext_for_prefix_search::<_, Fr, _>(
            &keyword_pks[i],
            &client.region_name,
            &filepath,
            &mut rng,
        )?;
        let read_user_id = readbale_user_ids[i];
        let permission_hash = compute_permission_hash(read_user_id, cur_dir.as_str());
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
        new_path_id_of_user_id.insert(read_user_id, path_id);
    }

    // 2. Shared key table
    for i in 0..num_readable_users {
        let read_user_id = readbale_user_ids[i];
        let shared_key_ct = &file_ct.shared_key_cts[i];
        client
            .post_shared_key(
                data_sk,
                new_path_id_of_user_id[&read_user_id],
                write_user_id,
                shared_key_ct,
            )
            .await?;
    }

    // 3. Authorization seed table
    let authorization_seed = gen_authorization_seed();
    let mut writeable_user_ids = Vec::with_capacity(num_writeable_users);
    for i in 0..num_writeable_users {
        let path_record = client
            .get_filepath(new_contents_data.writeable_user_path_ids[i])
            .await?;
        writeable_user_ids.push(path_record.user_id);
        let (pk, _) = get_user_public_keys(client, path_record.user_id).await?;
        let authorization_seed_ct = encrypt_authorization_seed(&pk, authorization_seed)?;
        client
            .post_authorization_seed(
                data_sk,
                path_record.path_id,
                path_record.user_id,
                &authorization_seed_ct,
            )
            .await?;
    }

    // 4. Contents table
    client
        .post_contents(
            authorization_seed,
            &file_ct.shared_key_hash,
            &file_ct.contents_ct,
        )
        .await?;

    // 5. Write permission table
    for i in 0..num_writeable_users {
        let path_id = new_contents_data.writeable_user_path_ids[i];
        let user_id = writeable_user_ids[i];
        client
            .post_write_permission(data_sk, write_user_id, path_id, user_id)
            .await?;
    }
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
    let permission_ct = gen_read_permission_ct(&new_data_pk, &recovered_shared_key, filepath)?;

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
    new_contents.readable_user_path_ids.push(new_path_id);
    let new_contents_ct =
        encrypt_new_file_with_shared_key(&recovered_shared_key, &new_contents.to_bytes())?;
    let authorization_seed =
        recover_authorization_seed_of_filepath(client, user_info, filepath).await?;
    client
        .put_contents(
            authorization_seed,
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
    let authorization_seed =
        recover_authorization_seed_of_filepath(client, user_info, filepath).await?;
    let pre_contents_record = client
        .get_contents(&recovered_shared_key.shared_key_hash)
        .await?;
    let mut new_contents = decrypt_contents_ct_str(
        &pre_contents_record.contents_ct.to_string(),
        &recovered_shared_key.shared_key,
    )?;
    let mut new_user_path_id = None;
    for path_id in new_contents.readable_user_path_ids.iter() {
        let path_record = client.get_filepath(*path_id).await?;
        if path_record.user_id == new_user_id {
            new_user_path_id = Some(path_id);
        }
    }
    let new_user_path_id = *new_user_path_id.ok_or(anyhow::anyhow!(
        "For the write permission, the user first needs to have the read permission."
    ))?;

    // 1. Authorization Seed Table
    let (pk, _) = get_user_public_keys(client, new_user_id).await?;
    let authorization_seed_ct = encrypt_authorization_seed(&pk, authorization_seed)?;
    client
        .post_authorization_seed(
            &user_info.data_sk,
            new_user_path_id,
            new_user_id,
            &authorization_seed_ct,
        )
        .await?;

    // 2. Contents table
    new_contents.num_writeable_users += 1;
    new_contents.writeable_user_path_ids.push(new_user_path_id);
    let new_contents_ct =
        encrypt_new_file_with_shared_key(&recovered_shared_key, &new_contents.to_bytes())?;
    client
        .put_contents(
            authorization_seed,
            &recovered_shared_key.shared_key_hash,
            &new_contents_ct,
        )
        .await?;

    // 3. Write permission table
    client
        .post_write_permission(
            &user_info.data_sk,
            user_info.id,
            new_user_path_id,
            new_user_id,
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
    let authorization_seed =
        recover_authorization_seed_of_filepath(client, user_info, filepath).await?;
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
            authorization_seed,
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

async fn recover_shared_key_of_filepath(
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

async fn recover_authorization_seed_of_filepath(
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

#[cfg(test)]
pub fn gen_test_path_table_record(
    region_name: &str,
    data_pk: &PkePublicKey,
    keyword_pk: &KeywordPK,
    user_id: DBInt,
    path_id: DBInt,
    parent_filepath: &str,
    filename: &str,
) -> Result<PathTableRecord> {
    let permission_hash = compute_permission_hash(user_id, parent_filepath);
    let filepath = parent_filepath.to_string() + "/" + filename;
    let data_ct = encrypt_filepath(&data_pk, &filepath)?;
    let keyword_ct = gen_ciphertext_for_prefix_search::<_, Fr, _>(
        &keyword_pk,
        region_name,
        &filepath,
        &mut rand_core::OsRng,
    )?;
    let test_path_record = PathTableRecord {
        path_id,
        user_id,
        permission_hash: permission_hash.to_string(),
        data_ct: data_ct.to_string(),
        keyword_ct: serde_json::to_string(&keyword_ct)?,
    };
    Ok(test_path_record)
}

#[cfg(test)]
mod test {
    use super::*;
    use aes_gcm::aead;
    use anyhow::Result;
    use httpmock::prelude::*;
    use sommelier_drive_cryptos::{
        pke_gen_public_key, pke_gen_secret_key, PemString, PkePublicKey, PkeSecretKey,
    };
    use tokio;

    #[tokio::test]
    async fn get_filepath_with_id_test() -> Result<()> {
        let server = MockServer::start_async().await;
        let region_name = "get_filepath_with_id";
        let client = HttpClient::new(server.base_url().as_str(), region_name);
        let user_id = 1;
        let user_info = gen_user_info(user_id)?;

        let path_id = 2;
        let filepath = "/root/test/test.txt";
        let (_, parent_filepath) = split_filepath(filepath);
        let permission_hash = compute_permission_hash(user_id, &parent_filepath);
        let data_pk = pke_gen_public_key(&user_info.data_sk);
        let data_ct = encrypt_filepath(&data_pk, filepath)?;
        let keyword_pk = user_info.keyword_sk.into_public_key();
        let keyword_ct = gen_ciphertext_for_prefix_search::<_, Fr, _>(
            &keyword_pk,
            region_name,
            filepath,
            &mut rand_core::OsRng,
        )?;

        let mock = server.mock(|when, then| {
            when.method(GET)
                .path_matches(Regex::new("/file-path").unwrap())
                .header("content-type", "application/json");
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&PathTableRecord {
                    path_id,
                    user_id,
                    permission_hash: permission_hash.to_string(),
                    data_ct: data_ct.to_string(),
                    keyword_ct: serde_json::to_string(&keyword_ct).unwrap(),
                });
        });

        let get_filepath = get_filepath_with_id(&client, &user_info, path_id).await?;
        assert_eq!(filepath, get_filepath);
        mock.assert();
        Ok(())
    }

    #[tokio::test]
    async fn get_children_pathes_test() -> Result<()> {
        let server = MockServer::start_async().await;
        let region_name = "get_children_pathes_test";
        let client = HttpClient::new(server.base_url().as_str(), region_name);
        let user_id = 1;
        let user_info = gen_user_info(user_id)?;
        let path_id = 2;
        let parent_filepath = "/root/test";
        let filename = "test.txt";
        let data_pk = pke_gen_public_key(&user_info.data_sk);
        let keyword_pk = user_info.keyword_sk.into_public_key();
        let test_path_record = gen_test_path_table_record(
            region_name,
            &data_pk,
            &keyword_pk,
            user_id,
            path_id,
            parent_filepath,
            filename,
        )?;

        let mock = server.mock(|when, then| {
            when.method(GET)
                .path_matches(Regex::new("/file-path/children").unwrap())
                .header("content-type", "application/json");
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&[test_path_record]);
        });
        let get_filepathes = get_children_pathes(&client, &user_info, parent_filepath).await?;
        assert_eq!(
            get_filepathes,
            vec![parent_filepath.to_string() + "/" + filename]
        );
        mock.assert();

        Ok(())
    }

    #[tokio::test]
    async fn search_descendant_pathes_test() -> Result<()> {
        let server = MockServer::start_async().await;
        let region_name = "get_children_pathes_test";
        let client = HttpClient::new(server.base_url().as_str(), region_name);
        let user_id = 0;
        let user_info = gen_user_info(user_id)?;
        let data_pk = pke_gen_public_key(&user_info.data_sk);
        let keyword_pk = user_info.keyword_sk.into_public_key();

        let num_pathes = 5;
        let parent_filepathes = vec!["/dir1", "/dir1", "/dir1", "/dir1/dir2", "/dir1/dir2/dir3"];
        let filenames = vec!["test1.txt", "test2.txt", "dir2", "dir3", "test2.pdf"];
        let test_path_records: Vec<PathTableRecord> = (0..num_pathes)
            .into_iter()
            .map(|i| {
                gen_test_path_table_record(
                    region_name,
                    &data_pk,
                    &keyword_pk,
                    i as u64 + 1,
                    i as u64 + 1,
                    parent_filepathes[i],
                    filenames[i],
                )
            })
            .collect::<Result<_, _>>()?;
        let mock = server.mock(|when, then| {
            when.method(GET)
                .path_matches(Regex::new("/file-path/search").unwrap())
                .header("content-type", "application/json");
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&test_path_records);
        });
        let get_filepathes = search_descendant_pathes(&client, &user_info, "/dir1").await?;
        for i in 0..num_pathes {
            assert_eq!(
                get_filepathes[i],
                parent_filepathes[i].to_string() + "/" + filenames[i]
            );
        }

        mock.assert();

        Ok(())
    }

    fn gen_user_info(user_id: DBInt) -> Result<SelfUserInfo> {
        let mut rng1 = aead::OsRng;
        let data_sk = pke_gen_secret_key(&mut rng1)?;
        let mut rng2 = rand_core::OsRng;
        let keyword_sk = KeywordSK::gen(&mut rng2, MAX_NUM_KEYWORD);
        Ok(SelfUserInfo {
            id: user_id,
            data_sk,
            keyword_sk,
        })
    }
}
