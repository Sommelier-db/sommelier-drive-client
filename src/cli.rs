use anyhow::Result;
use once_cell::sync::Lazy;
use promkit::{build::Builder, readline};
use sommelier_drive_client::*;
use std::cell::RefCell;
use std::io;
use tokio::runtime::Runtime;

fn main() -> Result<()> {
    #[cfg(not(feature = "cli"))]
    panic!("To run the cli, you need to compile this crate with `cli` feature.");
    #[cfg(feature = "cli")]
    let region_name = "sommelier_drive_cli";
    let rt = Runtime::new()?;
    let fut_result = async {
        cli(region_name).await.unwrap();
    };
    rt.block_on(fut_result);
    Ok(())
}

async fn cli(region_name: &'static str) -> Result<()> {
    let mut p = readline::Builder::default().build()?;
    let base_url = p.run()?;
    thread_local! {
        pub static GLOBAL_USER_INFO: RefCell<Option<SelfUserInfo>> = RefCell::new(None)
    };
    let client = HttpClient::new(&base_url, region_name);
    loop {
        let line = p.run()?;
        let mut spw = line.split_whitespace();
        let command = spw.next().expect("Command not found.");
        match command {
            "register" => {
                let filepath = spw.next().expect("Initial directory path not found.");
                let new_info = register_user(&client, filepath).await?;
                println!("You are registered with a user id {}", new_info.id);
                GLOBAL_USER_INFO.with(|info| {
                    let mut info_ref = info.borrow_mut();
                    *info_ref = Some(new_info);
                });
            }
            "touch" => {
                let filepath = spw.next().expect("File path not found.");
                let user_info = GLOBAL_USER_INFO
                    .with(|info| info.borrow().clone().expect("You have to login first."));
                add_file(&client, &user_info, filepath, Vec::new()).await?
            }
            "mkdir" => {
                let filepath = spw.next().expect("File path not found.");
                let user_info = GLOBAL_USER_INFO
                    .with(|info| info.borrow().clone().expect("You have to login first."));
                add_directory(&client, &user_info, filepath).await?
            }
            "cat" => {
                let filepath = spw.next().expect("File path not found.");
                let user_info = GLOBAL_USER_INFO
                    .with(|info| info.borrow().clone().expect("You have to login first."));
                let is_exist = is_exist_filepath(&client, &user_info, filepath).await?;
                if !is_exist {
                    panic!("The given filepath {} does not exist.", filepath);
                }
                let contents_data = open_filepath(&client, &user_info, filepath).await?;
                if !contents_data.is_file {
                    panic!(
                        "The file at filepath {} is not a file but a directory.",
                        filepath
                    );
                }
                println!("{}", String::from_utf8(contents_data.file_bytes)?);
            }
            "modify" => {
                let filepath = spw.next().expect("File path not found.");
                let text = spw.next().expect("Input text not found.");
                let user_info = GLOBAL_USER_INFO
                    .with(|info| info.borrow().clone().expect("You have to login first."));
                let is_exist = is_exist_filepath(&client, &user_info, filepath).await?;
                if !is_exist {
                    panic!("The given filepath {} does not exist.", filepath);
                }
                let contents_data = open_filepath(&client, &user_info, filepath).await?;
                if !contents_data.is_file {
                    panic!(
                        "The file at filepath {} is not a file but a directory.",
                        filepath
                    );
                }
                modify_file(&client, &user_info, filepath, text.as_bytes().to_vec()).await?;
            }
            "ls" => {
                let filepath = spw.next().expect("File path not found.");
                let user_info = GLOBAL_USER_INFO
                    .with(|info| info.borrow().clone().expect("You have to login first."));
                let is_exist = is_exist_filepath(&client, &user_info, filepath).await?;
                if !is_exist {
                    panic!("The given filepath {} does not exist.", filepath);
                }
                let children_pathes = get_children_pathes(&client, &user_info, filepath).await?;
                for path in children_pathes {
                    println!("{}", path);
                }
            }
            "find" => {
                let filepath = spw.next().expect("File path not found.");
                let user_info = GLOBAL_USER_INFO
                    .with(|info| info.borrow().clone().expect("You have to login first."));
                let is_exist = is_exist_filepath(&client, &user_info, filepath).await?;
                if !is_exist {
                    panic!("The given filepath {} does not exist.", filepath);
                }
                let pathes = search_descendant_pathes(&client, &user_info, filepath).await?;
                for path in pathes {
                    println!("{}", path);
                }
            }
            "exit" => {
                return Ok(());
            }
            _ => panic!("{} is not supported", command),
        }
    }
}
