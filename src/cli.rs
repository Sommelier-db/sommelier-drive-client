//use anyhow::Result;
use promkit::{build::Builder, crossterm::style, readline};
use sommelier_drive_client::*;
use std::{cell::RefCell, process::exit};
use tokio::runtime::Runtime;

fn main() -> Result<(), String> {
    #[cfg(not(feature = "cli"))]
    panic!("To run the cli, you need to compile this crate with `cli` feature.");
    #[cfg(feature = "cli")]
    let region_name = "sommelier_drive_cli";
    let rt = Runtime::new().expect("Runtime init error");
    let fut_result = async {
        cli(region_name).await.unwrap();
    };
    rt.block_on(fut_result);
    Ok(())
}

async fn cli(region_name: &'static str) -> Result<(), String> {
    let mut p = readline::Builder::default()
        .title("Enter your server url")
        .title_color(style::Color::DarkGreen)
        .build()
        .expect("readline init error");
    let base_url = p.run().expect("Server url not found.");
    println!("Welcome to Sommelier Drive!");
    let mut p = readline::Builder::default()
        .build()
        .expect("readline init error");
    loop {
        let line = p.run().expect("Fail to get next prompt.");
        let result = perform_each_op(&base_url, region_name, line).await;
        match result {
            Err(e) => println!("{}", e.to_string()),
            _ => {}
        }
    }
}

async fn perform_each_op(
    base_url: &str,
    region_name: &'static str,
    line: String,
) -> Result<(), String> {
    thread_local! {
        pub static GLOBAL_USER_INFO: RefCell<Option<SelfUserInfo>> = RefCell::new(None)
    };
    let client = HttpClient::new(&base_url, region_name);
    let mut spw = line.split_whitespace();
    let command = spw.next().expect("Command not found.");
    match command {
        "register" => {
            let filepath = spw.next().ok_or("Initial directory path not found.")?;
            let new_info = register_user(&client, filepath)
                .await
                .map_err(|e| e.to_string())?;
            println!("You are registered with a user id {}", new_info.id);
            GLOBAL_USER_INFO.with(|info| {
                let mut info_ref = info.borrow_mut();
                *info_ref = Some(new_info);
            });
        }
        "touch" => {
            let filepath = spw.next().ok_or("File path not found.")?;
            let user_info = GLOBAL_USER_INFO
                .with(|info| info.borrow().clone().ok_or("You have to login first."))?;
            add_file(&client, &user_info, filepath, Vec::new())
                .await
                .map_err(|e| e.to_string())?;
        }
        "mkdir" => {
            let filepath = spw.next().ok_or("File path not found.")?;
            let user_info = GLOBAL_USER_INFO
                .with(|info| info.borrow().clone().ok_or("You have to login first."))?;
            add_directory(&client, &user_info, filepath)
                .await
                .map_err(|e| e.to_string())?;
        }
        "cat" => {
            let filepath = spw.next().ok_or("File path not found.")?;
            let user_info = GLOBAL_USER_INFO
                .with(|info| info.borrow().clone().ok_or("You have to login first."))?;
            let is_exist = is_exist_filepath(&client, &user_info, filepath)
                .await
                .map_err(|e| e.to_string())?;
            if !is_exist {
                return Err(format!("The given filepath {} does not exist.", filepath));
            }
            let contents_data = open_filepath(&client, &user_info, filepath)
                .await
                .map_err(|e| e.to_string())?;
            if !contents_data.is_file {
                return Err(format!(
                    "The file at filepath {} is not a file but a directory.",
                    filepath
                ));
            }
            let bytes_string =
                String::from_utf8(contents_data.file_bytes).map_err(|e| e.to_string())?;
            println!("{}", bytes_string);
        }
        "modify" => {
            let filepath = spw.next().ok_or("File path not found.")?;
            let text = spw.next().ok_or("Input text not found.")?;
            let user_info = GLOBAL_USER_INFO
                .with(|info| info.borrow().clone().ok_or("You have to login first."))?;
            let is_exist = is_exist_filepath(&client, &user_info, filepath)
                .await
                .map_err(|e| e.to_string())?;
            if !is_exist {
                return Err(format!("The given filepath {} does not exist.", filepath));
            }
            let contents_data = open_filepath(&client, &user_info, filepath)
                .await
                .map_err(|e| e.to_string())?;
            if !contents_data.is_file {
                return Err(format!(
                    "The file at filepath {} is not a file but a directory.",
                    filepath
                ));
            }
            modify_file(&client, &user_info, filepath, text.as_bytes().to_vec())
                .await
                .map_err(|e| e.to_string())?;
        }
        "ls" => {
            let filepath = spw.next().ok_or("File path not found.")?;
            let user_info = GLOBAL_USER_INFO
                .with(|info| info.borrow().clone().ok_or("You have to login first."))?;
            let is_exist = is_exist_filepath(&client, &user_info, filepath)
                .await
                .map_err(|e| e.to_string())?;
            if !is_exist {
                return Err(format!("The given filepath {} does not exist.", filepath));
            }
            let children_pathes = get_children_pathes(&client, &user_info, filepath)
                .await
                .map_err(|e| e.to_string())?;
            for path in children_pathes {
                println!("{}", path);
            }
        }
        "find" => {
            let filepath = spw.next().ok_or("File path not found.")?;
            let user_info = GLOBAL_USER_INFO
                .with(|info| info.borrow().clone().ok_or("You have to login first."))?;
            let is_exist = is_exist_filepath(&client, &user_info, filepath)
                .await
                .map_err(|e| e.to_string())?;
            if !is_exist {
                return Err(format!("The given filepath {} does not exist.", filepath));
            }
            let pathes = search_descendant_pathes(&client, &user_info, filepath)
                .await
                .map_err(|e| e.to_string())?;
            for path in pathes {
                println!("{}", path);
            }
        }
        "exit" => {
            exit(0);
        }
        _ => return Err(format!("{} is not supported", command)),
    }
    Ok(())
}
