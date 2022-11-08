# Sommelier Drive Client
**Client implementation of Sommelier Drive**

## Disclaimer
DO NOT USE THIS LIBRARY IN PRODUCTION. At this point, this is under development. It has known and unknown bugs and security flaws.

## Installation and Build
You can install and build our library with the following commands.
```bash
git clone https://github.com/Sommelier-db/sommelier-drive-client.git
cd sommelier-drive-client
./build.sh
```

## Run Client CLI
You can start the client CLI by executing the following command under the sommelier-drive-client directory.
```bash
cargo run --release
```
When you see the green message "Enter your server url", enter the URL of the server hosting the Sommelier Drive server.
After that, you can run the following commands!

## Command Usage
### register `initDirPath`
Create a new user account and the user's initial directory under the root directory.

- Inputs:
    1. `initDirPath`: A file path of the initial directory.
- Example: `register /data1`

**Note: Before running the following commands, you must create a user account with this command!**

### touch `filePath`
Create a new file with an empty contents.

- Inputs:
    1. `filePath`: A file path.
- Example: `touch /data1/test.txt`

### mkdir `dirPath`
Create a new directory.

- Inputs:
    1. `dirPath`: A directory path.
- Example: `mkdir /data1/subdata`

### cat `filePath`
Retrieve a text in the file located in the given file path.

- Inputs:
    1. `filePath`: A file path.
- Example: `cat /data1/test.txt`

### modify `filePath` `text`
Modify the file contents located in the given file path with the given text.

- Inputs:
    1. `filePath`: A file path of the file to be modified.
    2. `text`: A text written in the file.
- Example: `modify /data1/test.txt Hello!`

### ls `dirPath`
Retrieve a childlen file paths under the given file path.

- Inputs:
    1. `dirPath`: A directory path.
- Example: `ls /data1`

### find `dirPath`
Retrieve a descendent file paths under the given file path.

- Inputs:
    1. `dirPath`: A directory path.
- Example: `find /data1`

### exit
Exit the CLI.

## Authors
- Sora Suegami

## License
This project is licensed under the MIT License - see the [LICENSE.md](https://github.com/SoraSuegami/halo2_rsa/blob/main/LICENSE.md) file for details
