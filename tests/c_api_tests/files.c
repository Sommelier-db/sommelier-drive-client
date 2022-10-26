#include "sommelier_drive_client.h"
#include <stdio.h>

int main()
{
    CHttpClient client;
    client.base_url = "http://localhost:8000/api";
    client.region_name = "myregion";
    char *init_path = "/myfilepath";
    CUserInfo user_info = registerUser(client, init_path);
    char *filepath1 = "/myfilepath/test.txt";
    const uint8_t file_bytes_ptr[6] = {83, 37, 32, 19, 54, 73};
    size_t file_bytes_len = sizeof(file_bytes_ptr) / sizeof(uint8_t);
    addFile(client, user_info, filepath1, file_bytes_ptr, file_bytes_len);
    CContentsData contents = openFilepath(client, user_info, filepath1);
    printf("is_file %d\n", contents.is_file);
    for (int i = 0; i < file_bytes_len; ++i)
    {
        printf("byte %d\n", *(contents.file_bytes_ptr + i));
    }
    freeContentsData(contents);

    char *filepath2 = "/myfilepath/sub";
    addDirectory(client, user_info, filepath2);
    CPathVec ls_pathes = getChildrenPathes(client, user_info, init_path);
    for (int i = 0; i < ls_pathes.len; i++)
    {
        printf("path at %d: %s\n", i, ls_pathes.ptr[i]);
    }
    freePathVec(ls_pathes);

    return 0;
}