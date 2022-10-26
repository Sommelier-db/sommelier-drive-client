#include "sommelier_drive_client.h"
#include <stdio.h>

int main()
{
    CHttpClient client;
    client.base_url = "http://localhost:8000/api";
    client.region_name = "myregion";
    CUserInfo userinfo = registerUser(client, "/myfilepath");
    printf("%s\n%s\n", userinfo.data_sk, userinfo.keyword_sk);
    CPublicKeys pks = getPublicKeys(client, userinfo.id);
    freeUserInfo(userinfo);
    freePublicKeys(pks);
    return 0;
}