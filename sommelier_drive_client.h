#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>


typedef struct CHttpClient {
  char *base_url;
  char *region_name;
} CHttpClient;

typedef struct CUserInfo {
  uint64_t id;
  char *data_sk;
  char *keyword_sk;
} CUserInfo;

typedef struct CPublicKeys {
  char *data_pk;
  char *keyword_pk;
} CPublicKeys;

typedef struct CContentsData {
  int is_file;
  size_t num_readable_users;
  size_t num_writeable_users;
  uint64_t *readable_user_path_ids;
  uint64_t *writeable_user_path_ids;
  const uint8_t *file_bytes_ptr;
  size_t file_bytes_len;
} CContentsData;

int addDirectory(struct CHttpClient client, struct CUserInfo user_info, char *filepath);

int addFile(struct CHttpClient client,
            struct CUserInfo user_info,
            char *filepath,
            const uint8_t *file_bytes_ptr,
            size_t file_bytes_len);

int addReadPermission(struct CHttpClient client,
                      struct CUserInfo user_info,
                      char *filepath,
                      uint64_t new_user_id);

int getChildrenPathes(struct CHttpClient client,
                      struct CUserInfo user_info,
                      char *cur_path,
                      char **result_pathes);

char *getFilePathWithId(struct CHttpClient client, struct CUserInfo user_info, uint64_t path_id);

struct CPublicKeys getPublicKeys(struct CHttpClient client, uint64_t user_id);

int isExistFilepath(struct CHttpClient client, struct CUserInfo user_info, char *filepath);

int modifyFile(struct CHttpClient client,
               struct CUserInfo user_info,
               char *filepath,
               const uint8_t *new_file_bytes_ptr,
               size_t new_file_bytes_len);

struct CContentsData openFilepath(struct CHttpClient client,
                                  struct CUserInfo user_info,
                                  char *filepath);

struct CUserInfo registerUser(struct CHttpClient client, char *filepath);

int searchDescendantPathes(struct CHttpClient client,
                           struct CUserInfo user_info,
                           char *cur_path,
                           char **result_pathes);
