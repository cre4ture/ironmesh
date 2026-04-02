#ifndef IRONMESH_IOS_APP_H
#define IRONMESH_IOS_APP_H

#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct IronmeshIosBytes {
  uint8_t *data;
  uintptr_t len;
  uintptr_t capacity;
} IronmeshIosBytes;

void *ironmesh_ios_facade_create(const char *connection_input,
                                 const char *server_ca_pem,
                                 const char *client_identity_json,
                                 char **out_error);

void ironmesh_ios_facade_free(void *handle);

void ironmesh_ios_string_free(char *value);

void ironmesh_ios_bytes_free(struct IronmeshIosBytes value);

int ironmesh_ios_facade_list_json(void *handle,
                                  const char *prefix,
                                  uintptr_t depth,
                                  const char *snapshot,
                                  char **out_json,
                                  char **out_error);

int ironmesh_ios_facade_metadata_json(void *handle,
                                      const char *key,
                                      char **out_json,
                                      char **out_error);

int ironmesh_ios_facade_fetch_bytes(void *handle,
                                    const char *key,
                                    struct IronmeshIosBytes *out_bytes,
                                    char **out_error);

int ironmesh_ios_facade_put_bytes(void *handle,
                                  const char *key,
                                  const uint8_t *data,
                                  uintptr_t len,
                                  char **out_json,
                                  char **out_error);

int ironmesh_ios_facade_delete_path(void *handle, const char *key, char **out_error);

int ironmesh_ios_facade_move_path(void *handle,
                                  const char *from_path,
                                  const char *to_path,
                                  int overwrite,
                                  char **out_error);

#endif  /* IRONMESH_IOS_APP_H */
