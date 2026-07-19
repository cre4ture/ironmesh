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

void *ironmesh_ios_facade_create_named(const char *connection_input,
                                       const char *server_ca_pem,
                                       const char *client_identity_json,
                                       const char *connection_name,
                                       char **out_error);

void ironmesh_ios_facade_free(void *handle);

/**
 * # Safety
 *
 * `value` must be a pointer previously returned by this library via
 * `CString::into_raw`, and it must not be freed more than once.
 */
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

int ironmesh_ios_facade_store_index_with_options_json(void *handle,
                                                      const char *prefix,
                                                      uintptr_t depth,
                                                      const char *snapshot,
                                                      const char *view,
                                                      intptr_t offset,
                                                      intptr_t limit,
                                                      const char *sort,
                                                      const char *media_filter,
                                                      char **out_json,
                                                      char **out_error);

int ironmesh_ios_facade_connection_diagnostics_json(void *handle,
                                                    char **out_json,
                                                    char **out_error);

int ironmesh_ios_facade_connection_route_snapshot_json(void *handle,
                                                       int refresh,
                                                       char **out_json,
                                                       char **out_error);

int ironmesh_ios_facade_fetch_bytes(void *handle,
                                    const char *key,
                                    struct IronmeshIosBytes *out_bytes,
                                    char **out_error);

int ironmesh_ios_facade_fetch_relative_bytes(void *handle,
                                             const char *path,
                                             struct IronmeshIosBytes *out_bytes,
                                             char **out_error);

int ironmesh_ios_facade_put_bytes(void *handle,
                                  const char *key,
                                  const uint8_t *data,
                                  uintptr_t len,
                                  char **out_json,
                                  char **out_error);

int ironmesh_ios_facade_put_bytes_with_expected_revision(void *handle,
                                                         const char *key,
                                                         const uint8_t *data,
                                                         uintptr_t len,
                                                         const char *expected_revision,
                                                         char **out_json,
                                                         char **out_error);

int ironmesh_ios_facade_delete_path_with_expected_revision(void *handle,
                                                           const char *key,
                                                           const char *expected_revision,
                                                           char **out_json,
                                                           char **out_error);

int ironmesh_ios_facade_enroll_with_bootstrap(const char *connection_input,
                                              const char *device_id_override,
                                              const char *device_label_override,
                                              char **out_json,
                                              char **out_error);

int ironmesh_ios_facade_delete_path(void *handle, const char *key, char **out_error);

int ironmesh_ios_facade_move_path(void *handle,
                                  const char *from_path,
                                  const char *to_path,
                                  int overwrite,
                                  char **out_error);

int ironmesh_ios_facade_move_path_with_expected_revision(void *handle,
                                                         const char *from_path,
                                                         const char *to_path,
                                                         int overwrite,
                                                         const char *expected_revision,
                                                         char **out_error);

int ironmesh_ios_facade_start_web_ui(const char *connection_input,
                                     const char *server_ca_pem,
                                     const char *client_identity_json,
                                     char **out_url,
                                     char **out_error);

int ironmesh_ios_facade_stop_web_ui(char **out_error);

#endif  /* IRONMESH_IOS_APP_H */
