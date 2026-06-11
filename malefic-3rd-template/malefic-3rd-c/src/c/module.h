#ifndef MALEFIC_MODULE_H
#define MALEFIC_MODULE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * C Module Interface for malefic-3rd-c
 *
 * CModuleName returns a static string (do NOT free).
 * CModuleHandle receives a serialized protobuf Request and returns a serialized Response.
 * The response buffer is malloc'd; Rust frees it via free().
 */

/* Returns the module name (static string, caller must NOT free). */
const char* CModuleName(void);

/*
 * Synchronous handler.
 *   task_id  : task identifier
 *   req_data : serialized protobuf Request
 *   req_len  : length of req_data
 *   resp_data: [out] pointer to malloc'd response buffer
 *   resp_len : [out] length of response buffer
 *
 * Returns 0 on success, non-zero on error.
 */
int CModuleHandle(uint32_t task_id,
                  const char* req_data, int req_len,
                  char** resp_data, int* resp_len);

/*
 * Module registration callback.
 * Called by module.c framework — each module implements this to populate
 * the handler function pointer.
 */

/* Handler function type: same signature as CModuleHandle */
typedef int (*module_handler_fn)(uint32_t task_id,
                                 const char* req_data, int req_len,
                                 char** resp_data, int* resp_len);

/* Implemented by each module (e.g. example.c) */
const char* module_name(void);
module_handler_fn module_handler(void);

#ifdef __cplusplus
}
#endif

#endif /* MALEFIC_MODULE_H */
