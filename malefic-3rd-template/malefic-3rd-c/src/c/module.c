#include "module.h"

/*
 * FFI exports — delegates to the registered module.
 */

const char* CModuleName(void) {
    return module_name();
}

int CModuleHandle(uint32_t task_id,
                  const char* req_data, int req_len,
                  char** resp_data, int* resp_len) {
    module_handler_fn handler = module_handler();
    if (!handler) {
        return -1;
    }
    return handler(task_id, req_data, req_len, resp_data, resp_len);
}
