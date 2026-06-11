#include <stdlib.h>
#include <string.h>
#include "module.h"
#include "malefic/module.pb.h"
#include <pb_encode.h>
#include <pb_decode.h>
#include <stdio.h>

/*
 * Example C module: echoes the request input back with a prefix.
 * Demonstrates nanopb decode/encode round-trip.
 */

static const char MODULE_NAME[] = "example_c";

const char* module_name(void) {
    return MODULE_NAME;
}

static int example_handle(uint32_t task_id,
                          const char* req_data, int req_len,
                          char** resp_data, int* resp_len) {
    (void)task_id;

    /* Decode Request */
    malefic_Request request = malefic_Request_init_zero;
    pb_istream_t istream = pb_istream_from_buffer((const pb_byte_t*)req_data, (size_t)req_len);
    if (!pb_decode(&istream, malefic_Request_fields, &request)) {
        return -1;
    }

    /* Build Response */
    malefic_Response response = malefic_Response_init_zero;
    snprintf(response.output, sizeof(response.output),
             "hello from c module, input: %s", request.input);

    /* Encode Response */
    uint8_t tmp_buf[4096];
    pb_ostream_t ostream = pb_ostream_from_buffer(tmp_buf, sizeof(tmp_buf));
    if (!pb_encode(&ostream, malefic_Response_fields, &response)) {
        return -1;
    }

    size_t encoded_len = ostream.bytes_written;
    *resp_data = (char*)malloc(encoded_len);
    if (!*resp_data) {
        return -1;
    }
    memcpy(*resp_data, tmp_buf, encoded_len);
    *resp_len = (int)encoded_len;

    return 0;
}

module_handler_fn module_handler(void) {
    return example_handle;
}
