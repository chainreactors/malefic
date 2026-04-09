# Example Nim module: echoes the request input back with a prefix.
# Demonstrates nanopb decode/encode round-trip via C interop.

{.passC: "-DPB_FIELD_32BIT".}

# --- nanopb types and functions ---

type
  pb_byte_t = uint8
  pb_istream_t {.importc, header: "pb_decode.h".} = object
  pb_ostream_t {.importc, header: "pb_encode.h".} = object
    bytes_written: csize_t

# nanopb generated types (opaque — actual layout handled by C)
type
  malefic_Request {.importc, header: "module.pb.h".} = object
    name: array[256, char]
    input: array[256, char]
  malefic_Response {.importc, header: "module.pb.h".} = object
    output: array[4096, char]
    error: array[256, char]

# nanopb field descriptors — declared as ptr to first element (C arrays decay to pointers)
var malefic_Request_fields_ptr {.importc: "malefic_Request_fields", header: "module.pb.h".}: ptr byte
var malefic_Response_fields_ptr {.importc: "malefic_Response_fields", header: "module.pb.h".}: ptr byte

# nanopb functions
proc pb_istream_from_buffer(buf: ptr pb_byte_t, bufsize: csize_t): pb_istream_t {.importc, header: "pb_decode.h".}
proc pb_decode(stream: ptr pb_istream_t, fields: ptr byte, dest_struct: pointer): bool {.importc, header: "pb_decode.h".}
proc pb_ostream_from_buffer(buf: ptr pb_byte_t, bufsize: csize_t): pb_ostream_t {.importc, header: "pb_encode.h".}
proc pb_encode(stream: ptr pb_ostream_t, fields: ptr byte, src_struct: pointer): bool {.importc, header: "pb_encode.h".}

# C stdlib
proc c_malloc(size: csize_t): pointer {.importc: "malloc", header: "<stdlib.h>".}
proc c_free(p: pointer) {.importc: "free", header: "<stdlib.h>".}
proc c_memcpy(dest, src: pointer, n: csize_t): pointer {.importc: "memcpy", header: "<string.h>".}
proc c_memset(s: pointer, c: cint, n: csize_t): pointer {.importc: "memset", header: "<string.h>".}
proc c_snprintf(buf: cstring, size: csize_t, fmt: cstring): cint {.importc: "snprintf", header: "<stdio.h>", varargs.}

const MODULE_NAME: cstring = "example_nim"

proc NimModuleName(): cstring {.exportc, cdecl.} =
  return MODULE_NAME

proc NimModuleHandle(task_id: uint32, req_data: cstring, req_len: cint,
                     resp_data: ptr cstring, resp_len: ptr cint): cint {.exportc, cdecl.} =
  # Decode Request (zero-init via memset instead of _init_zero macro)
  var request: malefic_Request
  discard c_memset(addr request, 0, csize_t(sizeof(request)))
  var istream = pb_istream_from_buffer(cast[ptr pb_byte_t](req_data), csize_t(req_len))
  if not pb_decode(addr istream, malefic_Request_fields_ptr, addr request):
    return -1

  # Build Response
  var response: malefic_Response
  discard c_memset(addr response, 0, csize_t(sizeof(response)))
  let inputStr = cast[cstring](addr request.input[0])
  discard c_snprintf(cast[cstring](addr response.output[0]), csize_t(sizeof(response.output)),
                     "hello from nim module, input: %s", inputStr)

  # Encode Response
  var tmp_buf: array[4096, uint8]
  var ostream = pb_ostream_from_buffer(cast[ptr pb_byte_t](addr tmp_buf[0]), csize_t(sizeof(tmp_buf)))
  if not pb_encode(addr ostream, malefic_Response_fields_ptr, addr response):
    return -1

  let encoded_len = ostream.bytes_written
  let out_ptr = c_malloc(encoded_len)
  if out_ptr == nil:
    return -1
  discard c_memcpy(out_ptr, addr tmp_buf[0], encoded_len)
  resp_data[] = cast[cstring](out_ptr)
  resp_len[] = cint(encoded_len)

  return 0
