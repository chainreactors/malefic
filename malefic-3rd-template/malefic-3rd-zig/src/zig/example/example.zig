const std = @import("std");
const c = @cImport({
    @cDefine("PB_FIELD_32BIT", {});
    @cInclude("pb_encode.h");
    @cInclude("pb_decode.h");
    @cInclude("module.pb.h");
});

const MODULE_NAME: [*:0]const u8 = "example_zig";

export fn ZigModuleName() callconv(.C) [*:0]const u8 {
    return MODULE_NAME;
}

export fn ZigModuleHandle(
    task_id: u32,
    req_data: [*]const u8,
    req_len: c_int,
    resp_data: *[*]u8,
    resp_len: *c_int,
) callconv(.C) c_int {
    _ = task_id;

    // Decode Request
    var request: c.malefic_Request = std.mem.zeroes(c.malefic_Request);
    var istream = c.pb_istream_from_buffer(req_data, @intCast(@as(usize, @intCast(req_len))));
    if (!c.pb_decode(&istream, c.malefic_Request_fields, &request)) {
        return -1;
    }

    // Build Response
    var response: c.malefic_Response = std.mem.zeroes(c.malefic_Response);

    const prefix = "hello from zig module, input: ";
    const input_slice = std.mem.sliceTo(&request.input, 0);
    const total_len = prefix.len + input_slice.len;

    if (total_len < response.output.len) {
        @memcpy(response.output[0..prefix.len], prefix);
        @memcpy(response.output[prefix.len .. prefix.len + input_slice.len], input_slice);
        response.output[total_len] = 0;
    } else {
        return -1;
    }

    // Encode Response
    var tmp_buf: [4096]u8 = undefined;
    var ostream = c.pb_ostream_from_buffer(&tmp_buf, tmp_buf.len);
    if (!c.pb_encode(&ostream, c.malefic_Response_fields, &response)) {
        return -1;
    }

    const encoded_len = ostream.bytes_written;
    const out_ptr: ?[*]u8 = @ptrCast(std.c.malloc(encoded_len) orelse return -1);
    @memcpy(out_ptr.?[0..encoded_len], tmp_buf[0..encoded_len]);
    resp_data.* = out_ptr.?;
    resp_len.* = @intCast(encoded_len);

    return 0;
}
