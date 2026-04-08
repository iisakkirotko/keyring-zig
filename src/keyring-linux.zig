const std = @import("std");

pub const KeyringLinux = @This();

const GCancellable = opaque {};
const GError = opaque {};
const gboolean = c_int;

const SecretSchemaFlags = enum(c_uint) {
    SECRET_SCHEMA_NONE = 0,
    SECRET_SCHEMA_DONT_MATCH_NAME = 1 << 1,
};

const SecretSchemaAttributeType = enum(c_uint) {
    SECRET_SCHEMA_ATTRIBUTE_STRING = 0,
    SECRET_SCHEMA_ATTRIBUTE_INTEGER = 1,
    SECRET_SCHEMA_ATTRIBUTE_BOOLEAN = 2,
};

const SecretSchemaAttribute = extern struct {
    name: ?[*:0]const c_char,
    type: SecretSchemaAttributeType,
};

const SecretSchema = extern struct {
    name: [*:0]const c_char,
    flags: SecretSchemaFlags,
    attributes: [32]SecretSchemaAttribute,
    reserved: c_int = 0,
    reserved1: ?*anyopaque = null,
    reserved2: ?*anyopaque = null,
    reserved3: ?*anyopaque = null,
    reserved4: ?*anyopaque = null,
    reserved5: ?*anyopaque = null,
    reserved6: ?*anyopaque = null,
    reserved7: ?*anyopaque = null,
};

pub extern "libsecret" fn secret_password_free(
    password: [*:0]c_char,
) void;

pub extern "glib-2.0" fn g_error_free(err: *GError) void;

pub extern "libsecret" fn secret_password_lookup_sync(
    schema: *const SecretSchema,
    cancellable: ?*GCancellable,
    err: *?*GError,
    ...,
) callconv(.c) ?[*:0]c_char;

pub extern "libsecret" fn secret_password_store_sync(
    schema: *const SecretSchema,
    collection: ?[*:0]const c_char,
    label: [*:0]const c_char,
    password: [*:0]const c_char,
    cancellable: ?*GCancellable,
    err: *?*GError,
    ...,
) callconv(.c) gboolean;

pub extern "libsecret" fn secret_password_clear_sync(
    schema: *const SecretSchema,
    cancellable: ?*GCancellable,
    err: *?*GError,
    ...,
) callconv(.c) gboolean;

const keyring_schema: SecretSchema = .{
    .name = @ptrCast("keyring-zig-schema"),
    .flags = .SECRET_SCHEMA_NONE,
    .attributes = .{
        SecretSchemaAttribute{ .name = @ptrCast("service"), .type = .SECRET_SCHEMA_ATTRIBUTE_STRING },
        SecretSchemaAttribute{ .name = @ptrCast("account"), .type = .SECRET_SCHEMA_ATTRIBUTE_STRING },
    } ++ [_]SecretSchemaAttribute{.{ .name = null, .type = .SECRET_SCHEMA_ATTRIBUTE_STRING }} ** 30,
};

/// Write a null terminated version of val into buf, and return a pointer
/// to a c_char version of it. Doesn't check that the buffer is large enough,
/// only asserts it.
fn toNulTerminatedChar(val: []const u8, buf: []u8) [*:0]const c_char {
    std.debug.assert(buf.len >= val.len + 1);
    @memcpy(buf[0..val.len], val);
    buf[val.len] = 0;
    const c_val: [*:0]const c_char = @ptrCast(buf[0..val.len :0]);
    return c_val;
}

const KeyChainGetError = error{ EntryNotFound, KeyChainReadError };
fn readEntry(service: [*:0]const c_char, key: [*:0]const c_char) KeyChainGetError![*:0]c_char {
    var err: ?*GError = null;

    const val = secret_password_lookup_sync(
        &keyring_schema,
        null,
        &err,
        "service",
        service,
        "account",
        key,
        @as(?[*:0]const c_char, null),
    ) orelse {
        if (err) |err_val| {
            g_error_free(err_val);
            return error.KeyChainReadError;
        }
        return error.EntryNotFound;
    };
    return val;
}

const KeyChainBufferGetError = KeyChainGetError || error{ BufferTooSmall, ServiceTooLong, KeyTooLong };
/// Get the entry corresponding to service and key.
/// Service and key have maximum length constraints (512 b and 2 kb respectively).
/// If you may need larger values, use getAlloc instead.
pub fn get(service: []const u8, key: []const u8, out_buf: []u8) KeyChainBufferGetError![]u8 {
    if (service.len > 512) return error.ServiceTooLong;
    if (key.len > 2048) return error.KeyTooLong;

    // Make nul terminated copies of service and key
    var service_buf: [512 + 1:0]u8 = undefined;
    var key_buf: [2048 + 1:0]u8 = undefined;

    const c_service = toNulTerminatedChar(service, service_buf[0..]);
    const c_key = toNulTerminatedChar(key, key_buf[0..]);

    const val = try readEntry(
        c_service,
        c_key,
    );
    defer secret_password_free(val);

    const val_slice: []const u8 = @ptrCast(std.mem.span(val));
    if (out_buf.len < val_slice.len) return error.BufferTooSmall;
    @memcpy(out_buf[0..val_slice.len], val_slice);
    return out_buf[0..val_slice.len];
}

const KeyChainAllocGetError = KeyChainGetError || error{OutOfMemory};
pub fn getAlloc(gpa: std.mem.Allocator, service: []const u8, key: []const u8) KeyChainAllocGetError![]u8 {
    var service_buf: []u8 = try gpa.alloc(u8, service.len + 1);
    defer gpa.free(service_buf);
    var key_buf: []u8 = try gpa.alloc(u8, key.len + 1);
    defer gpa.free(key_buf);

    const c_service = toNulTerminatedChar(service, service_buf[0..]);
    const c_key = toNulTerminatedChar(key, key_buf[0..]);

    const val = try readEntry(
        c_service,
        c_key,
    );
    defer secret_password_free(val);

    const val_slice: []const u8 = @ptrCast(std.mem.span(val));
    const return_val = try gpa.dupe(u8, val_slice);
    return return_val;
}

const KeyChainWriteError = error{ ServiceTooLong, KeyTooLong, ValueTooLong, KeyChainWriteError } || std.fmt.BufPrintError;
pub fn set(service: []const u8, key: []const u8, value: []const u8) KeyChainWriteError!void {
    if (service.len > 512) return error.ServiceTooLong;
    if (key.len > 2048) return error.KeyTooLong;
    if (value.len > 16 * 1024) return error.ValueTooLong;

    var service_buf: [512 + 1]u8 = undefined;
    const c_service = toNulTerminatedChar(service, service_buf[0..]);

    var key_buf: [2048 + 1]u8 = undefined;
    const c_key = toNulTerminatedChar(key, key_buf[0..]);

    // service_buf + key_buf + 1 for separator + 1 for nul
    var label_buf: [2560 + 1 + 1]u8 = undefined;
    const label = try std.fmt.bufPrint(&label_buf, "{s}/{s}", .{ service, key });
    label_buf[label.len] = 0;
    const c_label: [:0]c_char = @ptrCast(label_buf[0..label.len :0]);

    var val_buf: [16 * 1024 + 1]u8 = undefined;
    const c_val = toNulTerminatedChar(value, val_buf[0..]);

    var err: ?*GError = null;
    const success = secret_password_store_sync(
        &keyring_schema,
        null,
        c_label,
        c_val,
        null,
        &err,
        "service",
        c_service,
        "account",
        c_key,
        @as(?[*:0]const c_char, null),
    );
    if (success == 0) return error.KeyChainWriteError;
}

const KeyChainDeleteError = error{ ServiceTooLong, KeyTooLong, KeyChainDeleteError };
pub fn delete(service: []const u8, key: []const u8) KeyChainDeleteError!void {
    if (service.len > 512) return error.ServiceTooLong;
    if (key.len > 2048) return error.KeyTooLong;

    var service_buf: [512 + 1]u8 = undefined;
    const c_service = toNulTerminatedChar(service, service_buf[0..]);

    var key_buf: [2048 + 1]u8 = undefined;
    const c_key = toNulTerminatedChar(key, key_buf[0..]);

    var err: ?*GError = null;
    const success = secret_password_clear_sync(
        &keyring_schema,
        null,
        &err,
        "service",
        c_service,
        "account",
        c_key,
        @as(?[*:0]const c_char, null),
    );
    if (success == 0) return error.KeyChainDeleteError;
}
