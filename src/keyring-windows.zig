const std = @import("std");

pub const KeyringWindows = @This();

const service_max_len = 512;
const key_max_len = 2048;

// =================================================================================
// Section: Definitions
// External function declarations for the windows credential manager API
// See https://github.com/marlersoft/zigwin32/blob/main/win32/security/credentials.zig
// =================================================================================

const BOOL = i32;
const DWORD = u32;
const LPWSTR = ?[*:0]u16;
const LPBYTE = ?[*]u8;

pub const CRED_TYPE = enum(u32) {
    GENERIC = 1,
    DOMAIN_PASSWORD = 2,
    DOMAIN_CERTIFICATE = 3,
    DOMAIN_VISIBLE_PASSWORD = 4,
    GENERIC_CERTIFICATE = 5,
    DOMAIN_EXTENDED = 6,
    MAXIMUM = 7,
    MAXIMUM_EX = 1007,
};

pub const CRED_FLAGS = packed struct(u32) {
    PASSWORD_FOR_CERT: u1 = 0,
    PROMPT_NOW: u1 = 0,
    USERNAME_TARGET: u1 = 0,
    OWF_CRED_BLOB: u1 = 0,
    REQUIRE_CONFIRMATION: u1 = 0,
    WILDCARD_MATCH: u1 = 0,
    VSM_PROTECTED: u1 = 0,
    NGC_CERT: u1 = 0,
    _8: u1 = 0,
    _9: u1 = 0,
    _10: u1 = 0,
    _11: u1 = 0,
    _12: u1 = 0,
    _13: u1 = 0,
    _14: u1 = 0,
    _15: u1 = 0,
    _16: u1 = 0,
    _17: u1 = 0,
    _18: u1 = 0,
    _19: u1 = 0,
    _20: u1 = 0,
    _21: u1 = 0,
    _22: u1 = 0,
    _23: u1 = 0,
    _24: u1 = 0,
    _25: u1 = 0,
    _26: u1 = 0,
    _27: u1 = 0,
    _28: u1 = 0,
    _29: u1 = 0,
    _30: u1 = 0,
    _31: u1 = 0,
};

pub const PWSTR = [*:0]u16;

pub const FILETIME = extern struct {
    dwLowDateTime: u32,
    dwHighDateTime: u32,
};

pub const CRED_PERSIST = enum(u32) {
    NONE = 0,
    SESSION = 1,
    LOCAL_MACHINE = 2,
    ENTERPRISE = 3,
};

pub const CREDENTIAL_ATTRIBUTEW = extern struct {
    Keyword: ?PWSTR,
    Flags: u32,
    ValueSize: u32,
    Value: ?*u8,
};

pub const CREDENTIALW = extern struct {
    Flags: CRED_FLAGS,
    Type: CRED_TYPE,
    TargetName: ?PWSTR,
    Comment: ?PWSTR,
    LastWritten: FILETIME,
    CredentialBlobSize: u32,
    CredentialBlob: ?*u8,
    Persist: CRED_PERSIST,
    AttributeCount: u32,
    Attributes: ?*CREDENTIAL_ATTRIBUTEW,
    TargetAlias: ?PWSTR,
    UserName: ?PWSTR,
};

// See https://github.com/marlersoft/zigwin32/blob/fd6ebce3ebfe48f291069c0ddc518b2cc83be450/win32/foundation.zig#L6535-L9724
// for error code definitions
pub extern "kernel32" fn GetLastError() callconv(.winapi) u32;

pub extern "advapi32" fn CredReadW(
    TargetName: ?[*:0]const u16,
    Type: u32,
    Flags: u32,
    Credential: ?*?*CREDENTIALW,
) callconv(.winapi) BOOL;

pub extern "advapi32" fn CredWriteW(
    Credential: ?*CREDENTIALW,
    Flags: u32,
) callconv(.winapi) BOOL;

pub extern "advapi32" fn CredDeleteW(
    TargetName: ?[*:0]const u16,
    Type: u32,
    Flags: u32,
) callconv(.winapi) BOOL;

pub extern "advapi32" fn CredFree(
    Buffer: ?*anyopaque,
) callconv(.winapi) void;

// =================================================================================
// Section: Implementation
// =================================================================================

const KeyChainGetError = error{ EntryNotFound, KeyChainReadError };
fn readCred(name: [:0]const u16, out: ?*?*CREDENTIALW) KeyChainGetError!void {
    const status = CredReadW(name, @intFromEnum(CRED_TYPE.GENERIC), 0, out);
    if (status == 0) {
        switch (GetLastError()) {
            1168 => return error.EntryNotFound,
            else => return error.KeyChainReadError,
        }
    }
}

fn nameLen(service: []const u8, key: []const u8) usize {
    // +1 for ':', +1 for null terminator
    return service.len + key.len + 1 + 1;
}

fn makeName(service: []const u8, key: []const u8, out_buf: []u16) error{InvalidUtf8}![:0]u16 {
    // var buf: [10 * 1024]u8 = undefined;
    // const out = try std.fmt.bufPrint(&buf, "{s}:{s}", .{ service, key });
    // const utf16_len = try std.unicode.utf8ToUtf16Le(out_buf, out);
    const post_service = try std.unicode.utf8ToUtf16Le(out_buf[0..], service);
    out_buf[post_service] = ':';
    const post_key = try std.unicode.utf8ToUtf16Le(out_buf[post_service + 1 .. out_buf.len - 1], key);
    out_buf[post_service + post_key + 1] = 0;
    return out_buf[0 .. post_service + post_key + 1 :0];
}

const KeyChainBufferGetError = KeyChainGetError || std.fmt.BufPrintError || error{ BufferTooSmall, InvalidUtf8, ServiceTooLong, KeyTooLong };
pub fn get(service: []const u8, key: []const u8, out_buf: []u8) KeyChainBufferGetError![]u8 {
    if (service.len > service_max_len) return error.ServiceTooLong;
    if (key.len > key_max_len) return error.KeyTooLong;

    var target_name_buf: [service_max_len + key_max_len + 2]u16 = undefined;
    const target_name = try makeName(service, key, &target_name_buf);

    var res: ?*CREDENTIALW = null;
    try readCred(target_name, &res);
    defer if (res) |ptr| CredFree(ptr);

    const blob_ptr: [*]u8 = @ptrCast(res.?.CredentialBlob orelse return error.KeyChainReadError);
    const len: usize = @intCast(res.?.CredentialBlobSize);
    if (out_buf.len < len) return error.BufferTooSmall;
    @memcpy(out_buf[0..len], blob_ptr[0..len]);
    return out_buf[0..len];
}

const KeyChainAllocGetError = KeyChainGetError || std.fmt.BufPrintError || error{ OutOfMemory, InvalidUtf8 };
pub fn getAlloc(gpa: std.mem.Allocator, service: []const u8, key: []const u8) KeyChainAllocGetError![]u8 {
    const target_name_buf = try gpa.alloc(u16, nameLen(service, key));
    defer gpa.free(target_name_buf);
    const target_name = try makeName(service, key, target_name_buf);

    var res: ?*CREDENTIALW = null;
    try readCred(target_name, &res);
    defer if (res) |ptr| CredFree(ptr);

    const blob_ptr: [*]u8 = @ptrCast(res.?.CredentialBlob orelse return error.KeyChainReadError);
    const len: usize = @intCast(res.?.CredentialBlobSize);
    const val = try gpa.dupe(u8, blob_ptr[0..len]);
    return val;
}

const KeyChainWriteError = error{ InvalidUtf8, ServiceTooLong, KeyTooLong, KeyChainWriteError };
pub fn set(service: []const u8, key: []const u8, value: []const u8) KeyChainWriteError!void {
    if (service.len > service_max_len) return error.ServiceTooLong;
    if (key.len > key_max_len) return error.KeyTooLong;

    var target_name_buf: [service_max_len + key_max_len + 2]u16 = undefined;
    const target_name = try makeName(service, key, &target_name_buf);

    var usr_buf: [key_max_len + 1]u16 = undefined;
    const usr_len = try std.unicode.utf8ToUtf16Le(&usr_buf, key);
    usr_buf[usr_len] = 0;
    const usr = usr_buf[0..usr_len :0];

    var data: CREDENTIALW = .{
        .Flags = .{},
        .Type = .GENERIC,
        .TargetName = target_name.ptr,
        .Comment = null,
        .LastWritten = std.mem.zeroes(FILETIME),
        .CredentialBlobSize = @intCast(value.len),
        .CredentialBlob = @ptrCast(@constCast(value.ptr)),
        .Persist = .LOCAL_MACHINE,
        .AttributeCount = 0,
        .Attributes = null,
        .TargetAlias = null,
        .UserName = usr.ptr,
    };

    const status = CredWriteW(&data, 0);
    if (status == 0) return error.KeyChainWriteError;
}

const KeyChainDeleteError = error{ EntryNotFound, InvalidUtf8, ServiceTooLong, KeyTooLong, KeyChainDeleteError };
pub fn delete(service: []const u8, key: []const u8) KeyChainDeleteError!void {
    if (service.len > service_max_len) return error.ServiceTooLong;
    if (key.len > key_max_len) return error.KeyTooLong;

    var target_name_buf: [service_max_len + key_max_len + 2]u16 = undefined;
    const target_name = try makeName(service, key, &target_name_buf);

    const status = CredDeleteW(target_name.ptr, @intFromEnum(CRED_TYPE.GENERIC), 0);
    if (status == 0) {
        switch (GetLastError()) {
            1168 => return error.EntryNotFound,
            else => return error.KeyChainDeleteError,
        }
    }
}

test "makeName formats and terminates utf16 target name" {
    var ascii_buf: [64]u16 = undefined;
    const ascii = try makeName("service", "user", &ascii_buf);
    try std.testing.expectEqualSlices(u16, &[_]u16{ 's', 'e', 'r', 'v', 'i', 'c', 'e', ':', 'u', 's', 'e', 'r' }, ascii);
    try std.testing.expectEqual(@as(u16, 0), ascii_buf[ascii.len]);

    var unicode_buf: [64]u16 = undefined;
    const unicode = try makeName("palvelu", "käyttäjä", &unicode_buf);
    const expected = std.unicode.utf8ToUtf16LeStringLiteral("palvelu:käyttäjä");
    try std.testing.expectEqualSlices(u16, expected, unicode);
    try std.testing.expectEqual(@as(u16, 0), unicode_buf[unicode.len]);
}
