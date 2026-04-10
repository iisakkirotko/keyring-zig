const std = @import("std");

pub const KeyringMacos = @This();

const sec = @cImport({
    @cInclude("Security/Security.h");
    @cInclude("CoreFoundation/CoreFoundation.h");
});

fn makeCfString(bytes: []const u8) error{CfStringCreationFailed}!sec.CFStringRef {
    const val = sec.CFStringCreateWithBytes(null, bytes.ptr, @intCast(bytes.len), sec.kCFStringEncodingUTF8, 0) orelse {
        return error.CfStringCreationFailed;
    };
    return val;
}

fn makeCfData(bytes: []const u8) error{CfDataCreationFailed}!sec.CFDataRef {
    const val = sec.CFDataCreate(null, bytes.ptr, @intCast(bytes.len)) orelse {
        return error.CfDataCreationFailed;
    };
    return val;
}

fn makeCfQueryDict(service: sec.CFStringRef, key: sec.CFStringRef, comptime minimal: bool) sec.CFDictionaryRef {
    // Search query looks like
    //  kSecClass: type of password, e.g. kSecClassInternetPassword
    //  Attributes: attributes to search by. Availability depends on type, see https://developer.apple.com/documentation/security/item-class-keys-and-values#Item-class-values
    //  kSecMatchLimit: how many to fetch
    //  kSecReturnAttributes: bool wether to return attrs
    //  kSecReturnData: bool wether to return the data
    const len = comptime if (minimal) 3 else 5;
    var keys: [len]sec.CFTypeRef = undefined;
    var values: [len]sec.CFTypeRef = undefined;

    keys[0] = sec.kSecClass;
    values[0] = sec.kSecClassGenericPassword;

    keys[1] = sec.kSecAttrService;
    values[1] = service;

    keys[2] = sec.kSecAttrAccount;
    values[2] = key;

    if (!minimal) {
        keys[3] = sec.kSecMatchLimit;
        values[3] = sec.kSecMatchLimitOne;

        keys[4] = sec.kSecReturnData;
        values[4] = sec.kCFBooleanTrue;
    }

    const cf_attrs = sec.CFDictionaryCreate(
        null,
        &keys,
        &values,
        len,
        &sec.kCFTypeDictionaryKeyCallBacks,
        &sec.kCFTypeDictionaryValueCallBacks,
    );
    return cf_attrs;
}

fn makeCfCreateDict(service: sec.CFStringRef, key: sec.CFStringRef, value: sec.CFDataRef) sec.CFDictionaryRef {
    var keys: [4]sec.CFTypeRef = undefined;
    var values: [4]sec.CFTypeRef = undefined;

    keys[0] = sec.kSecClass;
    values[0] = sec.kSecClassGenericPassword;

    keys[1] = sec.kSecAttrService;
    values[1] = service;

    keys[2] = sec.kSecAttrAccount;
    values[2] = key;

    keys[3] = sec.kSecValueData;
    values[3] = value;

    const cf_dict = sec.CFDictionaryCreate(
        null,
        &keys,
        &values,
        4,
        &sec.kCFTypeDictionaryKeyCallBacks,
        &sec.kCFTypeDictionaryValueCallBacks,
    );
    return cf_dict;
}

const KeyChainGetError = error{ EntryNotFound, KeyChainReadError, CfStringCreationFailed };
fn _getItem(service: []const u8, key: []const u8, out: *sec.CFTypeRef) KeyChainGetError!sec.OSStatus {
    const cf_service = try makeCfString(service);
    defer sec.CFRelease(cf_service);

    const cf_key = try makeCfString(key);
    defer sec.CFRelease(cf_key);

    const cf_attrs = makeCfQueryDict(cf_service, cf_key, false);
    defer sec.CFRelease(cf_attrs);

    const status = sec.SecItemCopyMatching(cf_attrs, out);
    if (status == sec.errSecItemNotFound) return error.EntryNotFound;
    if (status != sec.errSecSuccess) return error.KeyChainReadError;
    return status;
}

const KeyChainBufferGetError = KeyChainGetError || error{BufferTooSmall};
pub fn get(service: []const u8, key: []const u8, out_buf: []u8) KeyChainBufferGetError![]u8 {
    var out: sec.CFTypeRef = undefined;
    _ = try _getItem(service, key, &out);
    defer if (out) |value| sec.CFRelease(value);

    const data: sec.CFDataRef = @ptrCast(out.?);
    const len: usize = @intCast(sec.CFDataGetLength(data));
    const ptr = sec.CFDataGetBytePtr(data);
    if (out_buf.len < len) return error.BufferTooSmall;
    @memcpy(out_buf[0..len], ptr[0..len]);
    return out_buf[0..len];
}

const KeyChainAllocGetError = KeyChainGetError || error{OutOfMemory};
pub fn getAlloc(gpa: std.mem.Allocator, service: []const u8, key: []const u8) KeyChainAllocGetError![]u8 {
    var out: sec.CFTypeRef = undefined;
    _ = try _getItem(service, key, &out);
    defer if (out) |value| sec.CFRelease(value);

    const data: sec.CFDataRef = @ptrCast(out.?);
    const len: usize = @intCast(sec.CFDataGetLength(data));
    const ptr = sec.CFDataGetBytePtr(data);
    const val = try gpa.dupe(u8, ptr[0..len]);
    return val;
}

const KeyChainUpdateError = error{ EntryNotFound, KeyChainUpdateError };
fn update(cf_service: sec.CFStringRef, cf_key: sec.CFStringRef, cf_value: sec.CFDataRef) KeyChainUpdateError!void {
    const query = makeCfQueryDict(cf_service, cf_key, true);
    defer sec.CFRelease(query);

    var keys: [1]sec.CFTypeRef = undefined;
    var values: [1]sec.CFTypeRef = undefined;

    keys[0] = sec.kSecValueData;
    values[0] = cf_value;

    const attr_dict = sec.CFDictionaryCreate(
        null,
        &keys,
        &values,
        1,
        &sec.kCFTypeDictionaryKeyCallBacks,
        &sec.kCFTypeDictionaryValueCallBacks,
    );
    defer sec.CFRelease(attr_dict);

    const status = sec.SecItemUpdate(query, attr_dict);
    if (status == sec.errSecItemNotFound) return error.EntryNotFound;
    if (status != sec.errSecSuccess) return error.KeyChainUpdateError;
}

const KeyChainWriteError = error{ KeyChainCreateError, KeyChainUpdateError, CfStringCreationFailed, CfDataCreationFailed };
pub fn set(service: []const u8, key: []const u8, value: []const u8) KeyChainWriteError!void {
    const cf_service = try makeCfString(service);
    defer sec.CFRelease(cf_service);

    const cf_key = try makeCfString(key);
    defer sec.CFRelease(cf_key);

    const cf_value = try makeCfData(value);
    defer sec.CFRelease(cf_value);

    return update(cf_service, cf_key, cf_value) catch |err| switch (err) {
        error.EntryNotFound => {
            const attr_dict = makeCfCreateDict(cf_service, cf_key, cf_value);
            defer sec.CFRelease(attr_dict);

            const status = sec.SecItemAdd(attr_dict, null);
            if (status != sec.errSecSuccess) return error.KeyChainCreateError;
        },
        error.KeyChainUpdateError => return error.KeyChainUpdateError,
    };
}

const KeyChainDeleteError = error{ EntryNotFound, KeyChainDeleteError, CfStringCreationFailed };
pub fn delete(service: []const u8, key: []const u8) KeyChainDeleteError!void {
    const cf_service = try makeCfString(service);
    defer sec.CFRelease(cf_service);

    const cf_key = try makeCfString(key);
    defer sec.CFRelease(cf_key);

    const query = makeCfQueryDict(cf_service, cf_key, true);
    defer sec.CFRelease(query);

    const status = sec.SecItemDelete(query);
    if (status == sec.errSecItemNotFound) return error.EntryNotFound;
    if (status != sec.errSecSuccess) return error.KeyChainDeleteError;
}
