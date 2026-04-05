const std = @import("std");
const builtin = @import("builtin");

const os_keyring = switch (builtin.os.tag) {
    .macos => @import("keyring-macos.zig"),
    .linux => @import("keyring-linux.zig"),
    .windows => @import("keyring-windows.zig"),
    else => @compileError("Unsupported OS"),
};

pub fn get(service: []const u8, key: []const u8, out_buf: []u8) ![]u8 {
    return os_keyring.get(service, key, out_buf);
}

pub fn getAlloc(gpa: std.mem.Allocator, service: []const u8, key: []const u8) ![]u8 {
    return os_keyring.getAlloc(gpa, service, key);
}

pub fn set(service: []const u8, key: []const u8, value: []const u8) !void {
    return os_keyring.set(service, key, value);
}

pub fn delete(service: []const u8, key: []const u8) !void {
    return os_keyring.delete(service, key);
}

var next_test_id: u64 = 0;

fn randomTestName(comptime prefix: []const u8) [prefix.len + 16]u8 {
    var buf: [prefix.len + 16]u8 = undefined;
    next_test_id += 1;
    const suffix = next_test_id;
    _ = std.fmt.bufPrint(&buf, "{s}{x:0>16}", .{ prefix, suffix }) catch unreachable;
    return buf;
}

test "get missing entry fails" {
    const service = randomTestName("keyring-zig-missing-service-");
    const key = randomTestName("keyring-zig-missing-key-");

    var buf: [64]u8 = undefined;
    try std.testing.expectError(error.EntryNotFound, get(&service, &key, &buf));
}

test "set then get works" {
    const service = randomTestName("keyring-zig-create-service-");
    const key = randomTestName("keyring-zig-create-key-");
    const value = "first-value";

    try set(&service, &key, value);
    defer delete(&service, &key) catch {};

    const got = try getAlloc(std.testing.allocator, &service, &key);
    defer std.testing.allocator.free(got);

    try std.testing.expectEqualSlices(u8, value, got);
}

test "set then modify works" {
    const service = randomTestName("keyring-zig-update-service-");
    const key = randomTestName("keyring-zig-update-key-");
    const first = "first-value";
    const second = "second-value";

    try set(&service, &key, first);
    defer delete(&service, &key) catch {};

    try set(&service, &key, second);

    const got = try getAlloc(std.testing.allocator, &service, &key);
    defer std.testing.allocator.free(got);

    try std.testing.expectEqualSlices(u8, second, got);
}
