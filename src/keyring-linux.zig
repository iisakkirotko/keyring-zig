const std = @import("std");

pub const KeyringLinux = @This();

pub fn get(service: []const u8, key: []const u8, out_buf: []u8) ![]u8 {
    _ = out_buf; // autofix
    _ = service; // autofix
    _ = key; // autofix
}

pub fn getAlloc(gpa: std.mem.Allocator, service: []const u8, key: []const u8) ![]u8 {
    _ = gpa; // autofix
    _ = service; // autofix
    _ = key; // autofix
}

pub fn set(service: []const u8, key: []const u8, value: []const u8) !void {
    _ = service; // autofix
    _ = key; // autofix
    _ = value; // autofix
}

pub fn delete(service: []const u8, key: []const u8) !void {
    _ = service; // autofix
    _ = key; // autofix
}
