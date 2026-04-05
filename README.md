# keyring-zig

Small cross-platform keyring access for Zig.

`keyring-zig` provides a minimal API for storing, reading, updating, and deleting secrets in the operating system credential store.

## Status

- macOS: supported
- Windows: supported
- Linux: planned, not implemented yet

## API

```zig
pub fn get(service: []const u8, key: []const u8, out_buf: []u8) ![]u8
pub fn getAlloc(gpa: std.mem.Allocator, service: []const u8, key: []const u8) ![]u8
pub fn set(service: []const u8, key: []const u8, value: []const u8) !void
pub fn delete(service: []const u8, key: []const u8) !void
```

## Example

```zig
const std = @import("std");
const keyring = @import("keyring_zig");

pub fn main() !void {
    try keyring.set("my-app", "api-token", "secret-value");

    const value = try keyring.getAlloc(std.heap.page_allocator, "my-app", "api-token");
    defer std.heap.page_allocator.free(value);

    std.debug.print("stored value: {s}\n", .{value});
}
```

## Development

Run the test suite with:

```sh
zig build test
```

Tests exercise the public API against the platform credential store.
