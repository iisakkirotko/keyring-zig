const std = @import("std");

fn linkPlatformDeps(module: *std.Build.Module, os_tag: std.Target.Os.Tag) void {
    switch (os_tag) {
        .macos => {
            module.linkFramework("Security", .{});
            module.linkFramework("CoreFoundation", .{});
        },
        .windows => {
            module.linkSystemLibrary("Advapi32", .{});
        },
        .linux => {
            module.link_libc = true;
            module.linkSystemLibrary("libsecret-1", .{});
            module.linkSystemLibrary("glib-2.0", .{});
        },
        else => {},
    }
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});

    const mod = b.addModule("keyring_zig", .{
        .root_source_file = b.path("src/keyring.zig"),
        .target = target,
    });
    linkPlatformDeps(mod, target.result.os.tag);

    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/keyring.zig"),
        .target = target,
    });

    const mod_tests = b.addTest(.{
        .root_module = test_mod,
    });
    linkPlatformDeps(test_mod, target.result.os.tag);

    const run_mod_tests = b.addRunArtifact(mod_tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
}
