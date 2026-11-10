#import "TunShared.h"

#ifdef V2RAYN_TUN_LOCAL_TRUST
#import <CommonCrypto/CommonDigest.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

static const NSUInteger MaxManifestBytes = 2 * 1024 * 1024;

static NSDictionary<NSString *, NSString *> *ExecutablePaths(void) {
    return @{
        TUN_APP_ID: @"Contents/MacOS/v2rayN",
        TUN_HELPER_ID: @"Contents/Library/LaunchServices/v2rayn-tun-helper",
        @"2dust.v2rayN.TunTrustTool": @"Contents/Library/LaunchServices/v2rayn-tun-trust",
        @"2dust.v2rayN.TunCore.sing-box": @"Contents/Library/TunCores/sing-box",
        @"2dust.v2rayN.TunCore.xray": @"Contents/Library/TunCores/xray",
        @"2dust.v2rayN.TunCore.mihomo": @"Contents/Library/TunCores/mihomo",
    };
}

static NSString *Hex(NSData *bytes) {
    const unsigned char *data = bytes.bytes;
    NSMutableString *result = [NSMutableString stringWithCapacity:bytes.length * 2];
    for (NSUInteger i = 0; i < bytes.length; i++) [result appendFormat:@"%02x", data[i]];
    return result;
}

static BOOL IsHex(id value, NSUInteger length) {
    return [value isKindOfClass:NSString.class] && [value length] == length &&
        [value rangeOfCharacterFromSet:[[NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdef"] invertedSet]].location == NSNotFound;
}

static BOOL RelativePath(id value) {
    if (![value isKindOfClass:NSString.class] || ![value length] || [value length] > 4096 ||
        [value isAbsolutePath] || [value containsString:@"\\"] || [value containsString:@"\0"]) return NO;
    for (NSString *component in [value componentsSeparatedByString:@"/"]) {
        if (!component.length || [component isEqual:@"."] || [component isEqual:@".."]) return NO;
    }
    return [value hasPrefix:@"Contents/"];
}

BOOL TunLocalManifestSchema(NSDictionary *manifest) {
    if (![manifest isKindOfClass:NSDictionary.class] || ![manifest[@"version"] isEqual:@1] ||
        ![manifest[@"mode"] isEqual:@"local-cdhash-v1"] ||
        ![manifest[@"application"] isEqual:TUN_INSTALL_PARENT @"/v2rayN.app"]) return NO;
    NSDictionary *files = manifest[@"files"], *executables = manifest[@"executables"];
    if (![files isKindOfClass:NSDictionary.class] || !files.count || files.count > 8192 ||
        ![executables isKindOfClass:NSDictionary.class] || executables.count != ExecutablePaths().count) return NO;
    for (NSString *path in files) if (!RelativePath(path) || !IsHex(files[path], 64)) return NO;
    for (NSString *identifier in ExecutablePaths()) {
        NSDictionary *entry = executables[identifier];
        if (![entry isKindOfClass:NSDictionary.class] || ![entry[@"path"] isEqual:ExecutablePaths()[identifier]] ||
            !files[entry[@"path"]]) return NO;
        NSArray *hashes = entry[@"cdhashes"];
        if (![hashes isKindOfClass:NSArray.class] || !hashes.count || hashes.count > 8) return NO;
        for (id hash in hashes) if (!IsHex(hash, 40)) return NO;
    }
    return YES;
}

static NSString *FileHash(NSURL *url) {
    if (!TunRootOwnedPath(url)) return nil;
    int fd = open(url.fileSystemRepresentation, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return nil;
    struct stat before = {0}, after = {0};
    BOOL ok = fstat(fd, &before) == 0 && S_ISREG(before.st_mode) && before.st_uid == 0 &&
        !(before.st_mode & 0022) && before.st_nlink == 1 && before.st_size <= 2LL * 1024 * 1024 * 1024;
    CC_SHA256_CTX context;
    CC_SHA256_Init(&context);
    unsigned char buffer[65536], digest[CC_SHA256_DIGEST_LENGTH];
    ssize_t count;
    while (ok) {
        count = read(fd, buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) ok = NO;
        if (count <= 0) break;
        CC_SHA256_Update(&context, buffer, (CC_LONG)count);
    }
    if (fstat(fd, &after) != 0 || before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
        before.st_size != after.st_size || before.st_mtimespec.tv_sec != after.st_mtimespec.tv_sec ||
        before.st_mtimespec.tv_nsec != after.st_mtimespec.tv_nsec) ok = NO;
    close(fd);
    if (!ok) return nil;
    CC_SHA256_Final(digest, &context);
    return Hex([NSData dataWithBytes:digest length:sizeof(digest)]);
}

NSDictionary *TunLocalReadManifest(void) {
    NSURL *url = [NSURL fileURLWithPath:TUN_TRUST_FILE];
    if (!TunRootOwnedPath(url)) return nil;
    int fd = open(url.fileSystemRepresentation, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return nil;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != 0 || (st.st_mode & 0022) ||
        st.st_nlink != 1 || st.st_size <= 0 || st.st_size > (off_t)MaxManifestBytes) { close(fd); return nil; }
    NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)st.st_size];
    size_t used = 0;
    while (used < data.length) {
        ssize_t count = read(fd, (uint8_t *)data.mutableBytes + used, data.length - used);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { close(fd); return nil; }
        used += (size_t)count;
    }
    close(fd);
    id manifest = [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListImmutable format:NULL error:NULL];
    return TunLocalManifestSchema(manifest) ? manifest : nil;
}

SecRequirementRef TunLocalRequirement(NSString *identifier) {
    NSDictionary *manifest = TunLocalReadManifest();
    if (!manifest || !ExecutablePaths()[identifier]) return NULL;
    NSMutableArray *pins = [NSMutableArray array];
    for (NSString *hash in manifest[@"executables"][identifier][@"cdhashes"]) {
        [pins addObject:[NSString stringWithFormat:@"cdhash H\"%@\"", hash]];
    }
    NSString *text = [NSString stringWithFormat:@"identifier \"%@\" and (%@)", identifier, [pins componentsJoinedByString:@" or "]];
    SecRequirementRef requirement = NULL;
    if (SecRequirementCreateWithString((__bridge CFStringRef)text, kSecCSDefaultFlags, &requirement) != errSecSuccess) return NULL;
    return requirement;
}

BOOL TunLocalValidateOrigin(NSDictionary *info, NSString *identifier) {
    NSString *relative = ExecutablePaths()[identifier];
    if (!relative || ![info[(__bridge NSString *)kSecCodeInfoIdentifier] isEqual:identifier]) return NO;
    NSURL *actual = info[(__bridge NSString *)kSecCodeInfoMainExecutable];
    NSURL *expected = [[NSURL fileURLWithPath:TUN_INSTALL_PARENT @"/v2rayN.app"] URLByAppendingPathComponent:relative];
    return [actual isKindOfClass:NSURL.class] && [actual.path isEqual:expected.path] && TunRootOwnedPath(actual);
}

BOOL TunLocalValidateFile(NSURL *url, NSString *identifier) {
    NSDictionary *manifest = TunLocalReadManifest();
    NSString *relative = ExecutablePaths()[identifier];
    // A bundle SecStaticCode validates the GUI, while its pinned bytes are the
    // main executable. Other roles are fixed standalone binaries.
    NSURL *file = [identifier isEqual:TUN_APP_ID] ? [url URLByAppendingPathComponent:relative] : url;
    NSString *expected = [TUN_INSTALL_PARENT @"/v2rayN.app/" stringByAppendingString:relative ?: @""];
    return manifest && relative && [file.path isEqual:expected] &&
        [FileHash(file) isEqual:manifest[@"files"][relative]];
}

static NSDictionary *Inventory(NSURL *app) {
    if (![app.path isEqual:TUN_INSTALL_PARENT @"/v2rayN.app"] || !TunRootOwnedPath(app)) return nil;
    NSMutableDictionary *files = [NSMutableDictionary dictionary];
    __block BOOL failed = NO;
    NSDirectoryEnumerator *entries = [NSFileManager.defaultManager enumeratorAtURL:app includingPropertiesForKeys:nil
        options:0 errorHandler:^BOOL(NSURL *url, NSError *error) { failed = YES; return NO; }];
    if (!entries) return nil;
    for (NSURL *url in entries) {
        struct stat st;
        if (!TunRootOwnedPath(url) || lstat(url.fileSystemRepresentation, &st) != 0) return nil;
        if (S_ISDIR(st.st_mode)) continue;
        if (!S_ISREG(st.st_mode) || files.count >= 8192) return nil;
        NSString *relative = [url.path substringFromIndex:app.path.length + 1];
        NSString *hash = FileHash(url);
        if (!RelativePath(relative) || !hash) return nil;
        files[relative] = hash;
    }
    return failed ? nil : files;
}

BOOL TunLocalVerifyInventory(NSURL *app) {
    NSDictionary *manifest = TunLocalReadManifest();
    return manifest && [Inventory(app) isEqual:manifest[@"files"]];
}

NSDictionary *TunLocalCreateManifest(NSURL *app, NSString **error) {
    // Enrollment is an installer/root action, never an XPC operation. Compute
    // pins from the installed protected bytes, not a caller-supplied manifest.
    if (geteuid() != 0) { *error = @"Local trust enrollment requires the system installer/root"; return nil; }
    NSDictionary *files = Inventory(app);
    if (!files || !files[@"Contents/MacOS/v2rayN.NativeAOT"]) { *error = @"Unsafe or incomplete installed NativeAOT bundle"; return nil; }
    NSMutableDictionary *executables = [NSMutableDictionary dictionary];
    for (NSString *identifier in ExecutablePaths()) {
        NSString *relative = ExecutablePaths()[identifier];
        NSURL *url = [identifier isEqual:TUN_APP_ID] ? app : [app URLByAppendingPathComponent:relative];
        SecStaticCodeRef code = NULL;
        if (SecStaticCodeCreateWithPath((__bridge CFURLRef)url, kSecCSDefaultFlags, &code) != errSecSuccess) { *error = @"Missing ad-hoc code signature"; return nil; }
        BOOL valid = SecStaticCodeCheckValidity(code, kSecCSStrictValidate | kSecCSCheckAllArchitectures, NULL) == errSecSuccess;
        CFDictionaryRef raw = NULL;
        if (SecCodeCopySigningInformation(code, kSecCSSigningInformation, &raw) != errSecSuccess) valid = NO;
        NSDictionary *info = CFBridgingRelease(raw);
        CFRelease(code);
        uint32_t flags = [info[(__bridge NSString *)kSecCodeInfoFlags] unsignedIntValue];
        NSDictionary *entitlements = info[(__bridge NSString *)kSecCodeInfoEntitlementsDict];
        valid = valid && (flags & 0x2) && (flags & 0x10000) &&
            [info[(__bridge NSString *)kSecCodeInfoIdentifier] isEqual:identifier] &&
            ![entitlements[@"com.apple.security.get-task-allow"] boolValue] &&
            ![entitlements[@"com.apple.security.cs.allow-jit"] boolValue] &&
            ![entitlements[@"com.apple.security.cs.allow-unsigned-executable-memory"] boolValue] &&
            ![entitlements[@"com.apple.security.cs.allow-dyld-environment-variables"] boolValue] &&
            ![entitlements[@"com.apple.security.cs.disable-executable-page-protection"] boolValue] &&
            ([identifier isEqual:TUN_APP_ID] || ![entitlements[@"com.apple.security.cs.disable-library-validation"] boolValue]);
        NSMutableArray *hashes = [NSMutableArray array];
        for (NSData *hash in info[(__bridge NSString *)kSecCodeInfoCdHashes]) {
            if (![hash isKindOfClass:NSData.class] || hash.length != 20) { valid = NO; break; }
            [hashes addObject:Hex(hash)];
        }
        if (!valid || !hashes.count) { *error = [@"Unsafe ad-hoc executable or entitlements: " stringByAppendingString:identifier]; return nil; }
        executables[identifier] = @{@"path": relative, @"cdhashes": hashes};
    }
    NSDictionary *manifest = @{@"version": @1, @"mode": @"local-cdhash-v1",
        @"application": app.path, @"files": files, @"executables": executables};
    if (!TunLocalManifestSchema(manifest)) { *error = @"Invalid local trust manifest"; return nil; }
    return manifest;
}

BOOL TunLocalWriteManifest(NSDictionary *manifest, NSString **error) {
    if (geteuid() != 0 || !TunLocalManifestSchema(manifest) ||
        !TunRootOwnedPath([NSURL fileURLWithPath:TUN_INSTALL_PARENT])) { *error = @"Cannot enroll local trust"; return NO; }
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:manifest format:NSPropertyListXMLFormat_v1_0 options:0 error:NULL];
    if (!data || data.length > MaxManifestBytes) { *error = @"Oversized local trust manifest"; return NO; }
    NSString *temporary = [TUN_INSTALL_PARENT stringByAppendingFormat:@"/.trust.%@.tmp", NSUUID.UUID.UUIDString];
    int fd = open(temporary.fileSystemRepresentation, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) { *error = @"Cannot create local trust file"; return NO; }
    const uint8_t *bytes = data.bytes;
    NSUInteger remaining = data.length;
    BOOL ok = YES;
    while (remaining) {
        ssize_t count = write(fd, bytes, remaining);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { ok = NO; break; }
        remaining -= (NSUInteger)count;
        bytes += count;
    }
    if (fchmod(fd, 0644) != 0 || fsync(fd) != 0) ok = NO;
    if (close(fd) != 0) ok = NO;
    if (ok && rename(temporary.fileSystemRepresentation, [TUN_TRUST_FILE fileSystemRepresentation]) == 0) return YES;
    unlink(temporary.fileSystemRepresentation);
    *error = @"Cannot commit local trust manifest";
    return NO;
}
#endif
