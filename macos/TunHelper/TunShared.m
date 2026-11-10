#import "TunShared.h"
#include <sys/stat.h>
#include <unistd.h>
#include <mach-o/dyld.h>

static NSDictionary *SigningInfo(SecCodeRef code, SecCSFlags flags) {
    CFDictionaryRef info = NULL;
    if (SecCodeCopySigningInformation((SecStaticCodeRef)code, flags, &info) != errSecSuccess) return nil;
    return CFBridgingRelease(info);
}

NSString *TunTeamIdentifier(void) {
    SecCodeRef code = NULL;
    if (SecCodeCopySelf(kSecCSDefaultFlags, &code) != errSecSuccess) return nil;
    NSString *team = SigningInfo(code, kSecCSSigningInformation)[(__bridge NSString *)kSecCodeInfoTeamIdentifier];
    CFRelease(code);
    if (![team isKindOfClass:NSString.class] || team.length != 10 ||
        [team rangeOfCharacterFromSet:[[NSCharacterSet characterSetWithCharactersInString:@"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"] invertedSet]].location != NSNotFound) return nil;
    return team;
}

static SecRequirementRef Requirement(NSString *identifier) {
    NSString *team = TunTeamIdentifier();
    if (!team) return NULL; // Unsigned/ad-hoc builds cannot authorize root operations.
    NSString *text = [NSString stringWithFormat:
        @"anchor apple generic and identifier \"%@\" and certificate leaf[subject.OU] = \"%@\"", identifier, team];
    SecRequirementRef requirement = NULL;
    if (SecRequirementCreateWithString((__bridge CFStringRef)text, kSecCSDefaultFlags, &requirement) != errSecSuccess) return NULL;
    return requirement;
}

BOOL TunValidateMessage(xpc_object_t message, NSString *identifier) {
    SecCodeRef code = NULL;
    // This public API uses the MESSAGE's audit token, not a recyclable PID or a
    // private NSXPCConnection property. Revalidate every request and every reply.
    if (SecCodeCreateWithXPCMessage(message, kSecCSDefaultFlags, &code) != errSecSuccess) return NO;
    SecRequirementRef requirement = Requirement(identifier);
    BOOL valid = requirement && SecCodeCheckValidity(code, kSecCSDefaultFlags, requirement) == errSecSuccess;
    NSDictionary *info = valid ? SigningInfo(code, kSecCSDynamicInformation | kSecCSSigningInformation) : nil;
    uint32_t flags = [info[(__bridge NSString *)kSecCodeInfoStatus] unsignedIntValue];
    NSDictionary *entitlements = info[(__bridge NSString *)kSecCodeInfoEntitlementsDict];
    // Hardened runtime + library validation; no debugger or DYLD injection escape.
    const uint32_t runtime = 0x10000, debugged = 0x10000000;
    valid = valid && (flags & runtime) && !(flags & debugged)
        && ![entitlements[@"com.apple.security.get-task-allow"] boolValue]
        && ![entitlements[@"com.apple.security.cs.disable-library-validation"] boolValue]
        && ![entitlements[@"com.apple.security.cs.allow-dyld-environment-variables"] boolValue]
        && ![entitlements[@"com.apple.security.cs.allow-jit"] boolValue]
        && ![entitlements[@"com.apple.security.cs.allow-unsigned-executable-memory"] boolValue];
    if (requirement) CFRelease(requirement);
    CFRelease(code);
    return valid;
}

BOOL TunRootOwnedPath(NSURL *url) {
    NSString *path = url.path.stringByStandardizingPath;
    if (![path hasPrefix:@"/"]) return NO;
    while (YES) {
        struct stat st;
        // Reject symlinks, non-root owners, and group/other-writable ancestors.
        if (lstat(path.fileSystemRepresentation, &st) != 0 || S_ISLNK(st.st_mode)
            || st.st_uid != 0 || (st.st_mode & 0022)) return NO;
        if ([path isEqualToString:@"/"]) return YES;
        path = path.stringByDeletingLastPathComponent;
    }
}

BOOL TunValidateExecutable(NSURL *url, NSString *identifier) {
    if (!TunRootOwnedPath(url)) return NO;
    SecStaticCodeRef code = NULL;
    if (SecStaticCodeCreateWithPath((__bridge CFURLRef)url, kSecCSDefaultFlags, &code) != errSecSuccess) return NO;
    SecRequirementRef requirement = Requirement(identifier);
    BOOL valid = requirement && SecStaticCodeCheckValidity(code,
        kSecCSStrictValidate | kSecCSCheckAllArchitectures, requirement) == errSecSuccess;
    if (requirement) CFRelease(requirement);
    CFRelease(code);
    return valid;
}

NSURL *TunApplicationURL(void) {
    // A standalone launch daemon need not have the application's mainBundle.
    // Derive the enclosing bundle from this process's actual executable instead.
    uint32_t length = 0;
    _NSGetExecutablePath(NULL, &length);
    if (!length || length > 1024 * 1024) return nil;
    char *path = malloc(length);
    if (!path) return nil;
    int result = _NSGetExecutablePath(path, &length);
    NSURL *url = result == 0 ? [NSURL fileURLWithPath:@(path)] : nil;
    free(path);
    for (NSUInteger i = 0; i < 8 && url.path.length > 1; i++, url = url.URLByDeletingLastPathComponent) {
        if ([url.pathExtension isEqualToString:@"app"]) return url.URLByResolvingSymlinksInPath;
    }
    return nil;
}

BOOL TunValidateApplication(NSURL *app) {
    // /Applications can be group-admin writable. Use the installer's protected
    // location so an unprivileged admin cannot swap an ancestor after validation.
    if (!app || ![app.URLByDeletingLastPathComponent.path isEqualToString:@"/Library/Application Support/v2rayN"]
        || !TunValidateExecutable(app, TUN_APP_ID)) return NO;
    if (![NSFileManager.defaultManager fileExistsAtPath:
        [app URLByAppendingPathComponent:@"Contents/MacOS/v2rayN.NativeAOT"].path]) return NO;
    // Check every bundle entry's ownership too. A signed root-owned container
    // must not contain user-writable native libraries, managed assemblies or data.
    __block BOOL failed = NO;
    NSDirectoryEnumerator *entries = [NSFileManager.defaultManager enumeratorAtURL:app
        includingPropertiesForKeys:nil options:0 errorHandler:^BOOL(NSURL *url, NSError *error) { failed = YES; return NO; }];
    if (!entries) return NO;
    for (NSURL *entry in entries) {
        if (!TunRootOwnedPath(entry)) return NO;
    }
    return !failed;
}

NSDictionary *TunError(NSString *message) { return @{@"ok": @NO, @"error": message ?: @"TUN service error"}; }

char *TunCopyJSON(NSDictionary *dictionary) {
    NSData *data = [NSJSONSerialization dataWithJSONObject:dictionary options:0 error:NULL];
    if (!data) return strdup("{\"ok\":false,\"error\":\"Invalid service response\"}");
    char *copy = malloc(data.length + 1);
    if (!copy) return NULL;
    memcpy(copy, data.bytes, data.length);
    copy[data.length] = 0;
    return copy;
}

NSDictionary *TunDecodeRequest(const void *bytes, size_t length) {
    if (!bytes || !length || length > TUN_MAX_REQUEST) return nil;
    id value = [NSJSONSerialization JSONObjectWithData:[NSData dataWithBytes:bytes length:length]
        options:NSJSONReadingMutableContainers error:NULL];
    return [value isKindOfClass:NSDictionary.class] ? value : nil;
}
