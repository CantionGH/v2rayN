#import "TunShared.h"
#import <SystemConfiguration/SystemConfiguration.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static NSURL *application;
static NSMutableSet *sessions;

static BOOL WritePrivateFile(NSURL *url, NSData *data) {
    int fd = open(url.fileSystemRepresentation, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return NO;
    const uint8_t *bytes = data.bytes;
    size_t remaining = data.length;
    BOOL ok = YES;
    while (remaining) {
        ssize_t written = write(fd, bytes, remaining);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) { ok = NO; break; }
        bytes += written;
        remaining -= (size_t)written;
    }
    if (close(fd) != 0) ok = NO;
    return ok;
}

@interface TunSession : NSObject
@property pid_t child;
@property int output;
@property int exitStatus;
@property NSURL *directory;
@property NSMutableData *log;
@property NSString *secret;
@property dispatch_source_t reader;
@property dispatch_source_t watcher;
- (NSDictionary *)handle:(NSDictionary *)request;
- (void)stop;
@end

@implementation TunSession
- (instancetype)init {
    if ((self = [super init])) { _output = -1; _log = [NSMutableData data]; }
    return self;
}

- (void)drainOutput {
    if (_output < 0) return;
    uint8_t buffer[16384];
    ssize_t count;
    NSUInteger drained = 0;
    while (drained < 256 * 1024 && (count = read(_output, buffer, sizeof(buffer))) > 0) {
        drained += (NSUInteger)count;
        if (_log.length + count > 512 * 1024) {
            // Bound memory even if the GUI stops polling or the core floods logs.
            [_log setLength:0];
        }
        [_log appendBytes:buffer length:(NSUInteger)count];
    }
}

- (void)finished:(int)status {
    _child = 0;
    _exitStatus = status;
    [self drainOutput];
    if (_watcher) { dispatch_source_cancel(_watcher); _watcher = nil; }
    if (_reader) { dispatch_source_cancel(_reader); _reader = nil; }
    if (_output >= 0) { close(_output); _output = -1; }
    if (_directory) {
        [NSFileManager.defaultManager removeItemAtURL:_directory error:NULL];
        _directory = nil;
    }
}

- (BOOL)running {
    if (!_child) return NO;
    int status = 0;
    pid_t result = waitpid(_child, &status, WNOHANG);
    if (result == _child || (result < 0 && errno == ECHILD)) [self finished:status];
    return _child != 0;
}

- (void)stop {
    if (![self running]) {
        if (_directory) [self finished:_exitStatus];
        return;
    }
    // All spawn/wait/kill operations are serialized on the daemon queue. We own
    // waitpid (not NSTask), so an exited child remains an unreaped zombie until
    // we check it. Its PID cannot be recycled between our check and kill.
    kill(_child, SIGTERM);
    for (NSUInteger i = 0; i < 120; i++) {
        if (![self running]) return;
        [self drainOutput];
        usleep(25000);
    }
    if (![self running]) return;
    kill(_child, SIGKILL);
    int status = 0;
    while (waitpid(_child, &status, 0) < 0 && errno == EINTR) { }
    [self finished:status];
}

- (NSDictionary *)start:(NSDictionary *)request {
    if (_child || _directory) return TunError(@"This connection already owns a core");
    NSUInteger running = 0;
    for (TunSession *session in sessions) if ([session running]) running++;
    if (running >= 2) return TunError(@"At most two privileged cores may run at once");
    NSString *error = nil;
    NSDictionary *config = TunValidateConfiguration(request, &error);
    NSDictionary *assets = config ? TunDecodeAssets(request, &error) : nil;
    if (!config || !assets) return TunError(error);
    NSString *core = request[@"core"];
    NSURL *executable = [application URLByAppendingPathComponent:[@"Contents/Library/TunCores/" stringByAppendingString:core]];
    NSString *identifier = [@"2dust.v2rayN.TunCore." stringByAppendingString:core];
    if (!TunValidateExecutable(executable, identifier)) return TunError(@"The bundled TUN core has an invalid signature or ownership. Reinstall the signed application.");

    const char *base = TUN_SESSION_ROOT;
    if ((mkdir(base, 0700) != 0 && errno != EEXIST) ||
        !TunRootOwnedPath([NSURL fileURLWithPath:@(base)])) return TunError(@"Unsafe TUN session directory");
    struct stat st;
    if (lstat(base, &st) != 0 || !S_ISDIR(st.st_mode) || (st.st_mode & 0777) != 0700) return TunError(@"Unsafe TUN session permissions");
    char pattern[] = TUN_SESSION_ROOT "/session.XXXXXX";
    if (!mkdtemp(pattern)) return TunError(@"Cannot create a private TUN session");
    _directory = [NSURL fileURLWithPath:@(pattern) isDirectory:YES];
    NSURL *assetDirectory = [_directory URLByAppendingPathComponent:@"assets" isDirectory:YES];
    if (mkdir(assetDirectory.fileSystemRepresentation, 0700) != 0) { [self stop]; return TunError(@"Cannot create asset directory"); }
    for (NSString *name in assets) {
        if (!WritePrivateFile([assetDirectory URLByAppendingPathComponent:name], assets[name])) {
            [self stop]; return TunError(@"Cannot snapshot TUN assets");
        }
    }
    // Only fixed, signed bundle resources are read with root privileges.
    for (NSString *name in @[@"geoip.dat", @"geosite.dat", @"Country.mmdb", @"geoip.metadb"]) {
        NSURL *source = [application URLByAppendingPathComponent:[@"Contents/Resources/TunAssets/" stringByAppendingString:name]];
        if ([NSFileManager.defaultManager fileExistsAtPath:source.path]) {
            if (!TunRootOwnedPath(source) || lstat(source.fileSystemRepresentation, &st) != 0 ||
                st.st_size > 128 * 1024 * 1024 || !S_ISREG(st.st_mode)) { [self stop]; return TunError(@"Invalid bundled asset"); }
            NSData *data = [NSData dataWithContentsOfURL:source];
            if (!data || !WritePrivateFile([_directory URLByAppendingPathComponent:name], data)) { [self stop]; return TunError(@"Cannot read bundled asset"); }
        }
    }
    NSURL *configURL = [_directory URLByAppendingPathComponent:@"config.json"];
    NSData *bytes = [NSJSONSerialization dataWithJSONObject:config options:0 error:NULL];
    if (!bytes || !WritePrivateFile(configURL, bytes)) { [self stop]; return TunError(@"Cannot snapshot TUN configuration"); }
    id experimental = config[@"experimental"];
    _secret = [core isEqual:@"mihomo"] ? config[@"secret"] : experimental[@"clash_api"][@"secret"];

    NSArray<NSString *> *arguments;
    if ([core isEqual:@"mihomo"]) arguments = @[executable.path, @"-f", configURL.path, @"-d", _directory.path];
    else if ([core isEqual:@"sing-box"]) arguments = @[executable.path, @"run", @"-c", configURL.path, @"--disable-color"];
    else arguments = @[executable.path, @"run", @"-c", configURL.path];
    // Do not inherit GUI/launchd environment variables or accept an environment
    // dictionary from the caller. In particular no DYLD_*, shell hooks or PATHs.
    NSArray<NSString *> *environment = @[@"PATH=/usr/bin:/bin:/usr/sbin:/sbin", @"LANG=en_US.UTF-8",
        [@"HOME=" stringByAppendingString:_directory.path], [@"TMPDIR=" stringByAppendingString:_directory.path],
        [@"XRAY_LOCATION_ASSET=" stringByAppendingString:_directory.path],
        [@"XRAY_LOCATION_CERT=" stringByAppendingString:_directory.path]];
    char *argv[arguments.count + 1], *envp[environment.count + 1];
    for (NSUInteger i = 0; i < arguments.count; i++) argv[i] = (char *)arguments[i].UTF8String;
    argv[arguments.count] = NULL;
    for (NSUInteger i = 0; i < environment.count; i++) envp[i] = (char *)environment[i].UTF8String;
    envp[environment.count] = NULL;

    int output[2];
    if (pipe(output) != 0) { [self stop]; return TunError(@"Cannot create core log pipe"); }
    int input = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (input < 0 || fcntl(output[0], F_SETFD, FD_CLOEXEC) < 0 || fcntl(output[1], F_SETFD, FD_CLOEXEC) < 0 ||
        fcntl(output[0], F_SETFL, O_NONBLOCK) < 0) {
        if (input >= 0) close(input);
        close(output[0]); close(output[1]); [self stop]; return TunError(@"Cannot configure core file descriptors");
    }
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attributes;
    int result = posix_spawn_file_actions_init(&actions);
    if (result != 0) {
        close(input); close(output[0]); close(output[1]); [self stop]; return TunError(@"Cannot initialize spawn actions");
    }
    result = posix_spawnattr_init(&attributes);
    if (result != 0) {
        posix_spawn_file_actions_destroy(&actions);
        close(input); close(output[0]); close(output[1]); [self stop]; return TunError(@"Cannot initialize spawn attributes");
    }
    sigset_t defaults, mask;
    sigemptyset(&mask);
    sigemptyset(&defaults);
    for (int sig = 1; sig < NSIG; sig++) {
        if (sig != SIGKILL && sig != SIGSTOP) sigaddset(&defaults, sig);
    }
    result = posix_spawn_file_actions_adddup2(&actions, input, STDIN_FILENO);
    if (!result) result = posix_spawn_file_actions_adddup2(&actions, output[1], STDOUT_FILENO);
    if (!result) result = posix_spawn_file_actions_adddup2(&actions, output[1], STDERR_FILENO);
    if (!result) result = posix_spawn_file_actions_addchdir_np(&actions, _directory.fileSystemRepresentation);
    if (!result) result = posix_spawnattr_setsigdefault(&attributes, &defaults);
    if (!result) result = posix_spawnattr_setsigmask(&attributes, &mask);
    if (!result) result = posix_spawnattr_setflags(&attributes,
        POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK);
    // No new process group: launchd must clean up the daemon's descendants when
    // the service is unloaded/crashes (AbandonProcessGroup is explicitly false).
    if (!result) result = posix_spawn(&_child, executable.fileSystemRepresentation, &actions, &attributes, argv, envp);
    posix_spawnattr_destroy(&attributes);
    posix_spawn_file_actions_destroy(&actions);
    close(input);
    close(output[1]);
    if (result != 0) { _child = 0; close(output[0]); [self stop]; return TunError(@"Failed to launch the bundled TUN core"); }
    _output = output[0];
    __weak TunSession *weakSelf = self;
    _reader = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, _output, 0, dispatch_get_main_queue());
    dispatch_source_set_event_handler(_reader, ^{ [weakSelf drainOutput]; });
    dispatch_resume(_reader);
    _watcher = dispatch_source_create(DISPATCH_SOURCE_TYPE_PROC, _child, DISPATCH_PROC_EXIT, dispatch_get_main_queue());
    dispatch_source_set_event_handler(_watcher, ^{ [weakSelf running]; });
    dispatch_resume(_watcher);
    return @{@"ok": @YES, @"running": @YES};
}

- (NSDictionary *)handle:(NSDictionary *)request {
    NSString *operation = request[@"operation"];
    if ([operation isEqual:@"start"]) {
        NSSet *allowed = [NSSet setWithArray:@[@"operation", @"core", @"config", @"assets"]];
        for (NSString *key in request) if (![allowed containsObject:key]) return TunError(@"Unknown start parameter");
        return [self start:request];
    }
    if (request.count != 1) return TunError(@"Control requests accept no arguments");
    if ([operation isEqual:@"stop"]) { [self stop]; return @{@"ok": @YES, @"running": @NO}; }
    if ([operation isEqual:@"status"]) {
        BOOL running = [self running];
        [self drainOutput];
        NSString *text = [[NSString alloc] initWithData:_log encoding:NSUTF8StringEncoding] ?: @"";
        if (_secret.length) text = [text stringByReplacingOccurrencesOfString:_secret withString:@"[redacted]"];
        // Retain a tail while running so a token split across polls is not exposed.
        NSUInteger keep = running ? MIN((NSUInteger)64, text.length) : 0;
        NSString *tail = [text substringFromIndex:text.length - keep];
        NSString *visible = [text substringToIndex:text.length - keep];
        _log = [[tail dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
        return @{@"ok": @YES, @"running": @(running), @"log": visible, @"exitStatus": @(_exitStatus)};
    }
    return TunError(@"Unknown TUN operation");
}
@end

static BOOL ConsoleUser(xpc_connection_t connection) {
    uid_t uid = 0;
    CFStringRef name = SCDynamicStoreCopyConsoleUser(NULL, &uid, NULL);
    if (name) CFRelease(name);
    return uid != 0 && uid == xpc_connection_get_euid(connection);
}

int main(void) {
    @autoreleasepool {
        umask(0077);
        application = TunApplicationURL();
        if (geteuid() != 0 || !TunValidateApplication(application)) return 1;
#ifdef V2RAYN_TUN_LOCAL_TRUST
        if (!TunValidateExecutable([application URLByAppendingPathComponent:@"Contents/Library/LaunchServices/v2rayn-tun-helper"], TUN_HELPER_ID)) return 1;
#endif
        sessions = [NSMutableSet set];
        xpc_connection_t listener = xpc_connection_create_mach_service(TUN_SERVICE,
            dispatch_get_main_queue(), XPC_CONNECTION_MACH_SERVICE_LISTENER);
        xpc_connection_set_event_handler(listener, ^(xpc_object_t peer) {
            if (xpc_get_type(peer) != XPC_TYPE_CONNECTION) return;
            xpc_connection_t connection = (xpc_connection_t)peer;
            if (!ConsoleUser(connection)) { xpc_connection_cancel(connection); return; }
            __block TunSession *session = nil;
            xpc_connection_set_target_queue(connection, dispatch_get_main_queue());
            xpc_connection_set_event_handler(connection, ^(xpc_object_t message) {
                @autoreleasepool {
                    if (xpc_get_type(message) == XPC_TYPE_ERROR) {
                        [session stop];
                        if (session) [sessions removeObject:session];
                        session = nil;
                        xpc_connection_set_event_handler(connection, ^(xpc_object_t ignored) {});
                        return;
                    }
                    if (xpc_get_type(message) != XPC_TYPE_DICTIONARY || !ConsoleUser(connection) ||
                        !TunValidateMessage(message, TUN_APP_ID)) {
                        [session stop]; xpc_connection_cancel(connection); return;
                    }
                    if (!session) {
                        if (sessions.count >= 16) { xpc_connection_cancel(connection); return; }
                        session = [TunSession new];
                        [sessions addObject:session];
                    }
                    size_t length = 0;
                    const void *bytes = xpc_dictionary_get_data(message, "json", &length);
                    NSDictionary *request = TunDecodeRequest(bytes, length);
                    NSDictionary *response;
                    @try { response = request ? [session handle:request] : TunError(@"Invalid TUN request"); }
                    @catch (NSException *exception) { [session stop]; response = TunError(@"Malformed TUN request"); }
                    xpc_object_t reply = xpc_dictionary_create_reply(message);
                    if (!reply) { [session stop]; xpc_connection_cancel(connection); return; }
                    char *json = TunCopyJSON(response);
                    if (!json) { [session stop]; xpc_connection_cancel(connection); return; }
                    xpc_dictionary_set_data(reply, "json", json, strlen(json));
                    free(json);
                    xpc_connection_send_message(connection, reply);
                }
            });
            xpc_connection_activate(connection);
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
                if (!session) xpc_connection_cancel(connection);
            });
        });
        xpc_connection_activate(listener);
        signal(SIGTERM, SIG_IGN);
        dispatch_source_t shutdown = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGTERM, 0, dispatch_get_main_queue());
        dispatch_source_set_event_handler(shutdown, ^{
            for (TunSession *session in sessions) [session stop];
            exit(0);
        });
        dispatch_resume(shutdown);
        dispatch_main();
    }
}
