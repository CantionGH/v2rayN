#import "../TunShared.h"

static NSUInteger checks;
static void Expect(BOOL condition, NSString *name) {
    checks++;
    if (!condition) { fprintf(stderr, "FAIL: %s\n", name.UTF8String); exit(1); }
}

static BOOL Accept(NSString *core, NSDictionary *config) {
    NSString *error = nil;
    return TunValidateConfiguration(@{@"core": core, @"config": config}, &error) != nil;
}

int main(void) {
    @autoreleasepool {
        NSString *secret = [@"A" stringByPaddingToLength:64 withString:@"A" startingAtIndex:0];
        Expect(Accept(@"sing-box", @{@"inbounds": @[@{@"type": @"tun"}]}), @"sing-box configuration");
        Expect(Accept(@"xray", @{@"metrics": @{@"listen": @"127.0.0.1:19091"}}), @"loopback Xray metrics");
        Expect(Accept(@"mihomo", @{@"external-controller": @"127.0.0.1:19090", @"secret": secret}), @"authenticated loopback controller");
        Expect(!Accept(@"bash", @{}), @"no arbitrary executable");
        Expect(!Accept(@"xray", @{@"api": @{@"services": @[@"HandlerService"]}}), @"no unauthenticated mutating gRPC API");
        Expect(!Accept(@"mihomo", @{@"external-controller": @"0.0.0.0:19090", @"secret": secret}), @"no remote privileged controller");
        Expect(!Accept(@"mihomo", @{@"external-controller": @"127.0.0.1:19090"}), @"no secretless controller");
        Expect(!Accept(@"mihomo", @{@"external-controller": @"127.0.0.1:abc", @"secret": secret}), @"no malformed controller port");
        for (NSString *path in @[@"/etc/sudoers", @"../outside", @"a/../../outside", @"~/outside", @"file:///etc/shadow", @"unix:///var/run/socket"]) {
            Expect(!Accept(@"sing-box", @{@"path": path}), [@"reject path: " stringByAppendingString:path]);
        }
        Expect(Accept(@"sing-box", @{@"path": @"assets/rules.data"}), @"private relative asset");
        Expect(!Accept(@"xray", @{@"domains": @[@"ext:/etc/shadow:tag"]}), @"no external geo files");
        for (NSString *key in @[@"script", @"command", @"plugin", @"external-ui", @"external-controller-unix", @"environment", @"proxy-providers"]) {
            Expect(!Accept(@"mihomo", @{key: @"anything"}), [@"reject field: " stringByAppendingString:key]);
        }
        NSString *error = nil;
        NSString *name = [[@"0" stringByPaddingToLength:64 withString:@"0" startingAtIndex:0] stringByAppendingString:@".data"];
        Expect(TunDecodeAssets(@{@"assets": @{name: @"AQIDBA=="}}, &error).count == 1, @"bounded data assets");
        Expect(!TunDecodeAssets(@{@"assets": @{@"../config.json": @"AQ=="}}, &error), @"no asset traversal");
        Expect(!TunDecodeAssets(@{@"assets": @{name: @"invalid!!!"}}, &error), @"reject malformed base64");
        Expect(!TunDecodeRequest("{}", TUN_MAX_REQUEST + 1), @"request limit checked before copying");
        Expect(!TunRootOwnedPath([NSURL fileURLWithPath:@"/tmp"]), @"no symlink/world-writable ancestors");
        xpc_object_t fake = xpc_dictionary_create(NULL, NULL, 0);
        Expect(!TunValidateMessage(fake, TUN_APP_ID), @"no forged PID/message without an audit token");
        printf("PASS: %lu native TUN policy checks\n", (unsigned long)checks);
        return 0;
    }
}
