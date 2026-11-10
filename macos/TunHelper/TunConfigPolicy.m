#import "TunShared.h"

static BOOL HexSecret(id secret) {
    return [secret isKindOfClass:NSString.class] && [secret length] == 64 &&
        [secret rangeOfCharacterFromSet:[[NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdefABCDEF"] invertedSet]].location == NSNotFound;
}

static BOOL SafeRelativePath(NSString *path) {
    if (path.length > 1024 || path.isAbsolutePath || [path hasPrefix:@"~"] ||
        [path containsString:@"\\"] || [path containsString:@":"] || [path containsString:@"\0"]) return NO;
    for (NSString *part in path.pathComponents) {
        if ([part isEqualToString:@".."] || [part isEqualToString:@"."]) return NO;
    }
    return YES;
}

static BOOL ValidateTree(id node, NSUInteger depth, NSString **error) {
    if (depth > 64) { *error = @"Configuration exceeds the nesting limit"; return NO; }
    if ([node isKindOfClass:NSDictionary.class]) {
        NSSet *forbidden = [NSSet setWithArray:@[@"script", @"command", @"exec", @"execute", @"plugin", @"plugin-opts",
            @"external-ui", @"external-ui-url", @"external-ui-name", @"external_ui", @"external_ui_download_url",
            @"external-controller-unix", @"external-controller-pipe", @"external-controller-tls", @"environment",
            @"proxy-providers"]];
        for (NSString *key in node) {
            if ([forbidden containsObject:key.lowercaseString]) {
                *error = [@"Unsupported privileged configuration field: " stringByAppendingString:key]; return NO;
            }
            id value = node[key];
            NSString *lower = key.lowercaseString;
            BOOL pathKey = [lower isEqualToString:@"path"] || [lower hasSuffix:@"file"] ||
                [lower hasSuffix:@"_path"] || [@[@"access", @"error", @"output", @"ca", @"private-key"] containsObject:lower];
            if (pathKey && [value isKindOfClass:NSString.class] && !SafeRelativePath(value)) {
                *error = [@"TUN file paths must stay inside the private session directory: " stringByAppendingString:key]; return NO;
            }
            if (!ValidateTree(value, depth + 1, error)) return NO;
        }
    } else if ([node isKindOfClass:NSArray.class]) {
        for (id value in node) if (!ValidateTree(value, depth + 1, error)) return NO;
    } else if ([node isKindOfClass:NSString.class]) {
        // Defense in depth for future/unknown file-bearing keys and ext:geo rules.
        NSString *text = node;
        if (text.isAbsolutePath || [text hasPrefix:@"~/"] ||
            [text containsString:@"../"] || [text containsString:@"..\\"] ||
            [text.lowercaseString hasPrefix:@"file:"] || [text.lowercaseString hasPrefix:@"unix:"] ||
            [text hasPrefix:@"ext:"] || [text containsString:@"\0"]) {
            *error = @"External filesystem references are not supported in privileged TUN configurations"; return NO;
        }
    }
    return YES;
}

static BOOL ValidateController(NSDictionary *controller, NSString *addressKey, NSString **error) {
    if (![controller isKindOfClass:NSDictionary.class]) { *error = @"Invalid controller configuration"; return NO; }
    NSString *address = controller[addressKey];
    if (!address || [address isEqual:@""]) return YES;
    if (![address isKindOfClass:NSString.class] || ![address hasPrefix:@"127.0.0.1:"] || !HexSecret(controller[@"secret"])) {
        *error = @"Privileged controllers require IPv4 loopback and a 256-bit secret"; return NO;
    }
    NSString *port = [address substringFromIndex:10];
    if (!port.length || [port rangeOfCharacterFromSet:NSCharacterSet.decimalDigitCharacterSet.invertedSet].location != NSNotFound ||
        port.integerValue < 1024 || port.integerValue > 65535) {
        *error = @"Invalid controller port"; return NO;
    }
    return YES;
}

NSDictionary *TunValidateConfiguration(NSDictionary *request, NSString **error) {
    NSString *core = request[@"core"];
    if (![@[@"sing-box", @"xray", @"mihomo"] containsObject:core]) { *error = @"Unsupported TUN core"; return nil; }
    NSDictionary *config = request[@"config"];
    if (![config isKindOfClass:NSDictionary.class] ||
        [NSJSONSerialization dataWithJSONObject:config options:0 error:NULL].length > 8 * 1024 * 1024) {
        *error = @"Invalid or oversized TUN configuration"; return nil;
    }
    if (!ValidateTree(config, 0, error)) return nil;
    if ([core isEqual:@"sing-box"]) {
        id experimental = config[@"experimental"];
        if (experimental && ![experimental isKindOfClass:NSDictionary.class]) { *error = @"Invalid experimental configuration"; return nil; }
        id controller = experimental[@"clash_api"];
        if (controller && !ValidateController(controller, @"external_controller", error)) return nil;
    } else if ([core isEqual:@"mihomo"]) {
        if (!ValidateController(config, @"external-controller", error)) return nil;
    } else {
        // Xray's statistics endpoint does not need the mutating HandlerService.
        id api = config[@"api"];
        if (api) { *error = @"Xray's privileged gRPC control API is not supported"; return nil; }
        id metrics = config[@"metrics"];
        if (metrics && (![metrics isKindOfClass:NSDictionary.class] ||
            ![metrics[@"listen"] isKindOfClass:NSString.class] || ![metrics[@"listen"] hasPrefix:@"127.0.0.1:"])) {
            *error = @"Xray metrics must bind to loopback"; return nil;
        }
    }
    return config;
}

NSDictionary<NSString *, NSData *> *TunDecodeAssets(NSDictionary *request, NSString **error) {
    NSDictionary *assets = request[@"assets"];
    if (![assets isKindOfClass:NSDictionary.class] || assets.count > 256) { *error = @"Invalid asset collection"; return nil; }
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    NSUInteger total = 0;
    NSCharacterSet *hex = [NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdef"];
    for (NSString *name in assets) {
        if (name.length != 69 || ![name hasSuffix:@".data"] ||
            [[name substringToIndex:64] rangeOfCharacterFromSet:hex.invertedSet].location != NSNotFound ||
            ![assets[name] isKindOfClass:NSString.class] || [assets[name] length] > 45 * 1024 * 1024) {
            *error = @"Invalid asset name or encoding"; return nil;
        }
        NSData *data = [[NSData alloc] initWithBase64EncodedString:assets[name] options:0];
        if (!data || data.length > 32 * 1024 * 1024 || total + data.length > 64 * 1024 * 1024) {
            *error = @"TUN assets exceed the size limit"; return nil;
        }
        total += data.length;
        result[name] = data;
    }
    return result;
}
