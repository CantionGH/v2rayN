#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <xpc/xpc.h>
#include <stdlib.h>
#include <string.h>

#define TUN_SERVICE "2dust.v2rayN.TunHelper"
#define TUN_APP_ID @"2dust.v2rayN"
#define TUN_HELPER_ID @"2dust.v2rayN.TunHelper"
#define TUN_PLIST @"2dust.v2rayN.TunHelper.plist"
#define TUN_MAX_REQUEST (96 * 1024 * 1024)

NSString *TunTeamIdentifier(void);
BOOL TunValidateMessage(xpc_object_t message, NSString *identifier);
BOOL TunValidateExecutable(NSURL *url, NSString *identifier);
BOOL TunRootOwnedPath(NSURL *url);
NSURL *TunApplicationURL(void);
BOOL TunValidateApplication(NSURL *app);
NSDictionary *TunError(NSString *message);
char *TunCopyJSON(NSDictionary *dictionary);
NSDictionary *TunDecodeRequest(const void *bytes, size_t length);

// Returns a normalized, independently validated configuration or nil. Only bytes
// are accepted: no caller-supplied executable, argv, environment, PID or file URL.
NSDictionary *TunValidateConfiguration(NSDictionary *request, NSString **error);
NSDictionary<NSString *, NSData *> *TunDecodeAssets(NSDictionary *request, NSString **error);
