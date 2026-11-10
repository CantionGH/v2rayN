#import "TunShared.h"
#import <ServiceManagement/ServiceManagement.h>

@interface TunClient : NSObject
@property xpc_connection_t connection;
@property dispatch_queue_t queue;
@end
@implementation TunClient
@end

// C ABI: each returned UTF-8 string belongs to the caller and must be freed.
__attribute__((visibility("default"))) char *v2rayn_tun_service(const char *action) {
    @autoreleasepool {
        NSString *operation = action ? @(action) : @"";
        NSURL *app = TunApplicationURL();
        if (!TunValidateApplication(app)) return TunCopyJSON(TunError(
            @"TUN requires a Developer ID signed, root-owned NativeAOT app in /Library/Application Support/v2rayN. Use the privileged-TUN installer."));
        SMAppService *service = [SMAppService daemonServiceWithPlistName:TUN_PLIST];
        NSError *error = nil;
        if ([operation isEqualToString:@"unregister"]) {
            if (![service unregisterAndReturnError:&error]) return TunCopyJSON(TunError(error.localizedDescription));
        } else if ([operation isEqualToString:@"register"]) {
            if (service.status == SMAppServiceStatusNotRegistered && ![service registerAndReturnError:&error])
                return TunCopyJSON(TunError(error.localizedDescription));
            if (service.status == SMAppServiceStatusRequiresApproval) {
                dispatch_async(dispatch_get_main_queue(), ^{ [SMAppService openSystemSettingsLoginItems]; });
                return TunCopyJSON(TunError(@"Approve v2rayN's background service in System Settings > General > Login Items, then enable TUN again."));
            }
            if (service.status != SMAppServiceStatusEnabled) return TunCopyJSON(TunError(@"The macOS TUN service is unavailable. Reinstall the signed application."));
        } else if (![operation isEqualToString:@"status"]) {
            return TunCopyJSON(TunError(@"Unknown service operation"));
        }
        return TunCopyJSON(@{@"ok": @YES, @"status": @(service.status)});
    }
}

__attribute__((visibility("default"))) void *v2rayn_tun_open(void) {
    @autoreleasepool {
        if (!TunTeamIdentifier()) return NULL;
        TunClient *client = [TunClient new];
        client.queue = dispatch_queue_create(TUN_SERVICE ".client", DISPATCH_QUEUE_SERIAL);
        client.connection = xpc_connection_create_mach_service(TUN_SERVICE, client.queue, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
        if (!client.connection) return NULL;
        xpc_connection_set_event_handler(client.connection, ^(xpc_object_t event) { /* Requests handle connection failures. */ });
        xpc_connection_activate(client.connection);
        return (__bridge_retained void *)client;
    }
}

__attribute__((visibility("default"))) char *v2rayn_tun_request(void *handle, const char *json) {
    @autoreleasepool {
        if (!handle || !json || strlen(json) > TUN_MAX_REQUEST) return TunCopyJSON(TunError(@"Invalid TUN request"));
        TunClient *client = (__bridge TunClient *)handle;
        xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
        xpc_dictionary_set_data(message, "json", json, strlen(json));
        dispatch_semaphore_t completed = dispatch_semaphore_create(0);
        __block NSDictionary *result = nil;
        xpc_connection_send_message_with_reply(client.connection, message, client.queue, ^(xpc_object_t reply) {
            if (xpc_get_type(reply) != XPC_TYPE_DICTIONARY ||
                !TunValidateMessage(reply, TUN_HELPER_ID) || xpc_connection_get_euid(client.connection) != 0) {
                result = TunError(@"The TUN service connection failed authentication or was interrupted");
                xpc_connection_cancel(client.connection);
            } else {
                size_t length = 0;
                const void *bytes = xpc_dictionary_get_data(reply, "json", &length);
                result = TunDecodeRequest(bytes, length) ?: TunError(@"Invalid service response");
            }
            dispatch_semaphore_signal(completed);
        });
        if (dispatch_semaphore_wait(completed, dispatch_time(DISPATCH_TIME_NOW, 15 * NSEC_PER_SEC)) != 0) {
            // Never reconnect and replay an ambiguous start. Canceling the owning
            // connection causes the daemon to terminate this session's child.
            xpc_connection_cancel(client.connection);
            return TunCopyJSON(TunError(@"The TUN service timed out; its session has been disconnected"));
        }
        return TunCopyJSON(result);
    }
}

__attribute__((visibility("default"))) void v2rayn_tun_close(void *handle) {
    @autoreleasepool {
        if (!handle) return;
        TunClient *client = (__bridge_transfer TunClient *)handle;
        xpc_connection_cancel(client.connection);
    }
}

__attribute__((visibility("default"))) void v2rayn_tun_free(void *pointer) { free(pointer); }
