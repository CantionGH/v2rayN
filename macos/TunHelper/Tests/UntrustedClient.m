#import "../TunShared.h"

int main(void) {
    @autoreleasepool {
        dispatch_queue_t queue = dispatch_queue_create("v2rayn.untrusted-test", DISPATCH_QUEUE_SERIAL);
        xpc_connection_t connection = xpc_connection_create_mach_service(TUN_SERVICE, queue, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
        xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {});
        xpc_connection_activate(connection);
        xpc_object_t request = xpc_dictionary_create(NULL, NULL, 0);
        const char *json = "{\"operation\":\"status\"}";
        xpc_dictionary_set_data(request, "json", json, strlen(json));
        dispatch_semaphore_t completed = dispatch_semaphore_create(0);
        __block BOOL rejected = NO;
        xpc_connection_send_message_with_reply(connection, request, queue, ^(xpc_object_t reply) {
            rejected = xpc_get_type(reply) == XPC_TYPE_ERROR;
            dispatch_semaphore_signal(completed);
        });
        BOOL timeout = dispatch_semaphore_wait(completed, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC)) != 0;
        xpc_connection_cancel(connection);
        if (timeout || !rejected) { fprintf(stderr, "Unenrolled IPC client was not explicitly rejected\n"); return 1; }
        puts("PASS: real unenrolled XPC client rejected");
        return 0;
    }
}
