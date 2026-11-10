#import "TunShared.h"
#include <unistd.h>

#ifdef V2RAYN_TUN_LOCAL_TRUST
int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc != 2 || strcmp(argv[1], "enroll") || geteuid() != 0) {
            fprintf(stderr, "This installer-only tool requires root and the fixed 'enroll' action.\n");
            return 1;
        }
        NSString *error = nil;
        NSDictionary *manifest = TunLocalCreateManifest(TunApplicationURL(), &error);
        if (!manifest || !TunLocalWriteManifest(manifest, &error)) {
            fprintf(stderr, "%s\n", error.UTF8String ?: "Local trust enrollment failed");
            return 1;
        }
        puts("Enrolled the installed application, helper and cores. Changes require a new administrator-approved installation.");
        return 0;
    }
}
#endif
