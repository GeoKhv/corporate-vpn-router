// Only read configurations belonging to this probe. No save/start/activation API.
#import <NetworkExtension/NetworkExtension.h>
#import <Foundation/Foundation.h>
#include <stdio.h>
int main(void) {
    @autoreleasepool {
        [NETransparentProxyManager loadAllFromPreferencesWithCompletionHandler:^(NSArray *managers, NSError *error) {
            if (error) printf("manager read: %s %ld\n", error.domain.UTF8String, (long)error.code);
            else printf("manager read: %lu configurations (no activation attempted)\n", (unsigned long)managers.count);
            exit(error ? 1 : 0);
        }];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 8*NSEC_PER_SEC), dispatch_get_main_queue(), ^{exit(2);});
        [[NSRunLoop currentRunLoop] run];
    }
    return 2;
}
