// Uses the unmodified Sparkle 2.10.1 installer and real file manager on disposable bundles.
// Only the atomic swap and one final rename are fault-injected.
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import "SUPlainInstaller.h"
#import "SUHost.h"
#import "SUFileManager.h"
static BOOL injectFailure=YES;
static NSString *destination,*newSourcePath;
static IMP originalMove;
static BOOL failedFinalMove=NO,restoredOld=NO;
static BOOL noSwap(id self,SEL cmd,NSURL *a,NSURL *b,NSError **e) { return NO; }
static BOOL move(id self,SEL cmd,NSURL *a,NSURL *b,NSError **e) {
    if (injectFailure && [b.path.stringByResolvingSymlinksInPath isEqual:destination.stringByResolvingSymlinksInPath] && [a.path isEqual:newSourcePath]) {
        failedFinalMove=YES;
        if(e)*e=[NSError errorWithDomain:NSPOSIXErrorDomain code:EIO userInfo:nil];return NO;
    }
    BOOL result=((BOOL(*)(id,SEL,NSURL*,NSURL*,NSError**))originalMove)(self,cmd,a,b,e);
    NSLog(@"move %@ -> %@ result=%d",a.path,b.path,result);
    if(failedFinalMove && [b.path.stringByResolvingSymlinksInPath isEqual:destination.stringByResolvingSymlinksInPath] && result)restoredOld=YES;
    return result;
}
int main(int argc,const char **argv) { @autoreleasepool {
    NSCAssert(argc==3,@"old new bundle args required");
    NSString *old=@(argv[1]),*new=@(argv[2]);destination=old;newSourcePath=new;
    Method m=class_getInstanceMethod(SUFileManager.class,@selector(moveItemAtURL:toURL:error:));
    originalMove=method_setImplementation(m,(IMP)move);
    method_setImplementation(class_getInstanceMethod(SUFileManager.class,@selector(swapItemAtURL:withItemAtURL:error:)),(IMP)noSwap);
    SUHost *host=[[SUHost alloc]initWithBundle:[NSBundle bundleWithPath:old]];
    SUPlainInstaller *installer=[[SUPlainInstaller alloc]initWithHost:host bundlePath:new installationPath:old];
    NSError *error=nil;
    NSCAssert([installer performInitialInstallation:&error],@"Initial validation: %@",error);
    NSCAssert(![installer performFinalInstallationProgressBlock:nil error:&error],@"Injected rename must fail");
    NSLog(@"injected=%d restored=%d error=%@",failedFinalMove,restoredOld,error);
    NSCAssert(failedFinalMove && restoredOld,@"Must move old bundle aside and restore it on failed new rename");
    NSCAssert([[NSFileManager defaultManager]fileExistsAtPath:[old stringByAppendingPathComponent:@"Contents/Info.plist"]],@"Original restored at original location");
    printf("PASS Sparkle failed final rename after moving old app; restored original at original path\n");
    injectFailure=NO;error=nil;
    NSCAssert([installer performFinalInstallationProgressBlock:nil error:&error],@"Retry succeeds: %@",error);
    [installer performCleanup];
    printf("PASS retry completes and cleans installer temporary directories\n");
}}
