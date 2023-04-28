#import <Foundation/Foundation.h>
#import "macholoader.h"
#include "dyldpatch.h"

int main (int argc, const char *argv[]) {
    NSString *path = [NSString stringWithUTF8String:argv[0]];
    NSString *backupPath = [[path stringByDeletingLastPathComponent] stringByAppendingPathComponent:@"Backup"];
    startLoader(argc, argv, [backupPath UTF8String]);
}
