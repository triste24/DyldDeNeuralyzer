//  main.m
//  MachOLoader
//
//  Created by triste24 on 2023/4/28.
//

#import <Foundation/Foundation.h>
#include "MachOLoader.h"

int main (int argc, const char *argv[]) {
    NSString *path = [NSString stringWithUTF8String:argv[0]];
    NSString *backupPath = [[path stringByDeletingLastPathComponent] stringByAppendingPathComponent:@"Backup"];
    startLoader(argc, argv, [backupPath UTF8String]);
}
