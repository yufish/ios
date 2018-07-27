//
//  OCnetworking.m
//  Nextcloud iOS
//
//  Created by Marino Faggiana on 10/05/15.
//  Copyright (c) 2017 TWS. All rights reserved.
//
//  Author Marino Faggiana <m.faggiana@twsweb.it>
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <http://www.gnu.org/licenses/>.
//

#import "OCNetworking.h"

#import "CCUtility.h"
#import "CCGraphics.h"
#import "CCCertificate.h"
#import "NSString+Encode.h"
#import "NCBridgeSwift.h"

#pragma clang diagnostic ignored "-Warc-performSelector-leaks"

@interface OCnetworking ()
{
    NSString *_activeUser;
    NSString *_activeUserID;
    NSString *_activePassword;
    NSString *_activeUrl;
}
@end

@implementation OCnetworking

- (id)initWithDelegate:(id <OCNetworkingDelegate>)delegate metadataNet:(CCMetadataNet *)metadataNet withUser:(NSString *)withUser withUserID:(NSString *)withUserID withPassword:(NSString *)withPassword withUrl:(NSString *)withUrl
{
    self = [super init];
    
    if (self) {
        
        _delegate = delegate;
        
        _metadataNet = [CCMetadataNet new];
        _metadataNet = [metadataNet copy];
        
        _activeUser = withUser;
        _activeUserID = withUserID;
        _activePassword = withPassword;
        _activeUrl = withUrl;
    }
    
    return self;
}

- (void)start
{
    if (![NSThread isMainThread]) {
        [self performSelectorOnMainThread:@selector(start) withObject:nil waitUntilDone:NO];
        return;
    }
    
    [self willChangeValueForKey:@"isExecuting"];
    _isExecuting = YES;
    [self didChangeValueForKey:@"isExecuting"];
    
    if (self.isCancelled) {
        
        [self finish];
        
    } else {
                
        [self poolNetworking];
    }
}

- (void)finish
{
    [self willChangeValueForKey:@"isExecuting"];
    [self willChangeValueForKey:@"isFinished"];
    
    _isExecuting = NO;
    _isFinished = YES;
    
    [self didChangeValueForKey:@"isExecuting"];
    [self didChangeValueForKey:@"isFinished"];
}

- (void)cancel
{
    if (_isExecuting) {
        
        [self complete];
    }
    
    [super cancel];
}

- (void)poolNetworking
{
#ifndef EXTENSION
    [[UIApplication sharedApplication] setNetworkActivityIndicatorVisible:YES];
#endif
        
    if([self respondsToSelector:NSSelectorFromString(_metadataNet.action)])
        [self performSelector:NSSelectorFromString(_metadataNet.action)];
}

#pragma --------------------------------------------------------------------------------------------
#pragma mark =====  Delegate  =====
#pragma --------------------------------------------------------------------------------------------

- (void)complete
{    
    [self finish];
    
#ifndef EXTENSION
    [[UIApplication sharedApplication] setNetworkActivityIndicatorVisible:NO];
#endif
}

#pragma --------------------------------------------------------------------------------------------
#pragma mark ===== Check Server =====
#pragma --------------------------------------------------------------------------------------------

- (void)checkServer:(NSString *)serverUrl success:(void (^)(void))success failure:(void (^)(NSString *message, NSInteger errorCode))failure
{
    OCCommunication *communication = [CCNetworking sharedNetworking].sharedOCCommunication;
    
    [communication setCredentialsWithUser:_activeUser andUserID:_activeUserID andPassword:_activePassword];
    [communication setUserAgent:[CCUtility getUserAgent]];
        
    [communication checkServer:serverUrl onCommunication:communication successRequest:^(NSHTTPURLResponse *response, NSString *redirectedServer) {
        
        success();
            
    } failureRequest:^(NSHTTPURLResponse *response, NSError *error, NSString *redirectedServer) {
        
        NSString *message;

        NSInteger errorCode = response.statusCode;
        if (errorCode == 0 || (errorCode >= 200 && errorCode < 300))
            errorCode = error.code;
        
        // Error
        if (errorCode == 503)
            message = NSLocalizedStringFromTable(@"_server_error_retry_", @"Error", nil);
        else
            message = [error.userInfo valueForKey:@"NSLocalizedDescription"];
    
        failure(message, errorCode);
    }];
}

#pragma --------------------------------------------------------------------------------------------
#pragma mark ===== download =====
#pragma --------------------------------------------------------------------------------------------

- (NSURLSessionTask *)downloadFileNameServerUrl:(NSString *)fileNameServerUrl fileNameLocalPath:(NSString *)fileNameLocalPath communication:(OCCommunication *)communication success:(void (^)(int64_t length, NSString *etag, NSDate *date))success failure:(void (^)(NSString *message, NSInteger errorCode))failure
{
    [communication setCredentialsWithUser:_activeUser andUserID:_activeUserID andPassword:_activePassword];
    [communication setUserAgent:[CCUtility getUserAgent]];
    
    NSURLSessionTask *sessionTask = [communication downloadFileSession:fileNameServerUrl toDestiny:fileNameLocalPath defaultPriority:YES onCommunication:communication progress:^(NSProgress *progress) {
        //float percent = roundf (progress.fractionCompleted * 100);
    } successRequest:^(NSURLResponse *response, NSURL *filePath) {

        int64_t totalUnitCount = 0;
        NSDate *date = [NSDate date];
        NSDateFormatter *dateFormatter = [NSDateFormatter new];
        NSLocale *enUSPOSIXLocale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
        [dateFormatter setLocale:enUSPOSIXLocale];
        [dateFormatter setDateFormat:@"EEE, dd MMM y HH:mm:ss zzz"];
        NSError *error;
        
        NSDictionary *fields = [(NSHTTPURLResponse*)response allHeaderFields];

        NSString *contentLength = [fields objectForKey:@"Content-Length"];
        if(contentLength) {
            totalUnitCount = (int64_t) [contentLength longLongValue];
        }
        NSString *etag = [CCUtility removeForbiddenCharactersFileSystem:[fields objectForKey:@"OC-ETag"]];
        NSString *dateString = [fields objectForKey:@"Date"];
        if (dateString) {
            if (![dateFormatter getObjectValue:&date forString:dateString range:nil error:&error]) {
                date = [NSDate date];
            }
        } else {
            date = [NSDate date];
        }
        
        success(totalUnitCount, etag, date);
        
    } failureRequest:^(NSURLResponse *response, NSError *error) {
        
        NSString *message;
        NSInteger errorCode;
        
        NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse*)response;
        errorCode = httpResponse.statusCode;
        
        if (errorCode == 0 || (errorCode >= 200 && errorCode < 300))
            errorCode = error.code;
        
        // Error
        if (errorCode == 503)
            message = NSLocalizedStringFromTable(@"_server_error_retry_", @"Error", nil);
        else
            message = [error.userInfo valueForKey:@"NSLocalizedDescription"];
        
        failure(message, errorCode);
    }];
    
    return sessionTask;
}

#pragma --------------------------------------------------------------------------------------------
#pragma mark ===== upload =====
#pragma --------------------------------------------------------------------------------------------

- (NSURLSessionTask *)uploadFileNameServerUrl:(NSString *)fileNameServerUrl fileNameLocalPath:(NSString *)fileNameLocalPath communication:(OCCommunication *)communication success:(void(^)(NSString *fileID, NSString *etag, NSDate *date))success failure:(void (^)(NSString *message, NSInteger errorCode))failure
{    
    [communication setCredentialsWithUser:_activeUser andUserID:_activeUserID andPassword:_activePassword];
    [communication setUserAgent:[CCUtility getUserAgent]];
    
    NSURLSessionTask *sessionTask = [communication uploadFileSession:fileNameLocalPath toDestiny:fileNameServerUrl onCommunication:communication progress:^(NSProgress *progress) {
        //float percent = roundf (progress.fractionCompleted * 100);
    } successRequest:^(NSURLResponse *response, NSString *redirectedServer) {
    
        NSDictionary *fields = [(NSHTTPURLResponse*)response allHeaderFields];

        NSString *fileID = [CCUtility removeForbiddenCharactersFileSystem:[fields objectForKey:@"OC-FileId"]];
        NSString *etag = [CCUtility removeForbiddenCharactersFileSystem:[fields objectForKey:@"OC-ETag"]];
        NSDate *date = [CCUtility dateEnUsPosixFromCloud:[fields objectForKey:@"Date"]];
        
        success(fileID, etag, date);
        
    } failureRequest:^(NSURLResponse *response, NSString *redirectedServer, NSError *error) {
        
        NSString *message;
        NSInteger errorCode;
        
        NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse*)response;
        errorCode = httpResponse.statusCode;
        
        if (errorCode == 0 || (errorCode >= 200 && errorCode < 300))
            errorCode = error.code;
        
        // Error
        if (errorCode == 503)
            message = NSLocalizedStringFromTable(@"_server_error_retry_", @"Error", nil);
        else
            message = [error.userInfo valueForKey:@"NSLocalizedDescription"];
        
        failure(message, errorCode);
        
    } failureBeforeRequest:^(NSError *error) {
        failure(@"", error.code);
    }];
    
    return sessionTask;
}
#pragma --------------------------------------------------------------------------------------------
#pragma mark ===== downloadThumbnail =====
#pragma --------------------------------------------------------------------------------------------

- (void)downloadThumbnailWithDimOfThumbnail:(NSString *)dimOfThumbnail fileID:(NSString*)fileID fileNamePath:(NSString *)fileNamePath fileNameView:(NSString *)fileNameView completion:(void (^)(NSString *message, NSInteger errorCode))completion
{
    OCCommunication *communication = [CCNetworking sharedNetworking].sharedOCCommunication;

    __block NSString *ext;
    NSInteger width = 0, height = 0;
    
    if ([dimOfThumbnail.lowercaseString isEqualToString:@"xs"])      { width = 32;   height = 32;  ext = @"ico"; }
    else if ([dimOfThumbnail.lowercaseString isEqualToString:@"s"])  { width = 64;   height = 64;  ext = @"ico"; }
    else if ([dimOfThumbnail.lowercaseString isEqualToString:@"m"])  { width = 128;  height = 128; ext = @"ico"; }
    else if ([dimOfThumbnail.lowercaseString isEqualToString:@"l"])  { width = 640;  height = 640; ext = @"pvw"; }
    else if ([dimOfThumbnail.lowercaseString isEqualToString:@"xl"]) { width = 1024; height = 1024; ext = @"pvw"; }
    
    NSString *fileNameViewPath = [NSString stringWithFormat:@"%@/%@.%@", [CCUtility getDirectoryProviderStorageFileID:fileID], fileNameView, ext];
    
    if ([[NSFileManager defaultManager] fileExistsAtPath:fileNameViewPath]) {
        
        completion(nil, 0);
        
    } else {
        
        [communication setCredentialsWithUser:_activeUser andUserID:_activeUserID andPassword:_activePassword];
        [communication setUserAgent:[CCUtility getUserAgent]];
        
        [communication getRemoteThumbnailByServer:[_activeUrl stringByAppendingString:@"/"] ofFilePath:fileNamePath withWidth:width andHeight:height onCommunication:communication successRequest:^(NSHTTPURLResponse *response, NSData *thumbnail, NSString *redirectedServer) {
            
            [UIImagePNGRepresentation([UIImage imageWithData:thumbnail]) writeToFile:fileNameViewPath atomically: YES];
                    
            completion(nil, 0);
            
        } failureRequest:^(NSHTTPURLResponse *response, NSError *error, NSString *redirectedServer) {
            
            NSString *message;

            NSInteger errorCode = response.statusCode;
            if (errorCode == 0 || (errorCode >= 200 && errorCode < 300))
                errorCode = error.code;
            
            // Error
            if (errorCode == 503)
                message = NSLocalizedStringFromTable(@"_server_error_retry_", @"Error", nil);
            else
                message = [error.userInfo valueForKey:@"NSLocalizedDescription"];
            
            completion(message, errorCode);
        }];
    }
}

#pragma --------------------------------------------------------------------------------------------
#pragma mark ===== Read Folder =====
#pragma --------------------------------------------------------------------------------------------

- (void)readFolder
{
    [self readFolder:_metadataNet.serverUrl depth:_metadataNet.depth account:_metadataNet.account success:^(NSArray *metadatas, tableMetadata *metadataFolder, NSString *directoryID) {
        
        _metadataNet.directoryID = directoryID;
        
        if ([self.delegate respondsToSelector:@selector(readFolderSuccessFailure:metadataFolder:metadatas:message:errorCode:)])
            [self.delegate readFolderSuccessFailure:_metadataNet metadataFolder:metadataFolder metadatas:metadatas message:nil errorCode:0];
        
        [self complete];
        
    } failure:^(NSString *message, NSInteger errorCode) {
        
        if ([self.delegate respondsToSelector:@selector(readFolderSuccessFailure:metadataFolder:metadatas:message:errorCode:)])
            [self.delegate readFolderSuccessFailure:_metadataNet metadataFolder:nil metadatas:nil message:message errorCode:errorCode];
        
        [self complete];
    }];
}

- (void)readFolder:(NSString *)serverUrl depth:(NSString *)depth account:(NSString *)account success:(void(^)(NSArray *metadatas, tableMetadata *metadataFolder, NSString *directoryID))success failure:(void (^)(NSString *message, NSInteger errorCode))failure
{
    OCCommunication *communication = [CCNetworking sharedNetworking].sharedOCCommunication;

    [communication setCredentialsWithUser:_activeUser andUserID:_activeUserID andPassword:_activePassword];
    [communication setUserAgent:[CCUtility getUserAgent]];
    
    [communication readFolder:serverUrl depth:depth withUserSessionToken:nil onCommunication:communication successRequest:^(NSHTTPURLResponse *response, NSArray *items, NSString *redirectedServer, NSString *token) {
        
        // Test active account
        tableAccount *recordAccount = [[NCManageDatabase sharedInstance] getAccountActive];
        if (![recordAccount.account isEqualToString:account]) {
            
            failure(NSLocalizedStringFromTable(@"_error_user_not_available_", @"Error", nil), k_CCErrorUserNotAvailble);
            
        } else {
            
            // Check items > 0
            if ([items count] == 0) {
                
#ifndef EXTENSION
                AppDelegate *appDelegate = (AppDelegate *)[[UIApplication sharedApplication] delegate];
                
                [appDelegate messageNotification:@"Server error" description:@"Read Folder WebDAV : [items NULL] please fix" visible:YES delay:k_dismissAfterSecond type:TWMessageBarMessageTypeError errorCode:k_CCErrorInternalError];
#endif
                failure(NSLocalizedStringFromTable(@"Read Folder WebDAV : [items NULL] please fix", @"Server error", nil), k_CCErrorInternalError);

            } else {
                
                dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
                
                    BOOL showHiddenFiles = [CCUtility getShowHiddenFiles];
                    BOOL isFolderEncrypted = [CCUtility isFolderEncrypted:serverUrl account:account];
                    
                    // directory [0]
                    OCFileDto *itemDtoFolder = [items objectAtIndex:0];
                    //NSDate *date = [NSDate dateWithTimeIntervalSince1970:itemDtoDirectory.date];
                    
                    NSString *directoryID = [[NCManageDatabase sharedInstance] addDirectoryWithEncrypted:itemDtoFolder.isEncrypted favorite:itemDtoFolder.isFavorite fileID:itemDtoFolder.ocId permissions:itemDtoFolder.permissions serverUrl:serverUrl].directoryID;
                    NSMutableArray *metadatas = [NSMutableArray new];
                    tableMetadata *metadataFolder = [tableMetadata new];
                    
                    NSString *autoUploadFileName = [[NCManageDatabase sharedInstance] getAccountAutoUploadFileName];
                    NSString *autoUploadDirectory = [[NCManageDatabase sharedInstance] getAccountAutoUploadDirectory:_activeUrl];
                    
                    NSString *serverUrlFolder;
                    NSString *directoryIDFolder;

                    // Metadata . (self Folder)
                    if ([serverUrl isEqualToString:[CCUtility getHomeServerUrlActiveUrl:_activeUrl]]) {
                        
                        // root folder
                        serverUrlFolder = @"..";
                        directoryIDFolder = @"00000000-0000-0000-0000-000000000000";
                        
                        metadataFolder = [CCUtility trasformedOCFileToCCMetadata:itemDtoFolder fileName:@"." serverUrl:serverUrlFolder directoryID:directoryIDFolder autoUploadFileName:autoUploadFileName autoUploadDirectory:autoUploadDirectory activeAccount:account isFolderEncrypted:isFolderEncrypted];
                        
                    } else {
                        
                        serverUrlFolder = [CCUtility deletingLastPathComponentFromServerUrl:serverUrl];
                        directoryIDFolder = [[NCManageDatabase sharedInstance] getDirectoryID:serverUrlFolder];
                        
                        if (!directoryIDFolder) {
                            dispatch_async(dispatch_get_main_queue(), ^{
                                success(metadatas, metadataFolder, directoryID);
                            });
                            return;
                        }
                        metadataFolder = [CCUtility trasformedOCFileToCCMetadata:itemDtoFolder fileName:[serverUrl lastPathComponent] serverUrl:serverUrlFolder directoryID:directoryIDFolder autoUploadFileName:autoUploadFileName autoUploadDirectory:autoUploadDirectory activeAccount:account isFolderEncrypted:isFolderEncrypted];
                    }

                    NSArray *itemsSortedArray = [items sortedArrayUsingComparator:^NSComparisonResult(id a, id b) {
                        
                        NSString *first = [(OCFileDto*)a fileName];
                        NSString *second = [(OCFileDto*)b fileName];
                        return [[first lowercaseString] compare:[second lowercaseString]];
                    }];
                    
                    for (NSUInteger i=1; i < [itemsSortedArray count]; i++) {
                        
                        OCFileDto *itemDto = [itemsSortedArray objectAtIndex:i];
                        NSString *fileName = [itemDto.fileName stringByReplacingOccurrencesOfString:@"/" withString:@""];
                        
                        // Skip hidden files
                        if (fileName.length > 0) {
                            if (!showHiddenFiles && [[fileName substringToIndex:1] isEqualToString:@"."])
                                continue;
                        } else {
                            continue;
                        }
                        
                        if (itemDto.isDirectory) {
                            (void)[[NCManageDatabase sharedInstance] addDirectoryWithEncrypted:itemDto.isEncrypted favorite:itemDto.isFavorite fileID:itemDto.ocId permissions:itemDto.permissions serverUrl:[CCUtility stringAppendServerUrl:serverUrl addFileName:fileName]];
                        }
                        
                        // ----- BUG #942 ---------
                        if ([itemDto.etag length] == 0) {
    #ifndef EXTENSION
                            AppDelegate *appDelegate = (AppDelegate *)[[UIApplication sharedApplication] delegate];
                            [appDelegate messageNotification:@"Server error" description:@"Metadata fileID absent, record excluded, please fix" visible:YES delay:k_dismissAfterSecond type:TWMessageBarMessageTypeError errorCode:k_CCErrorInternalError];
    #endif
                            continue;
                        }
                        // ------------------------
                        
                        [metadatas addObject:[CCUtility trasformedOCFileToCCMetadata:itemDto fileName:itemDto.fileName serverUrl:serverUrl directoryID:directoryID autoUploadFileName:autoUploadFileName autoUploadDirectory:autoUploadDirectory activeAccount:account isFolderEncrypted:isFolderEncrypted]];
                    }
                    
                    dispatch_async(dispatch_get_main_queue(), ^{
                        success(metadatas, metadataFolder, directoryID);
                    });
                });
            }
        }
    
    } failureRequest:^(NSHTTPURLResponse *response, NSError *error, NSString *token, NSString *redirectedServer) {
        
        NSString *message;
        
        NSInteger errorCode = response.statusCode;
        if (errorCode == 0 || (errorCode >= 200 && errorCode < 300))
            errorCode = error.code;
        
        // Error
        if (errorCode == 503)
            message = NSLocalizedStringFromTable(@"_server_error_retry_", @"Error", nil);
        else
            message = [error.userInfo valueForKey:@"NSLocalizedDescription"];
        
        // Request trusted certificated
        if ([error code] == NSURLErrorServerCertificateUntrusted && self.delegate)
            [[CCCertificate sharedManager] presentViewControllerCertificateWithTitle:[error localizedDescription] viewController:(UIViewController *)self.delegate delegate:self];
        
        // Activity
        [[NCManageDatabase sharedInstance] addActivityClient:serverUrl fileID:@"" action:k_activityDebugActionReadFolder selector:@"" note:[error.userInfo valueForKey:@"NSLocalizedDescription"] type:k_activityTypeFailure verbose:k_activityVerboseHigh activeUrl:_activeUrl];

        failure(message, errorCode);
    }];
}

#pragma --------------------------------------------------------------------------------------------
#pragma mark ===== ReadFile =====
#pragma --------------------------------------------------------------------------------------------

- (void)readFile
{
    [self readFile:_metadataNet.fileName serverUrl:_metadataNet.serverUrl account:_metadataNet.account success:^(tableMetadata *metadata) {
        
        if([self.delegate respondsToSelector:@selector(readFileSuccessFailure:metadata:message:errorCode:)])
            [self.delegate readFileSuccessFailure:_metadataNet metadata:metadata message:nil errorCode:0];
        
        [self complete];
        
    } failure:^(NSString *message, NSInteger errorCode) {
        
        if ([self.delegate respondsToSelector:@selector(readFileSuccessFailure:metadata:message:errorCode:)])
            [self.delegate readFileSuccessFailure:_metadataNet metadata:nil message:message errorCode:errorCode];
        
        [self complete];
    }];
}

- (void)readFile:(NSString *)fileName serverUrl:(NSString *)serverUrl account:(NSString *)account success:(void(^)(tableMetadata *metadata))success failure:(void (^)(NSString *message, NSInteger errorCode))failure
{
    OCCommunication *communication = [CCNetworking sharedNetworking].sharedOCCommunication;
    
    NSString *fileNamePath;

    if (fileName) {
        fileNamePath = [NSString stringWithFormat:@"%@/%@", serverUrl, fileName];
    } else {
        fileName= @".";
        fileNamePath = serverUrl;
    }
    
    [communication setCredentialsWithUser:_activeUser andUserID:_activeUserID andPassword:_activePassword];
    [communication setUserAgent:[CCUtility getUserAgent]];
    
    [communication readFile:fileNamePath onCommunication:communication successRequest:^(NSHTTPURLResponse *response, NSArray *items, NSString *redirectedServer) {
        
        // Test active account
        tableAccount *recordAccount = [[NCManageDatabase sharedInstance] getAccountActive];
        if (![recordAccount.account isEqualToString:account]) {
            
            failure(NSLocalizedStringFromTable(@"_error_user_not_available_", @"Error", nil), k_CCErrorUserNotAvailble);
            
        } else {
            
            BOOL isFolderEncrypted = [CCUtility isFolderEncrypted:serverUrl account:account];
            
            if ([items count] > 0) {
                
                tableMetadata *metadata = [tableMetadata new];
                
                OCFileDto *itemDto = [items objectAtIndex:0];
                
                NSString *directoryID = [[NCManageDatabase sharedInstance] getDirectoryID:serverUrl];
                if (directoryID) {
                    
                    NSString *autoUploadFileName = [[NCManageDatabase sharedInstance] getAccountAutoUploadFileName];
                    NSString *autoUploadDirectory = [[NCManageDatabase sharedInstance] getAccountAutoUploadDirectory:_activeUrl];
                    
                    metadata = [CCUtility trasformedOCFileToCCMetadata:itemDto fileName:fileName serverUrl:serverUrl directoryID:directoryID autoUploadFileName:autoUploadFileName autoUploadDirectory:autoUploadDirectory activeAccount:account isFolderEncrypted:isFolderEncrypted];
                    
                    success(metadata);
                    
                } else {
                    
                    failure(NSLocalizedStringFromTable(@"Directory not found", @"Error", nil), k_CCErrorInternalError);
                }
            }
            
            // BUG 1038 item == 0
            else {
                
#ifndef EXTENSION
                AppDelegate *appDelegate = (AppDelegate *)[[UIApplication sharedApplication] delegate];
                
                [appDelegate messageNotification:@"Server error" description:@"Read File WebDAV : [items NULL] please fix" visible:YES delay:k_dismissAfterSecond type:TWMessageBarMessageTypeError errorCode:k_CCErrorInternalError];
#endif
                failure(NSLocalizedStringFromTable(@"Read File WebDAV : [items NULL] please fix", @"Server error", nil), k_CCErrorInternalError);
            }
        }
        
    } failureRequest:^(NSHTTPURLResponse *response, NSError *error, NSString *redirectedServer) {
        
        NSString *message;
        
        NSInteger errorCode = response.statusCode;
        if (errorCode == 0 || (errorCode >= 200 && errorCode < 300))
            errorCode = error.code;
        
        // Error
        if (errorCode == 503)
            message = NSLocalizedStringFromTable(@"_server_error_retry_", @"Error", nil);
        else
            message = [error.userInfo valueForKey:@"NSLocalizedDescription"];
        
        // Request trusted certificated
        if ([error code] == NSURLErrorServerCertificateUntrusted && self.delegate)
            [[CCCertificate sharedManager] presentViewControllerCertificateWithTitle:[error localizedDescription] viewController:(UIViewController *)self.delegate delegate:self];
        
        // Activity
        [[NCManageDatabase sharedInstance] addActivityClient:serverUrl fileID:@"" action:k_activityDebugActionReadFolder selector:@"" note:[error.userInfo valueForKey:@"NSLocalizedDescription"] type:k_activityTypeFailure verbose:k_activityVerboseHigh activeUrl:_activeUrl];
        
        failure(message, errorCode);
    }];
}

#pragma --------------------------------------------------------------------------------------------
#pragma mark ===== Search =====
#pragma --------------------------------------------------------------------------------------------

- (void)search
{
    OCCommunication *communication = [CCNetworking sharedNetworking].sharedOCCommunication;
    
    [communication setCredentialsWithUser:_activeUser andUserID:_activeUserID andPassword:_activePassword];
    [communication setUserAgent:[CCUtility getUserAgent]];
    
    NSString *path = [_activeUrl stringByAppendingString:k_dav];
    NSString *folder = [_metadataNet.serverUrl stringByReplacingOccurrencesOfString:[CCUtility getHomeServerUrlActiveUrl:_activeUrl] withString:@""];
    NSString *dateLastModified;
    
    if (_metadataNet.date) {
        NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
        NSLocale *enUSPOSIXLocale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
        [dateFormatter setLocale:enUSPOSIXLocale];
        [dateFormatter setDateFormat:@"yyyy-MM-dd'T'HH:mm:ssZZZZZ"];
    
        dateLastModified = [dateFormatter stringFromDate:_metadataNet.date];
    }
    
    [communication search:path folder:folder fileName: [NSString stringWithFormat:@"%%%@%%", _metadataNet.fileName] depth:_metadataNet.depth dateLastModified:dateLastModified contentType:_metadataNet.contentType withUserSessionToken:nil onCommunication:communication successRequest:^(NSHTTPURLResponse *response, NSArray *items, NSString *redirectedServer, NSString *token) {
        
        // Test active account
        tableAccount *recordAccount = [[NCManageDatabase sharedInstance] getAccountActive];
        if (![recordAccount.account isEqualToString:_metadataNet.account]) {
            if ([self.delegate respondsToSelector:@selector(searchSuccessFailure:metadatas:message:errorCode:)])
                [self.delegate searchSuccessFailure:_metadataNet metadatas:nil message:NSLocalizedStringFromTable(@"_error_user_not_available_", @"Error", nil) errorCode:k_CCErrorUserNotAvailble];

            [self complete];
            return;
        }
        
        NSMutableArray *metadatas = [NSMutableArray new];
        BOOL showHiddenFiles = [CCUtility getShowHiddenFiles];

        NSString *autoUploadFileName = [[NCManageDatabase sharedInstance] getAccountAutoUploadFileName];
        NSString *autoUploadDirectory = [[NCManageDatabase sharedInstance] getAccountAutoUploadDirectory:_activeUrl];

        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        
            for(OCFileDto *itemDto in items) {
            
                NSString *serverUrl, *directoryID;
                BOOL isFolderEncrypted;

                NSString *fileName = [itemDto.fileName stringByReplacingOccurrencesOfString:@"/" withString:@""];

                // Skip hidden files
                if (fileName.length > 0) {
                    if (!showHiddenFiles && [[fileName substringToIndex:1] isEqualToString:@"."])
                        continue;
                } else
                    continue;
            
                // ----- BUG #942 ---------
                if ([itemDto.etag length] == 0) {
#ifndef EXTENSION
                    AppDelegate *appDelegate = (AppDelegate *)[[UIApplication sharedApplication] delegate];
                    [appDelegate messageNotification:@"Server error" description:@"Metadata fileID absent, record excluded, please fix" visible:YES delay:k_dismissAfterSecond type:TWMessageBarMessageTypeError errorCode:k_CCErrorInternalError];
#endif
                    continue;
                }
                // ------------------------
            
                serverUrl = [itemDto.filePath stringByReplacingOccurrencesOfString:[NSString stringWithFormat:@"%@/files/%@", k_dav, _activeUserID] withString:@""];
                if ([serverUrl hasPrefix:@"/"])
                    serverUrl = [serverUrl substringFromIndex:1];
                if ([serverUrl hasSuffix:@"/"])
                    serverUrl = [serverUrl substringToIndex:[serverUrl length] - 1];
                serverUrl = [CCUtility stringAppendServerUrl:[_activeUrl stringByAppendingString:k_webDAV] addFileName:serverUrl];
                
                if (itemDto.isDirectory) {
                    (void)[[NCManageDatabase sharedInstance] addDirectoryWithEncrypted:itemDto.isEncrypted favorite:itemDto.isFavorite fileID:itemDto.ocId permissions:itemDto.permissions serverUrl:[NSString stringWithFormat:@"%@/%@", serverUrl, fileName]];
                }
                
                directoryID = [[NCManageDatabase sharedInstance] getDirectoryID:serverUrl];
                
                isFolderEncrypted = [CCUtility isFolderEncrypted:serverUrl account:_metadataNet.account];
                
                [metadatas addObject:[CCUtility trasformedOCFileToCCMetadata:itemDto fileName:itemDto.fileName serverUrl:serverUrl directoryID:directoryID autoUploadFileName:autoUploadFileName autoUploadDirectory:autoUploadDirectory activeAccount:_metadataNet.account isFolderEncrypted:isFolderEncrypted]];
            }
    
            dispatch_async(dispatch_get_main_queue(), ^{
                if ([self.delegate respondsToSelector:@selector(searchSuccessFailure:metadatas:message:errorCode:)])
                    [self.delegate searchSuccessFailure:_metadataNet metadatas:metadatas message:nil errorCode:0];
            });
        
        });
        
        [self complete];
        
    } failureRequest:^(NSHTTPURLResponse *response, NSError *error, NSString *token, NSString *redirectedServer) {
        
        NSInteger errorCode = response.statusCode;
        if (errorCode == 0 || (errorCode >= 200 && errorCode < 300))
            errorCode = error.code;

        // Error
        if ([self.delegate respondsToSelector:@selector(searchSuccessFailure:metadatas:message:errorCode:)]) {
            
            if (errorCode == 503)
                [self.delegate searchSuccessFailure:_metadataNet metadatas:nil message:NSLocalizedStringFromTable(@"_server_error_retry_", @"Error", nil) errorCode:errorCode];
            else
                [self.delegate searchSuccessFailure:_metadataNet metadatas:nil message:[error.userInfo valueForKey:@"NSLocalizedDescription"] errorCode:errorCode];
        }

        // Request trusted certificated
        if ([error code] == NSURLErrorServerCertificateUntrusted && self.delegate)
            [[CCCertificate sharedManager] presentViewControllerCertificateWithTitle:[error localizedDescription] viewController:(UIViewController *)self.delegate delegate:self];
        
        [self complete];
    }];
}

#pragma --------------------------------------------------------------------------------------------
#pragma mark ===== Setting Favorite =====
#pragma --------------------------------------------------------------------------------------------

- (void)settingFavorite:(NSString *)fileName favorite:(BOOL)favorite completion:(void (^)(NSString *message, NSInteger errorCode))completion
{
    OCCommunication *communication = [CCNetworking sharedNetworking].sharedOCCommunication;
    
    [communication setCredentialsWithUser:_activeUser andUserID:_activeUserID andPassword:_activePassword];
    [communication setUserAgent:[CCUtility getUserAgent]];
    
    NSString *server = [_activeUrl stringByAppendingString:k_dav];

    [communication settingFavoriteServer:server andFileOrFolderPath:fileName favorite:favorite withUserSessionToken:nil onCommunication:communication successRequest:^(NSHTTPURLResponse *response, NSString *redirectedServer, NSString *token) {
        
        completion(nil, 0);
        
    } failureRequest:^(NSHTTPURLResponse *response, NSError *error, NSString *token, NSString *redirectedServer) {
        
        NSString *message;
        
        NSInteger errorCode = response.statusCode;
        if (errorCode == 0 || (errorCode >= 200 && errorCode < 300))
            errorCode = error.code;
        
        // Error
        if (errorCode == 503)
            message = NSLocalizedStringFromTable(@"_server_error_retry_", @"Error", nil);
        else
            message = [error.userInfo valueForKey:@"NSLocalizedDescription"];
        
        // Request trusted certificated
        if ([error code] == NSURLErrorServerCertificateUntrusted && self.delegate)
            [[CCCertificate sharedManager] presentViewControllerCertificateWithTitle:[error localizedDescription] viewController:(UIViewController *)self.delegate delegate:self];
        
        completion(message, errorCode);
    }];
}

#pragma --------------------------------------------------------------------------------------------
#pragma mark ===== Listing Favorites =====
#pragma --------------------------------------------------------------------------------------------

- (void)listingFavorites:(NSString *)serverUrl account:(NSString *)account success:(void(^)(NSArray *metadatas))success failure:(void (^)(NSString *message, NSInteger errorCode))failure
{
    OCCommunication *communication = [CCNetworking sharedNetworking].sharedOCCommunication;
    
    [communication setCredentialsWithUser:_activeUser andUserID:_activeUserID andPassword:_activePassword];
    [communication setUserAgent:[CCUtility getUserAgent]];
    
    NSString *path = [_activeUrl stringByAppendingString:k_dav];
    NSString *folder = [serverUrl stringByReplacingOccurrencesOfString:[CCUtility getHomeServerUrlActiveUrl:_activeUrl] withString:@""];
    
    [communication listingFavorites:path folder:folder withUserSessionToken:nil onCommunication:communication successRequest:^(NSHTTPURLResponse *response, NSArray *items, NSString *redirectedServer, NSString *token) {
        
        // Test active account
        tableAccount *recordAccount = [[NCManageDatabase sharedInstance] getAccountActive];
        if (![recordAccount.account isEqualToString:account]) {
            
            failure(NSLocalizedStringFromTable(@"_error_user_not_available_", @"Error", nil), k_CCErrorUserNotAvailble);
            
        } else {
        
            NSMutableArray *metadatas = [NSMutableArray new];
            BOOL showHiddenFiles = [CCUtility getShowHiddenFiles];

            NSString *autoUploadFileName = [[NCManageDatabase sharedInstance] getAccountAutoUploadFileName];
            NSString *autoUploadDirectory = [[NCManageDatabase sharedInstance] getAccountAutoUploadDirectory:_activeUrl];
        
            // Order by fileNamePath
            items = [items sortedArrayUsingComparator:^NSComparisonResult(id obj1, id obj2) {
                
                OCFileDto *record1 = obj1, *record2 = obj2;
                
                NSString *path1 = [[record1.filePath stringByAppendingString:record1.fileName] lowercaseString];
                NSString *path2 = [[record2.filePath stringByAppendingString:record2.fileName] lowercaseString];
                
                return [path1 compare:path2];
                
            }];
        
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
           
                for(OCFileDto *itemDto in items) {
                    
                    NSString *serverUrl, *directoryID;
                    BOOL isFolderEncrypted;
                    
                    NSString *fileName = [itemDto.fileName stringByReplacingOccurrencesOfString:@"/" withString:@""];
                    
                    // Skip hidden files
                    if (fileName.length > 0) {
                        if (!showHiddenFiles && [[fileName substringToIndex:1] isEqualToString:@"."])
                            continue;
                    } else
                        continue;
                    
                    // ----- BUG #942 ---------
                    if ([itemDto.etag length] == 0) {
    #ifndef EXTENSION
                        AppDelegate *appDelegate = (AppDelegate *)[[UIApplication sharedApplication] delegate];
                        [appDelegate messageNotification:@"Server error" description:@"Metadata fileID absent, record excluded, please fix" visible:YES delay:k_dismissAfterSecond type:TWMessageBarMessageTypeError errorCode:k_CCErrorInternalError];
    #endif
                        continue;
                    }
                    // ------------------------
                    
                    serverUrl = [itemDto.filePath stringByReplacingOccurrencesOfString:[NSString stringWithFormat:@"%@/files/%@", k_dav, _activeUserID] withString:@""];
                    if ([serverUrl hasPrefix:@"/"])
                        serverUrl = [serverUrl substringFromIndex:1];
                    if ([serverUrl hasSuffix:@"/"])
                        serverUrl = [serverUrl substringToIndex:[serverUrl length] - 1];
                    serverUrl = [CCUtility stringAppendServerUrl:[_activeUrl stringByAppendingString:k_webDAV] addFileName:serverUrl];
                    
                    if (itemDto.isDirectory) {
                        (void)[[NCManageDatabase sharedInstance] addDirectoryWithEncrypted:itemDto.isEncrypted favorite:itemDto.isFavorite fileID:itemDto.ocId permissions:itemDto.permissions serverUrl:[NSString stringWithFormat:@"%@/%@", serverUrl, fileName]];
                    }
                    
                    directoryID = [[NCManageDatabase sharedInstance] getDirectoryID:serverUrl];
                    
                    isFolderEncrypted = [CCUtility isFolderEncrypted:serverUrl account:account];
                    
                    [metadatas addObject:[CCUtility trasformedOCFileToCCMetadata:itemDto fileName:itemDto.fileName serverUrl:serverUrl directoryID:directoryID autoUploadFileName:autoUploadFileName autoUploadDirectory:autoUploadDirectory activeAccount:account isFolderEncrypted:isFolderEncrypted]];
                }
                
                dispatch_async(dispatch_get_main_queue(), ^{
                    success(metadatas);
                });
            });
        }
        
    } failureRequest:^(NSHTTPURLResponse *response, NSError *error, NSString *token, NSString *redirectedServer) {
        
        NSString *message;

        NSInteger errorCode = response.statusCode;
        if (errorCode == 0 || (errorCode >= 200 && errorCode < 300))
            errorCode = error.code;
        
        // Error
        if (errorCode == 503)
            message = NSLocalizedStringFromTable(@"_server_error_retry_", @"Error", nil);
        else
            message = [error.userInfo valueForKey:@"NSLocalizedDescription"];

        // Request trusted certificated
        if ([error code] == NSURLErrorServerCertificateUntrusted && self.delegate)
            [[CCCertificate sharedManager] presentViewControllerCertificateWithTitle:[error localizedDescription] viewController:(UIViewController *)self.delegate delegate:self];
        
        // Activity
        [[NCManageDatabase sharedInstance] addActivityClient:serverUrl fileID:@"" action:k_activityDebugActionListingFavorites selector:@"" note:[error.userInfo valueForKey:@"NSLocalizedDescription"] type:k_activityTypeFailure verbose:k_activityVerboseHigh activeUrl:_activeUrl];

        failure(message, errorCode);
    }];
}

#pragma --------------------------------------------------------------------------------------------
#pragma mark ===== Create Folder =====
#pragma --------------------------------------------------------------------------------------------

- (void)createFolder:(NSString *)fileName serverUrl:(NSString *)serverUrl account:(NSString *)account success:(void(^)(NSString *fileID, NSDate *date))success failure:(void (^)(NSString *message, NSInteger errorCode))failure
{
    NSString *path = [NSString stringWithFormat:@"%@/%@", serverUrl, fileName];
    NSString *autoUploadFileName = [[NCManageDatabase sharedInstance] getAccountAutoUploadFileName];
    NSString *autoUploadDirectory = [[NCManageDatabase sharedInstance] getAccountAutoUploadDirectory:_activeUrl];

    OCCommunication *communication = [CCNetworking sharedNetworking].sharedOCCommunication;

    [communication setCredentialsWithUser:_activeUser andUserID:_activeUserID andPassword:_activePassword];
    [communication setUserAgent:[CCUtility getUserAgent]];
    
    [communication createFolder:path onCommunication:communication withForbiddenCharactersSupported:YES successRequest:^(NSHTTPURLResponse *response, NSString *redirectedServer) {

        if (![[[NCManageDatabase sharedInstance] getAccountActive].account isEqualToString:account]) {
            
            failure(NSLocalizedStringFromTable(@"_error_user_not_available_", @"Error", nil), k_CCErrorUserNotAvailble);
            
        } else {
            
            NSDictionary *fields = [response allHeaderFields];
            
            NSString *fileID = [CCUtility removeForbiddenCharactersFileSystem:[fields objectForKey:@"OC-FileId"]];
            NSDate *date = [CCUtility dateEnUsPosixFromCloud:[fields objectForKey:@"Date"]];
            
            success(fileID, date);
        }
        
    } failureRequest:^(NSHTTPURLResponse *response, NSError *error, NSString *redirectedServer) {

        NSString *message;
        
        if (([fileName isEqualToString:autoUploadFileName] && [serverUrl isEqualToString:autoUploadDirectory]))
            message = nil;
        else
            message = [CCError manageErrorOC:response.statusCode error:error];
        
        NSInteger errorCode = response.statusCode;
        if (errorCode == 0 || (errorCode >= 200 && errorCode < 300))
            errorCode = error.code;

        // Request trusted certificated
        if ([error code] == NSURLErrorServerCertificateUntrusted && self.delegate)
            [[CCCertificate sharedManager] presentViewControllerCertificateWithTitle:[error localizedDescription] viewController:(UIViewController *)self.delegate delegate:self];
        
        // Activity
        [[NCManageDatabase sharedInstance] addActivityClient:path fileID:@"" action:k_activityDebugActionCreateFolder selector:@"" note:NSLocalizedStringFromTable(@"_not_possible_create_folder_", @"Error", nil) type:k_activityTypeFailure verbose:k_activityVerboseDefault activeUrl:_activeUrl];

        failure(message, errorCode);

    } errorBeforeRequest:^(NSError *error) {
        
        NSString *message;
    
        if (([fileName isEqualToString:autoUploadFileName] && [serverUrl isEqualToString:autoUploadDirectory]))
            message = nil;
        else {
            if (error.code == OCErrorForbidenCharacters)
                message = NSLocalizedStringFromTable(@"_forbidden_characters_from_server_", @"Error", nil);
            else
                message = NSLocalizedStringFromTable(@"_unknow_response_server_", @"Error", nil);
        }
        
        failure(message, error.code);
    }];
}

#pragma --------------------------------------------------------------------------------------------
#pragma mark =====  Delete =====
#pragma --------------------------------------------------------------------------------------------

- (void)deleteFileOrFolder:(NSString *)fileName serverUrl:(NSString *)serverUrl completion:(void (^)(NSString *message, NSInteger errorCode))completion
{    
    NSString *serverFilePath = [NSString stringWithFormat:@"%@/%@", serverUrl, fileName];
    
    OCCommunication *communication = [CCNetworking sharedNetworking].sharedOCCommunication;

    [communication setCredentialsWithUser:_activeUser andUserID:_activeUserID andPassword:_activePassword];
    [communication setUserAgent:[CCUtility getUserAgent]];
    
    [communication deleteFileOrFolder:serverFilePath onCommunication:communication successRequest:^(NSHTTPURLResponse *response, NSString *redirectedServer) {
        
        completion(nil, 0);
        
    } failureRquest:^(NSHTTPURLResponse *response, NSError *error, NSString *redirectedServer) {
        
        NSString *message;
        
        NSInteger errorCode = response.statusCode;
        if (errorCode == 0 || (errorCode >= 200 && errorCode < 300))
            errorCode = error.code;
        
        // Error
        if (errorCode == 503)
            message = NSLocalizedStringFromTable(@"_server_error_retry_", @"Error", nil);
        else
            message = [error.userInfo valueForKey:@"NSLocalizedDescription"];
        
        // Request trusted certificated
        if ([error code] == NSURLErrorServerCertificateUntrusted && self.delegate)
            [[CCCertificate sharedManager] presentViewControllerCertificateWithTitle:[error localizedDescription] viewController:(UIViewController *)self.delegate delegate:self];
        
        // Activity
        [[NCManageDatabase sharedInstance] addActivityClient:serverUrl fileID:@"" action:k_activityDebugActionDeleteFileFolder selector:@"" note:[error.userInfo valueForKey:@"NSLocalizedDescription"] type:k_activityTypeFailure verbose:k_activityVerboseHigh activeUrl:_activeUrl];
        
        completion(message, errorCode);
    }];
}

#pragma --------------------------------------------------------------------------------------------
#pragma mark ===== Move =====
#pragma --------------------------------------------------------------------------------------------

- (void)moveFileOrFolder
{
    NSString *fileNamePath = [NSString stringWithFormat:@"%@/%@", _metadataNet.serverUrl, _metadataNet.fileName];
    NSString *fileNameToPath = [NSString stringWithFormat:@"%@/%@", _metadataNet.serverUrlTo, _metadataNet.fileNameTo];
    
    [self moveFileOrFolder:fileNamePath fileNameTo:fileNameToPath success:^{
        
        if ([_metadataNet.selector isEqualToString:selectorRename] && [self.delegate respondsToSelector:@selector(renameSuccess:)])
            [self.delegate renameSuccess:_metadataNet];
        
        if ([_metadataNet.selector isEqualToString:selectorMove] && [self.delegate respondsToSelector:@selector(moveSuccess:)])
            [self.delegate moveSuccess:_metadataNet];
        
        [self complete];
        
    } failure:^(NSString *message, NSInteger errorCode) {
        
        if ([self.delegate respondsToSelector:@selector(renameMoveFileOrFolderFailure:message:errorCode:)])
            [self.delegate renameMoveFileOrFolderFailure:_metadataNet message:message errorCode:errorCode];

        [self complete];
    }];
}

- (void)moveFileOrFolder:(NSString *)fileName fileNameTo:(NSString *)fileNameTo success:(void (^)(void))success failure:(void (^)(NSString *message, NSInteger errorCode))failure
{
    OCCommunication *communication = [CCNetworking sharedNetworking].sharedOCCommunication;
    
    [communication setCredentialsWithUser:_activeUser andUserID:_activeUserID andPassword:_activePassword];
    [communication setUserAgent:[CCUtility getUserAgent]];
    
    [communication moveFileOrFolder:fileName toDestiny:fileNameTo onCommunication:communication withForbiddenCharactersSupported:YES successRequest:^(NSHTTPURLResponse *response, NSString *redirectedServer) {

        success();
        
    } failureRequest:^(NSHTTPURLResponse *response, NSError *error, NSString *redirectedServer) {
        
        NSInteger errorCode = response.statusCode;
        if (errorCode == 0 || (errorCode >= 200 && errorCode < 300))
            errorCode = error.code;
        
        NSString *message = [CCError manageErrorOC:response.statusCode error:error];
        
        failure(message, error.code);
        
    } errorBeforeRequest:^(NSError *error) {
        
        NSString *message;
        
        if (error.code == OCErrorMovingTheDestinyAndOriginAreTheSame) {
            message = NSLocalizedStringFromTable(@"_error_folder_destiny_is_the_same_", @"Error", nil);
        } else if (error.code == OCErrorMovingFolderInsideHimself) {
            message = NSLocalizedStringFromTable(@"_error_folder_destiny_is_the_same_", @"Error", nil);
        } else if (error.code == OCErrorMovingDestinyNameHaveForbiddenCharacters) {
            message = NSLocalizedStringFromTable(@"_forbidden_characters_from_server_", @"Error", nil);
        } else {
            message = NSLocalizedStringFromTable(@"_unknow_response_server_", @"Error", nil);
        }
        
        failure(message, error.code);
    }];
}

#pragma --------------------------------------------------------------------------------------------
#pragma mark ===== Shared =====
#pragma --------------------------------------------------------------------------------------------

- (void)readShareServer
{
#ifndef EXTENSION
    AppDelegate *appDelegate = (AppDelegate *)[[UIApplication sharedApplication] delegate];
    OCCommunication *communication = [CCNetworking sharedNetworking].sharedOCCommunication;
    
    [communication setCredentialsWithUser:_activeUser andUserID:_activeUserID andPassword:_activePassword];
    [communication setUserAgent:[CCUtility getUserAgent]];
    
    [communication readSharedByServer:[_activeUrl stringByAppendingString:@"/"] onCommunication:communication successRequest:^(NSHTTPURLResponse *response, NSArray *items, NSString *redirectedServer) {
        
        // Test active account
        tableAccount *recordAccount = [[NCManageDatabase sharedInstance] getAccountActive];
        if (![recordAccount.account isEqualToString:_metadataNet.account]) {
            if ([self.delegate respondsToSelector:@selector(shareFailure:message:errorCode:)])
                [self.delegate shareFailure:_metadataNet message:NSLocalizedStringFromTable(@"_error_user_not_available_", @"Error", nil) errorCode:k_CCErrorUserNotAvailble];
            
            [self complete];
            return;
        }
        
        BOOL openWindow = NO;
        
        [appDelegate.sharesID removeAllObjects];
        
        if ([recordAccount.account isEqualToString:_metadataNet.account]) {
        
            for (OCSharedDto *item in items)
                [appDelegate.sharesID setObject:item forKey:[@(item.idRemoteShared) stringValue]];
            
            if ([_metadataNet.selector isEqual:selectorOpenWindowShare]) openWindow = YES;
            
            if ([_metadataNet.action isEqual:actionUpdateShare]) openWindow = YES;
            if ([_metadataNet.action isEqual:actionShare]) openWindow = YES;
            if ([_metadataNet.action isEqual:actionShareWith]) openWindow = YES;
        }
        
        if([self.delegate respondsToSelector:@selector(readSharedSuccess:items:openWindow:)])
            [self.delegate readSharedSuccess:_metadataNet items:appDelegate.sharesID openWindow:openWindow];
        
        [self complete];
        
    } failureRequest :^(NSHTTPURLResponse *response, NSError *error, NSString *redirectedServer) {
        
        NSInteger errorCode = response.statusCode;
        if (errorCode == 0 || (errorCode >= 200 && errorCode < 300))
            errorCode = error.code;
        
        // Error
        if ([self.delegate respondsToSelector:@selector(shareFailure:message:errorCode:)]) {
            
            if (errorCode == 503)
                [self.delegate shareFailure:_metadataNet message:NSLocalizedStringFromTable(@"_server_error_retry_", @"Error", nil) errorCode:errorCode];
            else
                [self.delegate shareFailure:_metadataNet message:[error.userInfo valueForKey:@"NSLocalizedDescription"] errorCode:errorCode];
        }
        
        // Request trusted certificated
        if ([error code] == NSURLErrorServerCertificateUntrusted && self.delegate)
            [[CCCertificate sharedManager] presentViewControllerCertificateWithTitle:[error localizedDescription] viewController:(UIViewController *)self.delegate delegate:self];
        
        [self complete];
    }];
#endif
}

- (void)share
{
    OCCommunication *communication = [CCNetworking sharedNetworking].sharedOCCommunication;
        
    [communication setCredentialsWithUser:_activeUser andUserID:_activeUserID andPassword:_activePassword];
    [communication setUserAgent:[CCUtility getUserAgent]];
    
    [communication shareFileOrFolderByServer:[_activeUrl stringByAppendingString:@"/"] andFileOrFolderPath:[_metadataNet.fileName encodeString:NSUTF8StringEncoding] andPassword:[_metadataNet.password encodeString:NSUTF8StringEncoding] onCommunication:communication successRequest:^(NSHTTPURLResponse *response, NSString *token, NSString *redirectedServer) {
        
        [self readShareServer];
        
    } failureRequest :^(NSHTTPURLResponse *response, NSError *error, NSString *redirectedServer) {
        
        NSInteger errorCode = response.statusCode;
        if (errorCode == 0 || (errorCode >= 200 && errorCode < 300))
            errorCode = error.code;

        // Error
        if ([self.delegate respondsToSelector:@selector(shareFailure:message:errorCode:)]) {
            
            if (errorCode == 503)
                [self.delegate shareFailure:_metadataNet message:NSLocalizedStringFromTable(@"_server_error_retry_", @"Error", nil) errorCode:errorCode];
            else
                [self.delegate shareFailure:_metadataNet message:[error.userInfo valueForKey:@"NSLocalizedDescription"] errorCode:errorCode];
        }

        // Request trusted certificated
        if ([error code] == NSURLErrorServerCertificateUntrusted && self.delegate)
            [[CCCertificate sharedManager] presentViewControllerCertificateWithTitle:[error localizedDescription] viewController:(UIViewController *)self.delegate delegate:self];
        
        [self complete];
    }];
}

// * @param shareeType -> NSInteger: to set the type of sharee (user/group/federated)

- (void)shareWith
{
    OCCommunication *communication = [CCNetworking sharedNetworking].sharedOCCommunication;
    
    [communication setCredentialsWithUser:_activeUser andUserID:_activeUserID andPassword:_activePassword];
    [communication setUserAgent:[CCUtility getUserAgent]];
    
    [communication shareWith:_metadataNet.share shareeType:_metadataNet.shareeType inServer:[_activeUrl stringByAppendingString:@"/"] andFileOrFolderPath:[_metadataNet.fileName encodeString:NSUTF8StringEncoding] andPermissions:_metadataNet.sharePermission onCommunication:communication successRequest:^(NSHTTPURLResponse *response, NSString *redirectedServer) {
        
        [self readShareServer];
                
    } failureRequest:^(NSHTTPURLResponse *response, NSError *error, NSString *redirectedServer) {
        
        NSInteger errorCode = response.statusCode;
        if (errorCode == 0 || (errorCode >= 200 && errorCode < 300))
            errorCode = error.code;

        // Error
        if ([self.delegate respondsToSelector:@selector(shareFailure:message:errorCode:)]) {
            
            if (errorCode == 503)
                [self.delegate shareFailure:_metadataNet message:NSLocalizedStringFromTable(@"_server_error_retry_", @"Error", nil) errorCode:errorCode];
            else
                [self.delegate shareFailure:_metadataNet message:[error.userInfo valueForKey:@"NSLocalizedDescription"] errorCode:errorCode];
        }

        // Request trusted certificated
        if ([error code] == NSURLErrorServerCertificateUntrusted && self.delegate)
            [[CCCertificate sharedManager] presentViewControllerCertificateWithTitle:[error localizedDescription] viewController:(UIViewController *)self.delegate delegate:self];
        
        [self complete];
    }];
}

- (void)updateShare
{
    OCCommunication *communication = [CCNetworking sharedNetworking].sharedOCCommunication;
    
    [communication setCredentialsWithUser:_activeUser andUserID:_activeUserID andPassword:_activePassword];
    [communication setUserAgent:[CCUtility getUserAgent]];
    
    [communication updateShare:[_metadataNet.share intValue] ofServerPath:[_activeUrl stringByAppendingString:@"/"] withPasswordProtect:[_metadataNet.password encodeString:NSUTF8StringEncoding] andExpirationTime:_metadataNet.expirationTime andPermissions:_metadataNet.sharePermission onCommunication:communication successRequest:^(NSHTTPURLResponse *response, NSString *redirectedServer) {
        
        [self readShareServer];
        
    } failureRequest:^(NSHTTPURLResponse *response, NSError *error, NSString *redirectedServer) {
        
#ifndef EXTENSION
        AppDelegate *appDelegate = (AppDelegate *)[[UIApplication sharedApplication] delegate];

        [appDelegate messageNotification:@"_error_" description:[CCError manageErrorOC:response.statusCode error:error] visible:YES delay:k_dismissAfterSecond type:TWMessageBarMessageTypeError errorCode:error.code];
#endif
        
        NSInteger errorCode = response.statusCode;
        if (errorCode == 0 || (errorCode >= 200 && errorCode < 300))
            errorCode = error.code;

        // Error
        if ([self.delegate respondsToSelector:@selector(shareFailure:message:errorCode:)]) {
            
            if (errorCode == 503)
                [self.delegate shareFailure:_metadataNet message:NSLocalizedStringFromTable(@"_server_error_retry_", @"Error", nil) errorCode:errorCode];
            else
                [self.delegate shareFailure:_metadataNet message:[error.userInfo valueForKey:@"NSLocalizedDescription"] errorCode:errorCode];
        }

        // Request trusted certificated
        if ([error code] == NSURLErrorServerCertificateUntrusted && self.delegate)
            [[CCCertificate sharedManager] presentViewControllerCertificateWithTitle:[error localizedDescription] viewController:(UIViewController *)self.delegate delegate:self];
        
        [self complete];
    }];
}

- (void)unShare
{
    OCCommunication *communication = [CCNetworking sharedNetworking].sharedOCCommunication;
    
    [communication setCredentialsWithUser:_activeUser andUserID:_activeUserID andPassword:_activePassword];
    [communication setUserAgent:[CCUtility getUserAgent]];
    
    [communication unShareFileOrFolderByServer:[_activeUrl stringByAppendingString:@"/"] andIdRemoteShared:[_metadataNet.share intValue] onCommunication:communication successRequest:^(NSHTTPURLResponse *response, NSString *redirectedServer) {
        
        if([self.delegate respondsToSelector:@selector(unShareSuccess:)])
            [self.delegate unShareSuccess:_metadataNet];
        
        [self complete];
        
    } failureRequest:^(NSHTTPURLResponse *response, NSError *error, NSString *redirectedServer) {
        
#ifndef EXTENSION
        [(AppDelegate *)[[UIApplication sharedApplication] delegate] messageNotification:@"_error_" description:[CCError manageErrorOC:response.statusCode error:error] visible:YES delay:k_dismissAfterSecond type:TWMessageBarMessageTypeError errorCode:error.code];
#endif
        
        NSInteger errorCode = response.statusCode;
        if (errorCode == 0 || (errorCode >= 200 && errorCode < 300))
            errorCode = error.code;

        // Error
        if ([self.delegate respondsToSelector:@selector(shareFailure:message:errorCode:)]) {
            
            if (errorCode == 503)
                [self.delegate shareFailure:_metadataNet message:NSLocalizedStringFromTable(@"_server_error_retry_", @"Error", nil) errorCode:errorCode];
            else
                [self.delegate shareFailure:_metadataNet message:[error.userInfo valueForKey:@"NSLocalizedDescription"] errorCode:errorCode];
        }
        
        // Request trusted certificated
        if ([error code] == NSURLErrorServerCertificateUntrusted && self.delegate)
            [[CCCertificate sharedManager] presentViewControllerCertificateWithTitle:[error localizedDescription] viewController:(UIViewController *)self.delegate delegate:self];
        
        [self complete];
    }];
}

- (void)getUserAndGroup
{
    OCCommunication *communication = [CCNetworking sharedNetworking].sharedOCCommunication;
    
    [communication setCredentialsWithUser:_activeUser andUserID:_activeUserID andPassword:_activePassword];
    [communication setUserAgent:[CCUtility getUserAgent]];
    
    [communication searchUsersAndGroupsWith:_metadataNet.optionAny forPage:1 with:50 ofServer:[_activeUrl stringByAppendingString:@"/"] onCommunication:communication successRequest:^(NSHTTPURLResponse *response, NSArray *itemList, NSString *redirectedServer) {
        
        if([self.delegate respondsToSelector:@selector(getUserAndGroupSuccess:items:)])
            [self.delegate getUserAndGroupSuccess:_metadataNet items:itemList];
        
        [self complete];
        
    } failureRequest:^(NSHTTPURLResponse *response, NSError *error, NSString *redirectedServer) {
        
        NSInteger errorCode = response.statusCode;
        if (errorCode == 0 || (errorCode >= 200 && errorCode < 300))
            errorCode = error.code;

        // Error
        if ([self.delegate respondsToSelector:@selector(getUserAndGroupFailure:message:errorCode:)]) {
            
            if (errorCode == 503)
                [self.delegate getUserAndGroupFailure:_metadataNet message:NSLocalizedStringFromTable(@"_server_error_retry_", @"Error", nil) errorCode:errorCode];
            else
                [self.delegate getUserAndGroupFailure:_metadataNet message:[error.userInfo valueForKey:@"NSLocalizedDescription"] errorCode:errorCode];
        }
        
        // Request trusted certificated
        if ([error code] == NSURLErrorServerCertificateUntrusted && self.delegate)
            [[CCCertificate sharedManager] presentViewControllerCertificateWithTitle:[error localizedDescription] viewController:(UIViewController *)self.delegate delegate:self];
        
        [self complete];
    }];
}

- (void)getSharePermissionsFile
{
    OCCommunication *communication = [CCNetworking sharedNetworking].sharedOCCommunication;

    NSString *fileName = [NSString stringWithFormat:@"%@/%@", _metadataNet.serverUrl, _metadataNet.fileName];
    
    [communication setCredentialsWithUser:_activeUser andUserID:_activeUserID andPassword:_activePassword];
    [communication setUserAgent:[CCUtility getUserAgent]];
    
    [communication getSharePermissionsFile:fileName onCommunication:communication successRequest:^(NSHTTPURLResponse *response, NSString *permissions, NSString *redirectedServer) {
        
        // Test active account
        tableAccount *recordAccount = [[NCManageDatabase sharedInstance] getAccountActive];
        if (![recordAccount.account isEqualToString:_metadataNet.account]) {
            if ([self.delegate respondsToSelector:@selector(getSharePermissionsFileFailure:message:errorCode:)])
                [self.delegate getSharePermissionsFileFailure:_metadataNet message:NSLocalizedStringFromTable(@"_error_user_not_available_", @"Error", nil) errorCode:k_CCErrorUserNotAvailble];
            
            [self complete];
            return;
        }
        
        if([self.delegate respondsToSelector:@selector(getSharePermissionsFileSuccess:permissions:)])
            [self.delegate getSharePermissionsFileSuccess:_metadataNet permissions:permissions];
        
        [self complete];
        
    } failureRequest:^(NSHTTPURLResponse *response, NSError *error, NSString *redirectedServer) {
        
        NSInteger errorCode = response.statusCode;
        if (errorCode == 0 || (errorCode >= 200 && errorCode < 300))
            errorCode = error.code;
        
        // Error
        if ([self.delegate respondsToSelector:@selector(getSharePermissionsFileFailure:message:errorCode:)]) {
            
            if (errorCode == 503)
                [self.delegate getSharePermissionsFileFailure:_metadataNet message:NSLocalizedStringFromTable(@"_server_error_retry_", @"Error", nil) errorCode:errorCode];
            else
                [self.delegate getSharePermissionsFileFailure:_metadataNet message:[error.userInfo valueForKey:@"NSLocalizedDescription"] errorCode:errorCode];
        }
        
        // Request trusted certificated
        if ([error code] == NSURLErrorServerCertificateUntrusted && self.delegate)
            [[CCCertificate sharedManager] presentViewControllerCertificateWithTitle:[error localizedDescription] viewController:(UIViewController *)self.delegate delegate:self];
        
        [self complete];
    }];
}

#pragma --------------------------------------------------------------------------------------------
#pragma mark ===== Activity =====
#pragma --------------------------------------------------------------------------------------------

- (void)getActivityServer
{
    OCCommunication *communication = [CCNetworking sharedNetworking].sharedOCCommunication;
    
    [communication setCredentialsWithUser:_activeUser andUserID:_activeUserID andPassword:_activePassword];
    [communication setUserAgent:[CCUtility getUserAgent]];
    
    [communication getActivityServer:[_activeUrl stringByAppendingString:@"/"] onCommunication:communication successRequest:^(NSHTTPURLResponse *response, NSArray *listOfActivity, NSString *redirectedServer) {
        
        // Test active account
        tableAccount *recordAccount = [[NCManageDatabase sharedInstance] getAccountActive];
        if (![recordAccount.account isEqualToString:_metadataNet.account]) {
            if ([self.delegate respondsToSelector:@selector(getActivityServerSuccessFailure:listOfActivity:message:errorCode:)])
                [self.delegate getActivityServerSuccessFailure:_metadataNet listOfActivity:nil message:NSLocalizedStringFromTable(@"_error_user_not_available_", @"Error", nil) errorCode:k_CCErrorUserNotAvailble];
            
            [self complete];
            return;
        }
        
        if ([self.delegate respondsToSelector:@selector(getActivityServerSuccessFailure:listOfActivity:message:errorCode:)])
            [self.delegate getActivityServerSuccessFailure:_metadataNet listOfActivity:listOfActivity message:nil errorCode:0];
        
        [self complete];
        
    } failureRequest:^(NSHTTPURLResponse *response, NSError *error, NSString *redirectedServer) {
        
        NSInteger errorCode = response.statusCode;
        if (errorCode == 0 || (errorCode >= 200 && errorCode < 300))
            errorCode = error.code;
        
        // Error
        if ([self.delegate respondsToSelector:@selector(getActivityServerSuccessFailure:listOfActivity:message:errorCode:)]) {
            
            if (errorCode == 503)
                [self.delegate getActivityServerSuccessFailure:_metadataNet listOfActivity:nil message:NSLocalizedStringFromTable(@"_server_error_retry_", @"Error", nil) errorCode:errorCode];
            else
                [self.delegate getActivityServerSuccessFailure:_metadataNet listOfActivity:nil message:[error.userInfo valueForKey:@"NSLocalizedDescription"] errorCode:errorCode];
        }

        // Request trusted certificated
        if ([error code] == NSURLErrorServerCertificateUntrusted && self.delegate)
            [[CCCertificate sharedManager] presentViewControllerCertificateWithTitle:[error localizedDescription] viewController:(UIViewController *)self.delegate delegate:self];
        
        [self complete];
    }];
}

#pragma --------------------------------------------------------------------------------------------
#pragma mark ===== External Sites =====
#pragma --------------------------------------------------------------------------------------------

- (void)getExternalSitesServer
{
    OCCommunication *communication = [CCNetworking sharedNetworking].sharedOCCommunication;
    
    [communication setCredentialsWithUser:_activeUser andUserID:_activeUserID andPassword:_activePassword];
    [communication setUserAgent:[CCUtility getUserAgent]];
    
    [communication getExternalSitesServer:[_activeUrl stringByAppendingString:@"/"] onCommunication:communication successRequest:^(NSHTTPURLResponse *response, NSArray *listOfExternalSites, NSString *redirectedServer) {
        
        // Test active account
        tableAccount *recordAccount = [[NCManageDatabase sharedInstance] getAccountActive];
        if (![recordAccount.account isEqualToString:_metadataNet.account]) {
            if ([self.delegate respondsToSelector:@selector(getExternalSitesServerSuccessFailure:listOfExternalSites:message:errorCode:)])
                [self.delegate getExternalSitesServerSuccessFailure:_metadataNet listOfExternalSites:nil message:NSLocalizedStringFromTable(@"_error_user_not_available_", @"Error", nil) errorCode:k_CCErrorUserNotAvailble];
            
            [self complete];
            return;
        }
        
        if ([self.delegate respondsToSelector:@selector(getExternalSitesServerSuccessFailure:listOfExternalSites:message:errorCode:)])
            [self.delegate getExternalSitesServerSuccessFailure:_metadataNet listOfExternalSites:listOfExternalSites message:nil errorCode:0];
        
        [self complete];
        
    } failureRequest:^(NSHTTPURLResponse *response, NSError *error, NSString *redirectedServer) {
        
        NSInteger errorCode = response.statusCode;
        if (errorCode == 0 || (errorCode >= 200 && errorCode < 300))
            errorCode = error.code;
        
        // Error
        if ([self.delegate respondsToSelector:@selector(getExternalSitesServerSuccessFailure:listOfExternalSites:message:errorCode:)]) {
            
            if (errorCode == 503)
                [self.delegate getExternalSitesServerSuccessFailure:_metadataNet listOfExternalSites:nil message:NSLocalizedStringFromTable(@"_server_error_retry_", @"Error", nil) errorCode:errorCode];
            else
                [self.delegate getExternalSitesServerSuccessFailure:_metadataNet listOfExternalSites:nil message:[error.userInfo valueForKey:@"NSLocalizedDescription"] errorCode:errorCode];
        }

        // Request trusted certificated
        if ([error code] == NSURLErrorServerCertificateUntrusted && self.delegate)
            [[CCCertificate sharedManager] presentViewControllerCertificateWithTitle:[error localizedDescription] viewController:(UIViewController *)self.delegate delegate:self];
        
        [self complete];
    }];

}
#pragma --------------------------------------------------------------------------------------------
#pragma mark ===== Middleware Ping =====
#pragma --------------------------------------------------------------------------------------------

/*
- (void)middlewarePing
{
    OCCommunication *communication = [CCNetworking sharedNetworking].sharedOCCommunication;
    
    [communication setCredentialsWithUser:_activeUser andPassword:_activePassword];
    [communication setUserAgent:[CCUtility getUserAgent]];
    
    [communication getMiddlewarePing:_metadataNet.serverUrl onCommunication:communication successRequest:^(NSHTTPURLResponse *response, NSArray *listOfExternalSites, NSString *redirectedServer) {
        
        [self complete];
        
    } failureRequest:^(NSHTTPURLResponse *response, NSError *error, NSString *redirectedServer) {
        
        NSInteger errorCode = response.statusCode;
        if (errorCode == 0 || (errorCode >= 200 && errorCode < 300))
            errorCode = error.code;
        
        // Error
        if ([self.delegate respondsToSelector:@selector(getExternalSitesServerFailure:message:errorCode:)]) {
            
            if (errorCode == 503)
                [self.delegate getExternalSitesServerFailure:_metadataNet message:NSLocalizedStringFromTable(@"_server_error_retry_", @"Error", nil) errorCode:errorCode];
            else
                [self.delegate getExternalSitesServerFailure:_metadataNet message:[error.userInfo valueForKey:@"NSLocalizedDescription"] errorCode:errorCode];
        }
        
        // Request trusted certificated
        if ([error code] == NSURLErrorServerCertificateUntrusted && self.delegate)
            [[CCCertificate sharedManager] presentViewControllerCertificateWithTitle:[error localizedDescription] viewController:(UIViewController *)self.delegate delegate:self];
        
        [self complete];
    }];
    
}
*/

#pragma --------------------------------------------------------------------------------------------
#pragma mark ===== Notification =====
#pragma --------------------------------------------------------------------------------------------

- (void)getNotificationServer
{
    OCCommunication *communication = [CCNetworking sharedNetworking].sharedOCCommunication;
    
    [communication setCredentialsWithUser:_activeUser andUserID:_activeUserID andPassword:_activePassword];
    [communication setUserAgent:[CCUtility getUserAgent]];
    
    [communication getNotificationServer:[_activeUrl stringByAppendingString:@"/"] onCommunication:communication successRequest:^(NSHTTPURLResponse *response, NSArray *listOfNotifications, NSString *redirectedServer) {
        
        // Test active account
        tableAccount *recordAccount = [[NCManageDatabase sharedInstance] getAccountActive];
        if (![recordAccount.account isEqualToString:_metadataNet.account]) {
            if ([self.delegate respondsToSelector:@selector(getNotificationServerSuccessFailure:listOfNotifications:message:errorCode:)])
                [self.delegate getNotificationServerSuccessFailure:_metadataNet listOfNotifications:nil message:NSLocalizedStringFromTable(@"_error_user_not_available_", @"Error", nil) errorCode:k_CCErrorUserNotAvailble];
            
            [self complete];
            return;
        }
        
        if ([self.delegate respondsToSelector:@selector(getNotificationServerSuccessFailure:listOfNotifications:message:errorCode:)])
            [self.delegate getNotificationServerSuccessFailure:_metadataNet listOfNotifications:listOfNotifications message:nil errorCode:0];
        
        [self complete];
        
    } failureRequest:^(NSHTTPURLResponse *response, NSError *error, NSString *redirectedServer) {
        
        NSInteger errorCode = response.statusCode;
        if (errorCode == 0 || (errorCode >= 200 && errorCode < 300))
            errorCode = error.code;
        
        // Error
        if ([self.delegate respondsToSelector:@selector(getNotificationServerSuccessFailure:listOfNotifications:message:errorCode:)]) {
            
            if (errorCode == 503)
                [self.delegate getNotificationServerSuccessFailure:_metadataNet listOfNotifications:nil message:NSLocalizedStringFromTable(@"_server_error_retry_", @"Error", nil) errorCode:errorCode];
            else
                [self.delegate getNotificationServerSuccessFailure:_metadataNet listOfNotifications:nil message:[error.userInfo valueForKey:@"NSLocalizedDescription"] errorCode:errorCode];
        }

        // Request trusted certificated
        if ([error code] == NSURLErrorServerCertificateUntrusted && self.delegate)
            [[CCCertificate sharedManager] presentViewControllerCertificateWithTitle:[error localizedDescription] viewController:(UIViewController *)self.delegate delegate:self];
        
        // Activity
        [[NCManageDatabase sharedInstance] addActivityClient:_activeUrl fileID:@"" action:k_activityDebugActionGetNotification selector:@"" note:[error.userInfo valueForKey:@"NSLocalizedDescription"] type:k_activityTypeFailure verbose:k_activityVerboseHigh activeUrl:_activeUrl];
        
        [self complete];
    }];
}

- (void)setNotificationServer
{
    OCCommunication *communication = [CCNetworking sharedNetworking].sharedOCCommunication;
    
    [communication setCredentialsWithUser:_activeUser andUserID:_activeUserID andPassword:_activePassword];
    [communication setUserAgent:[CCUtility getUserAgent]];
    
    NSString *type = _metadataNet.optionAny;
    
    [communication setNotificationServer:_metadataNet.serverUrl type:type onCommunication:communication successRequest:^(NSHTTPURLResponse *response, NSString *redirectedServer) {
        
        // Test active account
        tableAccount *recordAccount = [[NCManageDatabase sharedInstance] getAccountActive];
        if (![recordAccount.account isEqualToString:_metadataNet.account]) {
            if ([self.delegate respondsToSelector:@selector(setNotificationServerSuccessFailure:message:errorCode:)])
                [self.delegate setNotificationServerSuccessFailure:_metadataNet message:NSLocalizedStringFromTable(@"_error_user_not_available_", @"Error", nil) errorCode:k_CCErrorUserNotAvailble];
            
            [self complete];
            return;
        }
        
        if ([self.delegate respondsToSelector:@selector(setNotificationServerSuccessFailure:message:errorCode:)])
            [self.delegate setNotificationServerSuccessFailure:_metadataNet message:nil errorCode:0];
        
        [self complete];
        
    } failureRequest:^(NSHTTPURLResponse *response, NSError *error, NSString *redirectedServer) {
        
        NSInteger errorCode = response.statusCode;
        if (errorCode == 0 || (errorCode >= 200 && errorCode < 300))
            errorCode = error.code;
        
        // Error
        if ([self.delegate respondsToSelector:@selector(setNotificationServerSuccessFailure:message:errorCode:)]) {
            
            if (errorCode == 503)
                [self.delegate setNotificationServerSuccessFailure:_metadataNet message:NSLocalizedStringFromTable(@"_server_error_retry_", @"Error", nil) errorCode:errorCode];
            else
                [self.delegate setNotificationServerSuccessFailure:_metadataNet message:[error.userInfo valueForKey:@"NSLocalizedDescription"] errorCode:errorCode];
        }

        // Request trusted certificated
        if ([error code] == NSURLErrorServerCertificateUntrusted && self.delegate)
            [[CCCertificate sharedManager] presentViewControllerCertificateWithTitle:[error localizedDescription] viewController:(UIViewController *)self.delegate delegate:self];
        
        [self complete];
    }];
}

#pragma --------------------------------------------------------------------------------------------
#pragma mark ===== Push Notification =====
#pragma --------------------------------------------------------------------------------------------

- (void)subscribingPushNotificationServer:(NSString *)urlServer pushToken:(NSString *)pushToken Hash:(NSString *)pushTokenHash devicePublicKey:(NSString *)devicePublicKey success:(void (^)(void))success failure:(void (^)(NSString *message, NSInteger errorCode))failure
{
    OCCommunication *communication = [CCNetworking sharedNetworking].sharedOCCommunication;
    
    [communication setCredentialsWithUser:_activeUser andUserID:_activeUserID andPassword:_activePassword];
    [communication setUserAgent:[CCUtility getUserAgent]];
    
    devicePublicKey = [CCUtility URLEncodeStringFromString:devicePublicKey];

    [communication subscribingNextcloudServerPush:urlServer pushTokenHash:pushTokenHash devicePublicKey:devicePublicKey proxyServerPath: [NCBrandOptions sharedInstance].pushNotificationServer onCommunication:communication successRequest:^(NSHTTPURLResponse *response, NSString *publicKey, NSString *deviceIdentifier, NSString *signature, NSString *redirectedServer) {
        
        deviceIdentifier = [CCUtility URLEncodeStringFromString:deviceIdentifier];
        signature = [CCUtility URLEncodeStringFromString:signature];
        publicKey = [CCUtility URLEncodeStringFromString:publicKey];
        
        [communication subscribingPushProxy:[NCBrandOptions sharedInstance].pushNotificationServer pushToken:pushToken deviceIdentifier:deviceIdentifier deviceIdentifierSignature:signature userPublicKey:publicKey onCommunication:communication successRequest:^(NSHTTPURLResponse *response, NSString *redirectedServer) {
            
            // Activity
            [[NCManageDatabase sharedInstance] addActivityClient:[NCBrandOptions sharedInstance].pushNotificationServer fileID:@"" action:k_activityDebugActionPushProxy selector:@"" note:@"Service registered." type:k_activityTypeSuccess verbose:k_activityVerboseHigh activeUrl:_activeUrl];
            
            success();
            
        } failureRequest:^(NSHTTPURLResponse *response, NSError *error, NSString *redirectedServer) {
           
            NSString *message;

            NSInteger errorCode = response.statusCode;
            if (errorCode == 0 || (errorCode >= 200 && errorCode < 300))
                errorCode = error.code;
            
            // Error
            if (errorCode == 503)
                message = NSLocalizedStringFromTable(@"_server_error_retry_", @"Error", nil);
            else
                message = [error.userInfo valueForKey:@"NSLocalizedDescription"];
            
            // Activity
            [[NCManageDatabase sharedInstance] addActivityClient:[NCBrandOptions sharedInstance].pushNotificationServer fileID:@"" action:k_activityDebugActionPushProxy selector:@"" note:[error.userInfo valueForKey:@"NSLocalizedDescription"] type:k_activityTypeFailure verbose:k_activityVerboseHigh activeUrl:_activeUrl];
            
            failure(message, errorCode);
        }];
        
    } failureRequest:^(NSHTTPURLResponse *response, NSError *error, NSString *redirectedServer) {
        
        NSString *message;

        NSInteger errorCode = response.statusCode;
        if (errorCode == 0 || (errorCode >= 200 && errorCode < 300))
            errorCode = error.code;
    
        // Error
        if (errorCode == 503)
            message = NSLocalizedStringFromTable(@"_server_error_retry_", @"Error", nil);
        else
            message = [error.userInfo valueForKey:@"NSLocalizedDescription"];

        // Activity
        [[NCManageDatabase sharedInstance] addActivityClient:_activeUrl fileID:@"" action:k_activityDebugActionServerPush selector:@"" note:[error.userInfo valueForKey:@"NSLocalizedDescription"] type:k_activityTypeFailure verbose:k_activityVerboseHigh activeUrl:_activeUrl];
        
        failure(message, errorCode);
    }];
}

#pragma --------------------------------------------------------------------------------------------
#pragma mark =====  User Profile =====
#pragma --------------------------------------------------------------------------------------------

- (void)getUserProfile
{
    OCCommunication *communication = [CCNetworking sharedNetworking].sharedOCCommunication;
    
    [communication setCredentialsWithUser:_activeUser andUserID:_activeUserID andPassword:_activePassword];
    [communication setUserAgent:[CCUtility getUserAgent]];
    
    [communication getUserProfileServer:[_activeUrl stringByAppendingString:@"/"] onCommunication:communication successRequest:^(NSHTTPURLResponse *response, OCUserProfile *userProfile, NSString *redirectedServer) {
        
        // Test active account
        tableAccount *recordAccount = [[NCManageDatabase sharedInstance] getAccountActive];
        if (![recordAccount.account isEqualToString:_metadataNet.account]) {
            if ([self.delegate respondsToSelector:@selector(getUserProfileSuccessFailure:userProfile:message:errorCode:)])
                [self.delegate getUserProfileSuccessFailure:_metadataNet userProfile:nil message:NSLocalizedStringFromTable(@"_error_user_not_available_", @"Error", nil) errorCode:k_CCErrorUserNotAvailble];
            
            [self complete];
            return;
        }
        
        if ([self.delegate respondsToSelector:@selector(getUserProfileSuccessFailure:userProfile:message:errorCode:)])
            [self.delegate getUserProfileSuccessFailure:_metadataNet userProfile:userProfile message:nil errorCode:0];
        
        [self complete];
        
    } failureRequest:^(NSHTTPURLResponse *response, NSError *error, NSString *redirectedServer) {
        
        NSInteger errorCode = response.statusCode;
        if (errorCode == 0 || (errorCode >= 200 && errorCode < 300))
            errorCode = error.code;
        
        // Error
        if ([self.delegate respondsToSelector:@selector(getUserProfileSuccessFailure:userProfile:message:errorCode:)]) {
            
            if (errorCode == 503)
                [self.delegate getUserProfileSuccessFailure:_metadataNet userProfile:nil message:NSLocalizedStringFromTable(@"_server_error_retry_", @"Error", nil) errorCode:errorCode];
            else
                [self.delegate getUserProfileSuccessFailure:_metadataNet userProfile:nil message:[error.userInfo valueForKey:@"NSLocalizedDescription"] errorCode:errorCode];
        }

        // Request trusted certificated
        if ([error code] == NSURLErrorServerCertificateUntrusted && self.delegate)
            [[CCCertificate sharedManager] presentViewControllerCertificateWithTitle:[error localizedDescription] viewController:(UIViewController *)self.delegate delegate:self];
        
        [self complete];
    }];
}

#pragma --------------------------------------------------------------------------------------------
#pragma mark ===== Capabilities =====
#pragma --------------------------------------------------------------------------------------------

- (void)getCapabilitiesOfServer
{
    OCCommunication *communication = [CCNetworking sharedNetworking].sharedOCCommunication;
    
    [communication setCredentialsWithUser:_activeUser andUserID:_activeUserID andPassword:_activePassword];
    [communication setUserAgent:[CCUtility getUserAgent]];
    
    [communication getCapabilitiesOfServer:[_activeUrl stringByAppendingString:@"/"] onCommunication:communication successRequest:^(NSHTTPURLResponse *response, OCCapabilities *capabilities, NSString *redirectedServer) {
        
        // Test active account
        tableAccount *recordAccount = [[NCManageDatabase sharedInstance] getAccountActive];
        if (![recordAccount.account isEqualToString:_metadataNet.account]) {
            if ([self.delegate respondsToSelector:@selector(getCapabilitiesOfServerSuccessFailure:capabilities:message:errorCode:)])
                [self.delegate getCapabilitiesOfServerSuccessFailure:_metadataNet capabilities:nil message:NSLocalizedStringFromTable(@"_error_user_not_available_", @"Error", nil) errorCode:k_CCErrorUserNotAvailble];
            
            [self complete];
            return;
        }
        
        if ([self.delegate respondsToSelector:@selector(getCapabilitiesOfServerSuccessFailure:capabilities:message:errorCode:)])
            [self.delegate getCapabilitiesOfServerSuccessFailure:_metadataNet capabilities:capabilities message:nil errorCode:0];
        
        [self complete];
        
    } failureRequest:^(NSHTTPURLResponse *response, NSError *error, NSString *redirectedServer) {
        
        NSInteger errorCode = response.statusCode;
        if (errorCode == 0 || (errorCode >= 200 && errorCode < 300))
            errorCode = error.code;

        // Error
        if ([self.delegate respondsToSelector:@selector(getCapabilitiesOfServerSuccessFailure:capabilities:message:errorCode:)]) {

            if (errorCode == 503)
                [self.delegate getCapabilitiesOfServerSuccessFailure:_metadataNet capabilities:nil message:NSLocalizedStringFromTable(@"_server_error_retry_", @"Error", nil) errorCode:errorCode];
            else
                [self.delegate getCapabilitiesOfServerSuccessFailure:_metadataNet capabilities:nil message:[error.userInfo valueForKey:@"NSLocalizedDescription"] errorCode:errorCode];
        }

        // Request trusted certificated
        if ([error code] == NSURLErrorServerCertificateUntrusted && self.delegate)
            [[CCCertificate sharedManager] presentViewControllerCertificateWithTitle:[error localizedDescription] viewController:(UIViewController *)self.delegate delegate:self];

        // Activity
        [[NCManageDatabase sharedInstance] addActivityClient:_activeUrl fileID:@"" action:k_activityDebugActionCapabilities selector:@"" note:[error.userInfo valueForKey:@"NSLocalizedDescription"] type:k_activityTypeFailure verbose:k_activityVerboseHigh activeUrl:_activeUrl];
        
        [self complete];
    }];
}

#pragma --------------------------------------------------------------------------------------------
#pragma mark ===== End-to-End Encryption =====
#pragma --------------------------------------------------------------------------------------------

- (void)getEndToEndPublicKeys
{
    OCCommunication *communication = [CCNetworking sharedNetworking].sharedOCCommunication;
    
    [communication setCredentialsWithUser:_activeUser andUserID:_activeUserID andPassword:_activePassword];
    [communication setUserAgent:[CCUtility getUserAgent]];
    
    [communication getEndToEndPublicKeys:[_activeUrl stringByAppendingString:@"/"] onCommunication:communication successRequest:^(NSHTTPURLResponse *response, NSString *publicKey, NSString *redirectedServer) {
        
        _metadataNet.key = publicKey;

        if ([self.delegate respondsToSelector:@selector(getEndToEndPublicKeysSuccess:)])
            [self.delegate getEndToEndPublicKeysSuccess:_metadataNet];
        
        [self complete];
        
    } failureRequest:^(NSHTTPURLResponse *response, NSError *error, NSString *redirectedServer) {
        
        NSInteger errorCode = response.statusCode;
        if (errorCode == 0 || (errorCode >= 200 && errorCode < 300))
            errorCode = error.code;
        
        // Error
        if ([self.delegate respondsToSelector:@selector(getEndToEndPublicKeysFailure:message:errorCode:)])
            [self.delegate getEndToEndPublicKeysFailure:_metadataNet message:[error.userInfo valueForKey:@"NSLocalizedDescription"] errorCode:errorCode];
        
        // Request trusted certificated
        if ([error code] == NSURLErrorServerCertificateUntrusted && self.delegate)
            [[CCCertificate sharedManager] presentViewControllerCertificateWithTitle:[error localizedDescription] viewController:(UIViewController *)self.delegate delegate:self];
        
        [self complete];
    }];
}

- (void)getEndToEndPrivateKeyCipher
{
    OCCommunication *communication = [CCNetworking sharedNetworking].sharedOCCommunication;
    
    [communication setCredentialsWithUser:_activeUser andUserID:_activeUserID andPassword:_activePassword];
    [communication setUserAgent:[CCUtility getUserAgent]];
    
    [communication getEndToEndPrivateKeyCipher:[_activeUrl stringByAppendingString:@"/"] onCommunication:communication successRequest:^(NSHTTPURLResponse *response, NSString *privateKeyChiper, NSString *redirectedServer) {
        
        _metadataNet.key = privateKeyChiper;
        
        if ([self.delegate respondsToSelector:@selector(getEndToEndPrivateKeyCipherSuccess:)])
            [self.delegate getEndToEndPrivateKeyCipherSuccess:_metadataNet];
        
        [self complete];
        
    } failureRequest:^(NSHTTPURLResponse *response, NSError *error, NSString *redirectedServer) {
        
        NSInteger errorCode = response.statusCode;
        if (errorCode == 0 || (errorCode >= 200 && errorCode < 300))
            errorCode = error.code;
        
        // Error
        if ([self.delegate respondsToSelector:@selector(getEndToEndPrivateKeyCipherFailure:message:errorCode:)])
            [self.delegate getEndToEndPrivateKeyCipherFailure:_metadataNet message:[error.userInfo valueForKey:@"NSLocalizedDescription"] errorCode:errorCode];
        
        // Request trusted certificated
        if ([error code] == NSURLErrorServerCertificateUntrusted && self.delegate)
            [[CCCertificate sharedManager] presentViewControllerCertificateWithTitle:[error localizedDescription] viewController:(UIViewController *)self.delegate delegate:self];
        
        [self complete];
    }];
}

- (void)signEndToEndPublicKey
{
    OCCommunication *communication = [CCNetworking sharedNetworking].sharedOCCommunication;
    
    // URL Encode
    NSString *publicKey = [CCUtility URLEncodeStringFromString:_metadataNet.key];

    [communication setCredentialsWithUser:_activeUser andUserID:_activeUserID andPassword:_activePassword];
    [communication setUserAgent:[CCUtility getUserAgent]];
    
    [communication signEndToEndPublicKey:[_activeUrl stringByAppendingString:@"/"] publicKey:publicKey onCommunication:communication successRequest:^(NSHTTPURLResponse *response, NSString *publicKey, NSString *redirectedServer) {
        
        _metadataNet.key = publicKey;

        if ([self.delegate respondsToSelector:@selector(signEndToEndPublicKeySuccess:)])
            [self.delegate signEndToEndPublicKeySuccess:_metadataNet];
        
        [self complete];
        
    } failureRequest:^(NSHTTPURLResponse *response, NSError *error, NSString *redirectedServer) {
        
        NSInteger errorCode = response.statusCode;
        if (errorCode == 0 || (errorCode >= 200 && errorCode < 300))
            errorCode = error.code;
        
        // Error
        if ([self.delegate respondsToSelector:@selector(signEndToEndPublicKeyFailure:message:errorCode:)])
            [self.delegate signEndToEndPublicKeyFailure:_metadataNet message:[error.userInfo valueForKey:@"NSLocalizedDescription"] errorCode:errorCode];
        
        // Request trusted certificated
        if ([error code] == NSURLErrorServerCertificateUntrusted && self.delegate)
            [[CCCertificate sharedManager] presentViewControllerCertificateWithTitle:[error localizedDescription] viewController:(UIViewController *)self.delegate delegate:self];
        
        [self complete];
    }];
}

- (void)storeEndToEndPrivateKeyCipher
{
    OCCommunication *communication = [CCNetworking sharedNetworking].sharedOCCommunication;
    
    // URL Encode
    NSString *privateKeyChiper = [CCUtility URLEncodeStringFromString:_metadataNet.keyCipher];
    
    [communication setCredentialsWithUser:_activeUser andUserID:_activeUserID andPassword:_activePassword];
    [communication setUserAgent:[CCUtility getUserAgent]];
    
    [communication storeEndToEndPrivateKeyCipher:[_activeUrl stringByAppendingString:@"/"] privateKeyChiper:privateKeyChiper onCommunication:communication successRequest:^(NSHTTPURLResponse *response, NSString *privateKey, NSString *redirectedServer) {
        
        if ([self.delegate respondsToSelector:@selector(storeEndToEndPrivateKeyCipherSuccess:)])
            [self.delegate storeEndToEndPrivateKeyCipherSuccess:_metadataNet];
        
        [self complete];
        
    } failureRequest:^(NSHTTPURLResponse *response, NSError *error, NSString *redirectedServer) {
        
        NSInteger errorCode = response.statusCode;
        if (errorCode == 0 || (errorCode >= 200 && errorCode < 300))
            errorCode = error.code;
        
        // Error
        if ([self.delegate respondsToSelector:@selector(storeEndToEndPrivateKeyCipherFailure:message:errorCode:)])
            [self.delegate storeEndToEndPrivateKeyCipherFailure:_metadataNet message:[error.userInfo valueForKey:@"NSLocalizedDescription"] errorCode:errorCode];
        
        // Request trusted certificated
        if ([error code] == NSURLErrorServerCertificateUntrusted && self.delegate)
            [[CCCertificate sharedManager] presentViewControllerCertificateWithTitle:[error localizedDescription] viewController:(UIViewController *)self.delegate delegate:self];
        
        [self complete];
    }];
}

- (void)deleteEndToEndPublicKey
{
    OCCommunication *communication = [CCNetworking sharedNetworking].sharedOCCommunication;
    
    [communication setCredentialsWithUser:_activeUser andUserID:_activeUserID andPassword:_activePassword];
    [communication setUserAgent:[CCUtility getUserAgent]];
    
    [communication deleteEndToEndPublicKey:[_activeUrl stringByAppendingString:@"/"] onCommunication:communication successRequest:^(NSHTTPURLResponse *response, NSString *redirectedServer) {
        
        if ([self.delegate respondsToSelector:@selector(deleteEndToEndPublicKeySuccess:)])
            [self.delegate deleteEndToEndPublicKeySuccess:_metadataNet];
        
        [self complete];
        
    } failureRequest:^(NSHTTPURLResponse *response, NSError *error, NSString *redirectedServer) {
        
        NSInteger errorCode = response.statusCode;
        if (errorCode == 0 || (errorCode >= 200 && errorCode < 300))
            errorCode = error.code;
        
        // Error
        if ([self.delegate respondsToSelector:@selector(deleteEndToEndPublicKeyFailure:message:errorCode:)])
            [self.delegate deleteEndToEndPublicKeyFailure:_metadataNet message:[error.userInfo valueForKey:@"NSLocalizedDescription"] errorCode:errorCode];
        
        // Request trusted certificated
        if ([error code] == NSURLErrorServerCertificateUntrusted && self.delegate)
            [[CCCertificate sharedManager] presentViewControllerCertificateWithTitle:[error localizedDescription] viewController:(UIViewController *)self.delegate delegate:self];
        
        [self complete];
    }];
}

- (void)deleteEndToEndPrivateKey
{
    OCCommunication *communication = [CCNetworking sharedNetworking].sharedOCCommunication;
    
    [communication setCredentialsWithUser:_activeUser andUserID:_activeUserID andPassword:_activePassword];
    [communication setUserAgent:[CCUtility getUserAgent]];
    
    [communication deleteEndToEndPrivateKey:[_activeUrl stringByAppendingString:@"/"] onCommunication:communication successRequest:^(NSHTTPURLResponse *response, NSString *redirectedServer) {
        
        if ([self.delegate respondsToSelector:@selector(deleteEndToEndPrivateKeySuccess:)])
            [self.delegate deleteEndToEndPrivateKeySuccess:_metadataNet];
        
        [self complete];
        
    } failureRequest:^(NSHTTPURLResponse *response, NSError *error, NSString *redirectedServer) {
        
        NSInteger errorCode = response.statusCode;
        if (errorCode == 0 || (errorCode >= 200 && errorCode < 300))
            errorCode = error.code;
        
        // Error
        if ([self.delegate respondsToSelector:@selector(deleteEndToEndPrivateKeyFailure:message:errorCode:)])
            [self.delegate deleteEndToEndPrivateKeyFailure:_metadataNet message:[error.userInfo valueForKey:@"NSLocalizedDescription"] errorCode:errorCode];
        
        // Request trusted certificated
        if ([error code] == NSURLErrorServerCertificateUntrusted && self.delegate)
            [[CCCertificate sharedManager] presentViewControllerCertificateWithTitle:[error localizedDescription] viewController:(UIViewController *)self.delegate delegate:self];
        
        [self complete];
    }];
}

- (void)getEndToEndServerPublicKey
{
    OCCommunication *communication = [CCNetworking sharedNetworking].sharedOCCommunication;
    
    [communication setCredentialsWithUser:_activeUser andUserID:_activeUserID andPassword:_activePassword];
    [communication setUserAgent:[CCUtility getUserAgent]];
    
    [communication getEndToEndServerPublicKey:[_activeUrl stringByAppendingString:@"/"] onCommunication:communication successRequest:^(NSHTTPURLResponse *response, NSString *publicKey, NSString *redirectedServer) {
        
        _metadataNet.key = publicKey;
        
        if ([self.delegate respondsToSelector:@selector(getEndToEndServerPublicKeySuccess:)])
            [self.delegate getEndToEndServerPublicKeySuccess:_metadataNet];
        
        [self complete];
        
    } failureRequest:^(NSHTTPURLResponse *response, NSError *error, NSString *redirectedServer) {
        
        NSInteger errorCode = response.statusCode;
        if (errorCode == 0 || (errorCode >= 200 && errorCode < 300))
            errorCode = error.code;
        
        // Error
        if ([self.delegate respondsToSelector:@selector(getEndToEndServerPublicKeyFailure:message:errorCode:)])
            [self.delegate getEndToEndServerPublicKeyFailure:_metadataNet message:[error.userInfo valueForKey:@"NSLocalizedDescription"] errorCode:errorCode];
        
        // Request trusted certificated
        if ([error code] == NSURLErrorServerCertificateUntrusted && self.delegate)
            [[CCCertificate sharedManager] presentViewControllerCertificateWithTitle:[error localizedDescription] viewController:(UIViewController *)self.delegate delegate:self];
        
        [self complete];
    }];
}

@end

#pragma --------------------------------------------------------------------------------------------
#pragma mark =====  OCURLSessionManager =====
#pragma --------------------------------------------------------------------------------------------

@implementation OCURLSessionManager

- (void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential *credential))completionHandler
{
    // The pinnning check
    if ([[CCCertificate sharedManager] checkTrustedChallenge:challenge]) {
        completionHandler(NSURLSessionAuthChallengeUseCredential, [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust]);
    } else {
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
    }
}

@end
