//
//  NCPushNotification.m
//  Nextcloud
//
//  Created by Marino Faggiana on 25/07/18.
//  Copyright © 2018 TWS. All rights reserved.
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

#import "NCPushNotification.h"

#import <openssl/rsa.h>
#import <openssl/pem.h>
#import <openssl/bio.h>
#import <openssl/bn.h>
#import <openssl/sha.h>
#import <openssl/err.h>
#import <openssl/ssl.h>
#import <CommonCrypto/CommonDigest.h>

#import "NCEndToEndEncryption.h"
#import "CCUtility.h"

@implementation NCPushNotification


- (BOOL)generatePushNotificationsKeyPair
{
    EVP_PKEY *pkey;
    NSError *keyError;
    pkey = [[NCEndToEndEncryption sharedManager] generateRSAKey:&keyError];
    if (keyError) {
        return NO;
    }
    
    // Extract publicKey, privateKey
    int len;
    char *keyBytes;
    
    // PublicKey
    BIO *publicKeyBIO = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(publicKeyBIO, pkey);
    
    len = BIO_pending(publicKeyBIO);
    keyBytes  = malloc(len);
    
    BIO_read(publicKeyBIO, keyBytes, len);
    _ncPNPublicKey = [NSData dataWithBytes:keyBytes length:len];
    [CCUtility setPushNotificationPublicKey:_ncPNPublicKey];
    NSLog(@"Push Notifications Key Pair generated: \n%@", [[NSString alloc] initWithData:_ncPNPublicKey encoding:NSUTF8StringEncoding]);
    
    // PrivateKey
    BIO *privateKeyBIO = BIO_new(BIO_s_mem());
    PEM_write_bio_PKCS8PrivateKey(privateKeyBIO, pkey, NULL, NULL, 0, NULL, NULL);
    
    len = BIO_pending(privateKeyBIO);
    keyBytes = malloc(len);
    
    BIO_read(privateKeyBIO, keyBytes, len);
    _ncPNPrivateKey = [NSData dataWithBytes:keyBytes length:len];
    [CCUtility setPushNotificationPrivateKey:_ncPNPrivateKey];
    
    EVP_PKEY_free(pkey);
    
    return YES;
}


@end
