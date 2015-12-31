//
//  FSOpenSSL.m
//  OpenSSL-for-iOS
//
//  Created by Felix Schulze on 16.03.2013.
//  Copyright 2013 Felix Schulze. All rights reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

#import "FSOpenSSL.h"
#include <openssl/md5.h>
#include <openssl/sha.h>
#import <openssl/evp.h>
#include <openssl/aes.h>

static const int blockSize = 6144;
static const int enBlockSize = 16;


@implementation FSOpenSSL

+ (NSString *)md5FromString:(NSString *)string {
    unsigned char *inStrg = (unsigned char *) [[string dataUsingEncoding:NSASCIIStringEncoding] bytes];
    unsigned long lngth = [string length];
    unsigned char result[MD5_DIGEST_LENGTH];
    NSMutableString *outStrg = [NSMutableString string];

    MD5(inStrg, lngth, result);

    unsigned int i;
    for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
        [outStrg appendFormat:@"%02x", result[i]];
    }
    return [outStrg copy];
}

+ (NSString *)sha256FromString:(NSString *)string {
    unsigned char *inStrg = (unsigned char *) [[string dataUsingEncoding:NSASCIIStringEncoding] bytes];
    unsigned long lngth = [string length];
    unsigned char result[SHA256_DIGEST_LENGTH];
    NSMutableString *outStrg = [NSMutableString string];

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, inStrg, lngth);
    SHA256_Final(result, &sha256);

    unsigned int i;
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        [outStrg appendFormat:@"%02x", result[i]];
    }
    return [outStrg copy];
}

+ (NSString *)base64FromString:(NSString *)string encodeWithNewlines:(BOOL)encodeWithNewlines {
    BIO *mem = BIO_new(BIO_s_mem());
    BIO *b64 = BIO_new(BIO_f_base64());

    if (!encodeWithNewlines) {
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    }
    mem = BIO_push(b64, mem);

    NSData *stringData = [string dataUsingEncoding:NSUTF8StringEncoding];
    NSUInteger length = stringData.length;
    void *buffer = (void *) [stringData bytes];
    int bufferSize = (int)MIN(length, INT_MAX);

    NSUInteger count = 0;

    BOOL error = NO;

    // Encode the data
    while (!error && count < length) {
        int result = BIO_write(mem, buffer, bufferSize);
        if (result <= 0) {
            error = YES;
        }
        else {
            count += result;
            buffer = (void *) [stringData bytes] + count;
            bufferSize = (int)MIN((length - count), INT_MAX);
        }
    }

    int flush_result = BIO_flush(mem);
    if (flush_result != 1) {
        return nil;
    }

    char *base64Pointer;
    NSUInteger base64Length = (NSUInteger) BIO_get_mem_data(mem, &base64Pointer);

    NSData *base64data = [NSData dataWithBytesNoCopy:base64Pointer length:base64Length freeWhenDone:NO];
    NSString *base64String = [[NSString alloc] initWithData:base64data encoding:NSUTF8StringEncoding];

    BIO_free_all(mem);
    return base64String;
}



+ (NSData *)aesEncryptWithKey:(NSString *)key plainData:(NSData *)plainData
{
    size_t bufferSize = [plainData length];
    unsigned char inbuf[1024];
    unsigned char encbuf[1024];
    memcpy(inbuf, [plainData bytes], [plainData length]);
    memset(encbuf, 0, sizeof(encbuf));
    
    unsigned char *key32 = (unsigned char*)[[key dataUsingEncoding:NSASCIIStringEncoding] bytes];
    unsigned char iv[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    
    AES_KEY aeskey;
    
    AES_set_encrypt_key(key32, 32*8, &aeskey);
    AES_cbc_encrypt(inbuf, encbuf, bufferSize, &aeskey, iv, AES_ENCRYPT);
    
    return [[NSData alloc]initWithBytes:encbuf length:bufferSize];
}


+ (NSData *)aesDecryptWithKey:(NSString *)key cipherData:(NSData *)cipherData
{
    size_t bufferSize = [cipherData length];
    unsigned char inbuf[1024];
    unsigned char decbuf[1024];
    memcpy(inbuf, [cipherData bytes], [cipherData length]);
    memset(decbuf, 0, sizeof(decbuf));
    
    unsigned char *deckey32 = (unsigned char*)[[key dataUsingEncoding:NSASCIIStringEncoding] bytes];
    unsigned char deciv[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    
    AES_KEY aesdeckey;
    
    AES_set_decrypt_key(deckey32, 32*8, &aesdeckey);
    AES_cbc_encrypt(inbuf, decbuf, bufferSize, &aesdeckey, deciv, AES_DECRYPT);
    
    return [[NSData alloc]initWithBytes:decbuf length:bufferSize];
}



+ (BOOL)aesFileEncryptAtPath:(NSString*)path key:(NSString *)key data:(NSData*)data
{
    if([[NSFileManager defaultManager] fileExistsAtPath:path]) //如果存在
    {
        BOOL isDeleted= [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
        if (isDeleted) {
            NSLog(@"dele success");
        }else {
            NSLog(@"dele fail");
        }
    }
    
    AES_KEY aeskey;
    unsigned char iv[enBlockSize] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    
    unsigned char srcBuffer[blockSize+enBlockSize];
    unsigned char dstBuffer[blockSize+enBlockSize];
    NSInputStream *inputStream = NULL;
    NSOutputStream *outputStream = NULL;
        
    long long fileSize = [data length];
    if (fileSize <= 0) {
        return NO;
    }
    
    if ((inputStream = [[NSInputStream alloc]initWithData:data]) == NULL) {
        return NO;
    }
    [inputStream open];

    if ((outputStream = [[NSOutputStream alloc]initWithURL:[NSURL fileURLWithPath:path] append:YES]) == NULL) {
        return NO;
    }
    [outputStream open];
    
    //aes key
    AES_set_encrypt_key((unsigned char*)[[key dataUsingEncoding:NSASCIIStringEncoding] bytes], 256, &aeskey);
    
    for (long long i = 0; i < fileSize;) {
        @autoreleasepool {
            int appendSize = 0, dataSegmentRealSize = 0;
            NSInteger bytesRead = 0;
            memset(srcBuffer, 0x00, blockSize+enBlockSize);
            memset(dstBuffer, 0x00, blockSize+enBlockSize);
            
            //Segment
            dataSegmentRealSize = (int)MIN((long long)blockSize, fileSize - i);
            bytesRead = [inputStream read:srcBuffer maxLength:dataSegmentRealSize];
            if (bytesRead != dataSegmentRealSize) {
                return NO;
            }
            i += dataSegmentRealSize;
            
            // last block
            if(i >= fileSize){
                int append = dataSegmentRealSize % enBlockSize;
                appendSize = enBlockSize + enBlockSize - append ;
                memset(srcBuffer+dataSegmentRealSize, appendSize, appendSize);
            }
            
            // encrypt
            AES_cbc_encrypt(srcBuffer, dstBuffer, dataSegmentRealSize+appendSize, &aeskey, iv, AES_ENCRYPT);
            
            // write
            [outputStream write:dstBuffer maxLength:dataSegmentRealSize+appendSize];
        }
    }
    
    [inputStream close];
    [outputStream close];
    
    if(![[NSFileManager defaultManager] fileExistsAtPath:path]) //如果不存在
    {
        return NO;
    }
    return YES;
}


+ (NSString *)aesFileDecryptAtPath:(NSString*)path key:(NSString *)key
{
    
    NSString *tempURL = NULL;
    NSString *puuid = [[path componentsSeparatedByString:@"/"] lastObject];
    tempURL = [NSString stringWithFormat:@"%@%@.mov", NSTemporaryDirectory(), puuid];
    if([[NSFileManager defaultManager] fileExistsAtPath:tempURL]) //如果存在
    {
        return tempURL;
    }
    
    AES_KEY aeskey;
    unsigned char iv[enBlockSize] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

    unsigned char srcBuffer[blockSize];
    unsigned char dstBuffer[blockSize];
    NSInputStream *inputStream = NULL;
    NSOutputStream *outputStream = NULL;
    
    long long fileSize = [self fileSizeAtPath:path];
    if (fileSize <= 0) {
        return nil;
    }
    
    if ((inputStream = [[NSInputStream alloc]initWithFileAtPath:path]) == NULL) {
        return nil;
    }
    [inputStream open];
    

    if ((outputStream = [[NSOutputStream alloc]initWithURL:[NSURL fileURLWithPath:tempURL] append:YES]) == NULL) {
        return nil;
    }
    [outputStream open];
    
    //aes key
    AES_set_decrypt_key((unsigned char*)[[key dataUsingEncoding:NSASCIIStringEncoding] bytes], 256, &aeskey);
    
    for(long long i = 0; i < fileSize;) {
        @autoreleasepool {
            NSInteger bytesRead = 0;
            int dataSegmentRealSize = 0;
            memset(srcBuffer, 0x00, blockSize);
            memset(dstBuffer, 0x00, blockSize);
            
            // Segment
            dataSegmentRealSize = (int)MIN((long long)blockSize, fileSize - i);
            if((dataSegmentRealSize%enBlockSize) != 0){
                return nil;
            }
            
            // Read
            bytesRead = [inputStream read:srcBuffer maxLength:dataSegmentRealSize];
            if (bytesRead != dataSegmentRealSize) {
                return nil;
            }
            i += dataSegmentRealSize;
            
            // decrypt
            AES_cbc_encrypt(srcBuffer, dstBuffer, dataSegmentRealSize, &aeskey, iv, AES_DECRYPT);
            if (i >= fileSize) {
                BOOL bProc = true;
                int val = dstBuffer[dataSegmentRealSize-1];
                for (int i = val; i > 0; i--) {
                    if(dstBuffer[dataSegmentRealSize-i] != val){
                        bProc = false;
                        break;
                    }
                }
                if(bProc){
                    dataSegmentRealSize -= val;
                }
            }
            
            // write to temp url
            [outputStream write:dstBuffer maxLength:dataSegmentRealSize];
        }
    }
    
    [inputStream close];
    [outputStream close];
    
    if(![[NSFileManager defaultManager] fileExistsAtPath:tempURL]) //如果不存在
    {
        return nil;
    }
    return tempURL;
}


+ (NSData *)aesFileDataDecryptAtPath:(NSString*)path key:(NSString *)key
{
    AES_KEY aeskey;
    unsigned char iv[enBlockSize] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    
    unsigned char srcBuffer[blockSize];
    unsigned char dstBuffer[blockSize];
    NSInputStream *inputStream = NULL;
    
    long long fileSize = [self fileSizeAtPath:path];
    if (fileSize <= 0) {
        return nil;
    }
    
    if ((inputStream = [[NSInputStream alloc]initWithFileAtPath:path]) == NULL) {
        return nil;
    }
    [inputStream open];
    
    NSMutableData *decData = [NSMutableData data];
    
    //aes key
    AES_set_decrypt_key((unsigned char*)[[key dataUsingEncoding:NSASCIIStringEncoding] bytes], 256, &aeskey);
    
    for(long long i = 0; i < fileSize;) {
        @autoreleasepool {
            NSInteger bytesRead = 0;
            int dataSegmentRealSize = 0;
            memset(srcBuffer, 0x00, blockSize);
            memset(dstBuffer, 0x00, blockSize);
            
            // Segment
            dataSegmentRealSize = (int)MIN((long long)blockSize, fileSize - i);
            if((dataSegmentRealSize%enBlockSize) != 0){
                return nil;
            }
            
            // Read
            bytesRead = [inputStream read:srcBuffer maxLength:dataSegmentRealSize];
            if (bytesRead != dataSegmentRealSize) {
                return nil;
            }
            i += dataSegmentRealSize;
            
            // decrypt
            AES_cbc_encrypt(srcBuffer, dstBuffer, dataSegmentRealSize, &aeskey, iv, AES_DECRYPT);
            if (i >= fileSize) {
                BOOL bProc = true;
                int val = dstBuffer[dataSegmentRealSize-1];
                for (int i = val; i > 0; i--) {
                    if(dstBuffer[dataSegmentRealSize-i] != val){
                        bProc = false;
                        break;
                    }
                }
                if(bProc){
                    dataSegmentRealSize -= val;
                }
            }
            
            // append data
            [decData appendBytes:dstBuffer length:dataSegmentRealSize];
        }
    }
    
    [inputStream close];
    
    return decData;
}


+ (NSData *)fixDataWithData:(NSData *)decData
{
    BOOL bProc = true;
    int len = (int)[decData length];
    unsigned char p[blockSize+enBlockSize] = {0x00};
    memcpy(p, [decData bytes], len);
    int val = p[len-1];
    for(int i = val; i > 0; i--){
        if(p[len-i] != val){
            bProc = false;
            break;
        }
    }
    if(!bProc){
        return [[NSData alloc]initWithBytes:[decData bytes] length:len-val];
    }else{
        return [[NSData alloc]initWithBytes:[decData bytes] length:len];
    }
}

+ (long long)fileSizeAtPath:(NSString*) filePath
{
    NSFileManager* manager = [NSFileManager defaultManager];
    if ([manager fileExistsAtPath:filePath]){
        return [[manager attributesOfItemAtPath:filePath error:nil] fileSize];
    }
    return 0;
}



@end