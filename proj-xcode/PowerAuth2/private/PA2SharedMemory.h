/*
 * Copyright 2022 Wultra s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#import <PowerAuth2/PowerAuthMacros.h>

/**
 The `PA2SharedMemory` allows you to create a named memory region that is shared between the multiple applications.
 */
@interface PA2SharedMemory : NSObject

/**
 Create named memory shared between multiple applications.
 
 @param identifier Identifier that identify region of shared memory between multiple applications.
 @param requestedSize Requested size of shared memory.
 @param setupBlock Block called only when this process just created the shared memory region for the first time.
 @param memory Pointer to allocated memory.
 @param size Size of allocated memory.
 @param crated YES if shared memory region is newly created.
 @return `PA2SharedMemory` instance or `nil` in case of failure.
 */
+ (nullable instancetype) namedSharedMemory:(nonnull NSString*)identifier
								   withSize:(NSUInteger)requestedSize
								  setupOnce:(BOOL (NS_NOESCAPE^_Nonnull)(void * _Nonnull memory, NSUInteger size, BOOL create))setupBlock;
/**
 Pointer to bytes shared between processes.
 
 Be aware that if you call `unlink`, then the bytes pointer is invalidated.
 */
@property (nonatomic, readonly, nonnull) void * bytes;
/**
 Contains number of bytes shared between processes.
 
 Be aware that if you call `unlink`, then the size is set to 0.
 */
@property (nonatomic, readonly) NSUInteger size;
/**
 Contains identifier of the shared memory. The identifier can be invalidated by calling `unlink` method.
 */
@property (nonatomic, strong, nullable, readonly) NSString * identifier;
/**
 Contains YES if object is still valid and point to shared memory. The object can be invalidated by calling `unlink` method.
 */
@property (nonatomic, readonly) BOOL isValid;

/**
 Release and unlink the shared memory. This function is normally useful only for deep cleanup, when you really need
 to delete the previously created shared memory. See `shm_unlink` manual for more details.
 
 Be aware that once you call unlink, then `bytes` and `size` properties are set to zero.
 */
- (void) unlink;

@end
