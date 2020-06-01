/**
 * Copyright 2017 Wultra s.r.o.
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

#import "PA2Macros.h"

/*
 The purpose of this header is to provide a several simple cryptographic functions
 which can be used on the limited systems, like WatchOS. We don't want to
 bring a whole CC7+OpenSSL to the application extensions, so this header provides
 all minumum functions required in our SDK.
 
 On resource rich platforms (such as IOS or macOS) our CC7 with OpenSSL is used.
 */

/**
 Computes HMAC_SHA256 digest for given data and key.
 */
PA2_EXTERN_C NSData * PA2PrivateCrypto_HMAC_SHA256(NSData * data, NSData * key);

/**
 Returns data object initialized with a required number of random bytes.
 Returns nil if underlying cryptographic pseudo-random number generator is not able
 to generate a required number of bytes.
 */
PA2_EXTERN_C NSData * PA2PrivateCrypto_GetRandomBytes(size_t count);
