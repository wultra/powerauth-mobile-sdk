/**
 * Copyright 2017 Lime - HighTech Solutions s.r.o.
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

#import <Foundation/Foundation.h>

@interface PATSApplication : NSObject

@property (nonatomic, strong) NSString * applicationId;
@property (nonatomic, strong) NSString * applicationName;

@end

@interface PATSApplicationVersion : NSObject

@property (nonatomic, strong) NSString * applicationVersionId;
@property (nonatomic, strong) NSString * applicationVersionName;
@property (nonatomic, strong) NSString * applicationKey;
@property (nonatomic, strong) NSString * applicationSecret;
@property (nonatomic, assign) BOOL supported;

@end

@interface PATSApplicationDetail : PATSApplication

@property (nonatomic, strong) NSString * masterPublicKey;
@property (nonatomic, strong) NSArray<PATSApplicationVersion*> * versions;

@end


