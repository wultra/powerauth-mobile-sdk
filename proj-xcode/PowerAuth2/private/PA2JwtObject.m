/*
 * Copyright 2024 Wultra s.r.o.
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

#import "PA2JwtObject.h"
#import "PA2PrivateMacros.h"

#pragma mark - JWT Header

@implementation PA2JwtHeader

- (instancetype) initWithTyp:(NSString*)typ
                     withAlg:(NSString*)alg
{
    self = [super init];
    if (self) {
        _typ = typ;
        _alg = alg;
    }
    return self;
}

- (instancetype) initJwtWithAlg:(NSString *)alg
{
    return [self initWithTyp:@"JWT" withAlg:alg];
}

- (instancetype) initWithDictionary:(NSDictionary<NSString *,NSObject *> *)dictionary
{
    return [self initWithTyp:PA2ObjectAs(dictionary[@"typ"], NSString)
                     withAlg:PA2ObjectAs(dictionary[@"typ"], NSString)];
}

- (NSDictionary<NSString *,NSObject *> *)toDictionary
{
    return @{
        @"typ": _typ,
        @"alg": _alg
    };
}

@end

#pragma mark - JWT Object

@implementation PA2JwtObject

- (instancetype) initWithJwt:(NSString*)jwt
{
    self = [super init];
    if (self) {
        _jwt = jwt;
    }
    return self;
}

- (instancetype) initWithDictionary:(NSDictionary<NSString *,NSObject *> *)dictionary
{
    return [self initWithJwt:PA2ObjectAs(dictionary[@"jwt"], NSString)];
}

- (NSDictionary<NSString *,NSObject *> *) toDictionary
{
    return @{ @"jwt": _jwt };
}

@end
