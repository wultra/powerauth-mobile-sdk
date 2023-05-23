/*
 * Copyright 2023 Wultra s.r.o.
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

typedef enum _RestObjectType {
    ROT_STRING  = 10,
    ROT_NUMBER  = 20,
    ROT_BOOL    = 21,
    ROT_INT     = 22,
    ROT_ARRAY   = 30,
    ROT_MAP     = 40,
    ROT_OBJECT  = 50,
} RestObjectType;

@interface RestObjectSpec : NSObject

- (id) initWithDictionary:(NSDictionary*)dictionary
             endpointName:(NSString*)endpointName
             propertyName:(NSString*)propertyName;


@property (nonatomic, readonly, strong) NSString * propertyName;
@property (nonatomic, readonly, strong) NSString * endpointName;

@property (nonatomic, readonly, strong) NSString * sourceKey;   // redirection when processing properties
@property (nonatomic, readonly, strong) NSString * sourcePath;  // redirection before any processing

/// Type of object in specification
@property (nonatomic, readonly) RestObjectType objectType;
/// Type of this object. Specify class name, or "string", "number", "array", "bool", "integer"
@property (nonatomic, readonly, strong) NSString * objectClass;
/// Object properties if objectClass is not "string", "number", "array"
@property (nonatomic, readonly, strong) NSDictionary<NSString*, RestObjectSpec*>* objectProperties;
/// Specify inner object stored in the array
@property (nonatomic, readonly, strong) RestObjectSpec* arrayClass;


- (id) transformFromValue:(id)value;

@end

@interface RestEndpoint : NSObject

- (id) initFromDictionary:(NSDictionary*)dictionary
             endpointName:(NSString*)endpointName;

@property (nonatomic, readonly, strong) NSString * path;
@property (nonatomic, readonly, strong) NSArray<NSString*>* parameters;
@property (nonatomic, readonly, strong) RestObjectSpec* response;

- (id) buildRequestObjectWithParameters:(NSArray*)parameters;
- (id) buildResponseObjectFromValue:(id<NSObject>)value;
- (id) buildResponseObjectFromDictionary:(NSDictionary*)dictionary error:(NSError**)error;

@end
