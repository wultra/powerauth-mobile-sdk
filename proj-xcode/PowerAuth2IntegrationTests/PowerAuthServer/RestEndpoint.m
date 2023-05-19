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

#import "RestEndpoint.h"

// MARK: - Endpoint specification

@implementation RestEndpoint
{
    NSString * _name;
}

static void _CheckDictionary(id object, NSString * endpointName)
{
    if (![object isKindOfClass:[NSDictionary class]]) {
        @throw [NSException exceptionWithName:@"RestError" reason:[NSString stringWithFormat:@"Invalid JSON for endpoint '%@'", endpointName] userInfo:nil];
    }
}

- (id) initFromDictionary:(NSDictionary *)dictionary
             endpointName:(NSString*)endpointName
{
    _CheckDictionary(dictionary, endpointName);
    
    self = [super init];
    if (self) {
        _path = dictionary[@"path"];
        if (!_path) {
            @throw [NSException exceptionWithName:@"RestError" reason:[NSString stringWithFormat:@"Path is missing in endpoint '%@'", endpointName] userInfo:nil];
        }
        _name = endpointName;
        _parameters = dictionary[@"parameters"];
        if (!_parameters) {
            _parameters = [NSArray array];
        }
        _response = [[RestObjectSpec alloc] initWithDictionary:dictionary[@"response"] endpointName:endpointName propertyName:@"{}"];
    }
    return self;
}

- (id) buildRequestObjectWithParameters:(NSArray*)parameters
{
    NSMutableDictionary * dictionary = [NSMutableDictionary dictionary];
    __block BOOL isError = NO;
    [parameters enumerateObjectsUsingBlock:^(NSString * value, NSUInteger idx, BOOL * stop) {
        if (idx < self.parameters.count) {
            NSString * key = self.parameters[idx];
            dictionary[key] = value;
        } else {
            @throw [NSException exceptionWithName:@"RestError" reason:[NSString stringWithFormat:@"Not enough request parameters defined in endpoint '%@'", _name] userInfo:nil];
        }
    }];
    return isError ? nil : @{ @"requestObject" : dictionary };
}

- (id) buildResponseObjectFromDictionary:(NSDictionary *)dictionary error:(NSError**)error
{
    @try {
        _CheckDictionary(dictionary, _name);
        return [_response transformFromValue:dictionary[@"responseObject"]];
    } @catch (NSException *exception) {
        if (error) *error = [NSError errorWithDomain:exception.name code:0 userInfo:@{NSLocalizedDescriptionKey: exception.reason } ];
        return nil;
    }
}

- (id) buildResponseObjectFromValue:(id<NSObject>)value
{
    return [_response transformFromValue:value];
}

@end

// MARK: - Object specification

@implementation RestObjectSpec

static RestObjectType ROTFromString(NSString * str, NSString * endpointName)
{
    if (str) {
        if ([str isEqualToString:@"string"]) return ROT_STRING;
        if ([str isEqualToString:@"number"]) return ROT_NUMBER;
        if ([str isEqualToString:@"array"]) return ROT_ARRAY;
        if ([str isEqualToString:@"dictionary"]) return ROT_MAP;
        if ([str isEqualToString:@"bool"]) return ROT_BOOL;
        if ([str isEqualToString:@"int"]) return ROT_INT;
        if (NSClassFromString(str)) {
            return ROT_OBJECT;
        }
        @throw [NSException exceptionWithName:@"RestError" reason:[NSString stringWithFormat:@"Invalid object class '%@' in endpoint '%@'", str, endpointName] userInfo:nil];
    }
    @throw [NSException exceptionWithName:@"RestError" reason:[NSString stringWithFormat:@"Missing object class in endpoint '%@'", endpointName] userInfo:nil];
}

- (id) initWithDictionary:(NSDictionary *)dictionary
             endpointName:(NSString *)endpointName
             propertyName:(NSString *)propertyName
{
    _CheckDictionary(dictionary, endpointName);
    
    NSString * objectClass = dictionary[@"class"];
    RestObjectType rot = ROTFromString(objectClass, endpointName);
    NSMutableDictionary * objectProperties = nil;
    RestObjectSpec * arrayClass = nil;
    
    if (rot == ROT_OBJECT) {
        NSDictionary * props = dictionary[@"properties"];
        if (!props) {
            @throw [NSException exceptionWithName:@"RestError" reason:[NSString stringWithFormat:@"Missing object properties in endpoint '%@'", endpointName] userInfo:nil];
        }
        objectProperties = [NSMutableDictionary dictionary];
        [props enumerateKeysAndObjectsUsingBlock:^(NSString * key, id  obj, BOOL * stop) {
            objectProperties[key] = [[RestObjectSpec alloc] initWithDictionary:obj endpointName:endpointName propertyName:key];
        }];
    }
    if (rot == ROT_ARRAY) {
        NSDictionary * arraySpec = dictionary[@"arrayClass"];
        if (!arraySpec) {
            @throw [NSException exceptionWithName:@"RestError" reason:[NSString stringWithFormat:@"Missing array specification in endpoint '%@'", endpointName] userInfo:nil];
        }
        arrayClass = [[RestObjectSpec alloc] initWithDictionary:arraySpec endpointName:endpointName propertyName:@"[]"];
    }
    self = [super init];
    if (self) {
        _objectType = rot;
        _objectClass = objectClass;
        _objectProperties = objectProperties;
        _arrayClass = arrayClass;
        _endpointName = endpointName;
        _propertyName = propertyName;
        _sourcePath = dictionary[@"path"];
        _sourceKey  = dictionary[@"key"];
    }
    return self;
}

- (id) buildString:(id)value
{
    if ([value isKindOfClass:[NSString class]]) {
        return value;
    }
    @throw [NSException exceptionWithName:@"RestError" reason:[NSString stringWithFormat:@"String is expected when transforming value of property '%@' in endpoint '%@'", _propertyName, _endpointName] userInfo:nil];
}

- (id) buildNumber:(id)value
{
    if ([value isKindOfClass:[NSNumber class]]) {
        return value;
    }
    @throw [NSException exceptionWithName:@"RestError" reason:[NSString stringWithFormat:@"Number is expected when transforming value of property '%@' in endpoint '%@'", _propertyName, _endpointName] userInfo:nil];
}

- (id) buildArray:(NSArray*)value
{
    if ([value isKindOfClass:[NSArray class]]) {
        NSMutableArray * array = [NSMutableArray array];
        [value enumerateObjectsUsingBlock:^(id  _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
            [array addObject: [_arrayClass transformFromValue:obj]];
        }];
        return array;
    }
    @throw [NSException exceptionWithName:@"RestError" reason:[NSString stringWithFormat:@"Array is expected when transforming value of property '%@' in endpoint '%@'", _propertyName, _endpointName] userInfo:nil];
}

- (id) buildDictionary:(NSDictionary*)value
{
    if ([value isKindOfClass:[NSDictionary class]]) {
        return value;
    }
    @throw [NSException exceptionWithName:@"RestError" reason:[NSString stringWithFormat:@"Dictionary is expected when transforming value of property '%@' in endpoint '%@'", _propertyName, _endpointName] userInfo:nil];
}

- (id) buildObject:(NSDictionary*)value
{
    if (![value isKindOfClass:[NSDictionary class]]) {
        @throw [NSException exceptionWithName:@"RestError" reason:[NSString stringWithFormat:@"Dictionary is expected when transforming value of property '%@' in endpoint '%@'", _propertyName, _endpointName] userInfo:nil];
    }
    Class instanceClass = NSClassFromString(_objectClass);
    id<NSObject> instance = [[instanceClass alloc] init];
    if (!instance) {
        @throw [NSException exceptionWithName:@"RestError" reason:[NSString stringWithFormat:@"Failed to create instance of '%@' when transforming value of property '%@' in endpoint '%@'", _objectClass, _propertyName, _endpointName] userInfo:nil];
    }
    [_objectProperties enumerateKeysAndObjectsUsingBlock:^(NSString * propertyName, RestObjectSpec * propertySpec, BOOL * _Nonnull stop) {
        id propertyValue = value[propertySpec.sourceKey ? propertySpec.sourceKey : propertyName];
        if (propertyValue) {
            // Has value, try to transform and set it to the instance
            [self updateProperty:propertyName withValue:propertyValue at:instance propertySpec:propertySpec];
        }
    }];
    return instance;
}

- (void) updateProperty:(NSString*)propertyName withValue:(id)value at:(id<NSObject>)target propertySpec:(RestObjectSpec*)propertySpec
{
    id transformedValue = [propertySpec transformFromValue:value];
    RestObjectType objectType = propertySpec.objectType;
    union {
        BOOL boolValue;
        NSInteger integerValue;
    } plainValue;
    if (objectType == ROT_BOOL) {
        plainValue.boolValue = [transformedValue boolValue];
    } else if (objectType == ROT_INT) {
        plainValue.integerValue = [transformedValue integerValue];
    }
    NSString * setterName = [NSString stringWithFormat:@"set%c%@:", toupper([propertyName characterAtIndex:0]), [propertyName substringFromIndex:1]];
    SEL setterSelector = NSSelectorFromString(setterName);
    if ([target respondsToSelector:setterSelector]) {
        NSMethodSignature * methodSignature = [target.class instanceMethodSignatureForSelector:setterSelector];
        NSInvocation * methodInvocation = [NSInvocation invocationWithMethodSignature:methodSignature];
        [methodInvocation setTarget:target];
        [methodInvocation setSelector:setterSelector];
        if (objectType == ROT_BOOL) {
            [methodInvocation setArgument:&plainValue.boolValue atIndex:2];
        } else if (objectType == ROT_INT) {
            [methodInvocation setArgument:&plainValue.integerValue atIndex:2];
        } else {
            [methodInvocation setArgument:&transformedValue atIndex:2];
        }
        [methodInvocation invoke];
    } else {
        @throw [NSException exceptionWithName:@"RestError" reason:[NSString stringWithFormat:@"Class '%@' doesn't respond to %@ when transforming value of property '%@' in endpoint '%@'", _objectClass, setterName, _propertyName, _endpointName] userInfo:nil];
    }
}

- (id) transformFromValue:(id)value
{
    if ([value isKindOfClass:[NSNull class]]) {
        return nil;
    }
    if (_sourcePath) {
        value = [self resolveValueAtPath:_sourcePath from:value];
    }
    switch (_objectType) {
        case ROT_STRING: return [self buildString:value];
        case ROT_NUMBER: return [self buildNumber:value];
        case ROT_BOOL:   return [self buildNumber:value];
        case ROT_INT:    return [self buildNumber:value];
        case ROT_ARRAY:  return [self buildArray:value];
        case ROT_MAP:    return [self buildDictionary:value];
        case ROT_OBJECT: return [self buildObject:value];
        default:
            @throw [NSException exceptionWithName:@"RestError" reason:@"Internal error" userInfo:nil];
    }
}

- (id) resolveValueAtPath:(NSString*)path from:(id)value
{
    NSArray * components = [path componentsSeparatedByString:@"."];
    for (NSUInteger i = 0; i < components.count; ++i) {
        NSString * key = components[i];
        if (![value isKindOfClass:[NSDictionary class]]) {
            @throw [NSException exceptionWithName:@"RestError" reason:[NSString stringWithFormat:@"Value at path %@ should be dictionary. Endpoint %@, property %@", path, _endpointName, _propertyName] userInfo:nil];
        }
        value = [(NSDictionary*)value objectForKey:key];
    }
    return value;
}

@end
