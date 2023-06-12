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

#import "RestHelper.h"
#import "RestEndpoint.h"
#import "AsyncHelper.h"

@implementation RestHelper
{
    NSBundle * _bundle;
    PowerAuthTestServerConfig * _config;
    NSString * _url;
    NSMutableDictionary<NSString*, RestEndpoint*> * _cache;
    PowerAuthTestServerVersion _version;
    NSDictionary * _headers;
    NSDictionary<NSString*, NSString*>* _endpointMapping;
}

- (id) initWithBundle:(NSBundle*)bundle
               config:(PowerAuthTestServerConfig*)config
{
    self = [super init];
    if (self) {
        _bundle = bundle;
        _config = config;
        _url = config.serverApiUrl;
        _cache = [NSMutableDictionary dictionary];
        _version = config.serverApiVersion;
        _session = [NSURLSession sharedSession];
        if (config.serverApiPassword && config.serverApiUsername) {
            NSString * basicAuth = [[[NSString stringWithFormat:@"%@:%@", config.serverApiUsername, config.serverApiPassword] dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:0];;
            _headers = @{
                @"Content-Type": @"application/json;charset=UTF-8",
                @"Accept" : @"application/json",
                @"Authorization": [@"Basic " stringByAppendingString:basicAuth]
            };
        } else {
            _headers = @{
                @"Content-Type": @"application/json;charset=UTF-8",
                @"Accept" : @"application/json"
            };
        }
    }
    return self;
}

- (PowerAuthTestServerVersion) applyServerVersion:(NSString*)version
{
    _endpointMapping = [self loadEndpointMapping:version];
    return [PowerAuthTestServerConfig apiVersionFromString:version];
}

- (id) request:(NSString*)requestName
        params:(NSArray*)params
{
    RestEndpoint * endpoint = [self endpointForName:requestName];
    id jsonData = [endpoint buildRequestObjectWithParameters:params];
    NSError * error = nil;
    NSData * requestData = [NSJSONSerialization dataWithJSONObject:jsonData options:0 error:&error];
    if (!requestData) {
        @throw [NSException exceptionWithName:@"RestError" reason:[NSString stringWithFormat:@"Cant't serialize request for endpoint: %@", requestName] userInfo:nil];
    }
    // Make things synchronous
    __block id responseObject = nil;
    __block NSError * responseError = nil;
    
    [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        
        //NSLog(@"Envelope data %@", envelopeData);
        // Prepare request
        NSString * requestPath = [_url stringByAppendingString:endpoint.path];
        NSMutableURLRequest * request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:requestPath]];
        request.HTTPMethod = @"POST";
        request.HTTPBody = requestData;
        [_headers enumerateKeysAndObjectsUsingBlock:^(NSString * key, NSString * value, BOOL * _Nonnull stop) {
            [request setValue:value forHTTPHeaderField:key];
        }];
        
        //
        NSURLSessionDataTask * task = [_session dataTaskWithRequest:request completionHandler:^(NSData * data, NSURLResponse * response, NSError * error) {
            if (data && !error) {
                NSDictionary * responseDictionary = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
                NSHTTPURLResponse * httpResponse = (NSHTTPURLResponse *)response;
                if ([responseDictionary isKindOfClass:[NSDictionary class]]) {
                    if (responseDictionary) {
                        if ([responseDictionary[@"status"] isEqual:@"OK"]) {
                            // Status is OK, transform endpoint
                            responseObject = [endpoint buildResponseObjectFromDictionary:responseDictionary error:&error];
                        } else {
                            NSDictionary * info = @{ NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Non-OK status received from the server.\nPath: %@\nRequest: %@\nResponse Status: %@\nResponse Payload: %@", endpoint.path, jsonData, @(httpResponse.statusCode), responseDictionary] } ;
                            error = [NSError errorWithDomain:@"RestError" code:1 userInfo:info];
                        }
                    }
                } else if (!error) {
                    NSDictionary * info = @{ NSLocalizedDescriptionKey : @"Unknown data received from the server." } ;
                    error = [NSError errorWithDomain:@"RestError" code:1 userInfo:info];
                }
            }
            if (!error && !responseObject) {
                NSDictionary * info = @{ NSLocalizedDescriptionKey : @"Unknown error during JSON response processing." } ;
                error = [NSError errorWithDomain:@"RestError" code:1 userInfo:info];
            }
            responseError = error;
            [waiting reportCompletion:nil];
        }];
        [task resume];
    } wait:5*60];
    // Process result
    if (responseError) {
        @throw [NSException exceptionWithName:@"RestError" reason:responseError.localizedDescription userInfo:nil];
    }
    return responseObject;

}

- (RestEndpoint*) endpointForName:(NSString*)endpointName
{
    NSString * mappedName = _endpointMapping[endpointName];
    if (!mappedName) {
        mappedName = endpointName;
    }
    RestEndpoint * endpoint = [_cache objectForKey:mappedName];
    if (!endpoint) {
        endpoint = [self loadEndpoint:mappedName];
        _cache[mappedName] = endpoint;
    }
    return endpoint;
}

- (RestEndpoint*) loadEndpoint:(NSString*)templateName
{
    // Load endpoint from bundle
    NSString * path = [_bundle pathForResource:templateName ofType:@"json"];
    if (!path) {
        NSLog(@"Requested endpoint template '%@' doesn't exist", templateName);
        return nil;
    }
    NSData * templateData = [[NSData alloc] initWithContentsOfFile:path];
    if (!templateData) {
        @throw [NSException exceptionWithName:@"RestError" reason:[NSString stringWithFormat:@"Can't load data for endpoint: %@", templateName] userInfo:nil];
    }
    NSError * error = nil;
    id templateObject = [NSJSONSerialization JSONObjectWithData:templateData options:0 error:&error];
    if (!templateObject) {
        @throw [NSException exceptionWithName:@"RestError" reason:[NSString stringWithFormat:@"Cant't deserialize JSON for endpoint: %@", templateName] userInfo:nil];
    }
    return [[RestEndpoint alloc] initFromDictionary:templateObject endpointName:templateName];
}

- (NSDictionary*) loadEndpointMapping:(NSString*)serverVersion
{
    NSString * path = [_bundle pathForResource:@"mappings" ofType:@"json"];
    if (!path) {
        NSLog(@"Endpoint mappings file doesn't exist");
        return nil;
    }
    NSData * mappingData = [[NSData alloc] initWithContentsOfFile:path];
    if (!mappingData) {
        @throw [NSException exceptionWithName:@"RestError" reason:@"Can't load mapping data" userInfo:nil];
    }
    NSError * error = nil;
    NSDictionary * mappingDict = [NSJSONSerialization JSONObjectWithData:mappingData options:0 error:&error];
    if (![mappingDict isKindOfClass:[NSDictionary class]]) {
        @throw [NSException exceptionWithName:@"RestError" reason:@"Invalid mapping data or root dictionary is missing" userInfo:nil];
    }
    NSDictionary * versions = mappingDict[@"versions"];
    NSDictionary * mappings = mappingDict[@"mappings"];
    if (![versions isKindOfClass:[NSDictionary class]] || ![mappings isKindOfClass:[NSDictionary class]]) {
        @throw [NSException exceptionWithName:@"RestError" reason:@"Invalid mapping data. Missing versions od mappings values" userInfo:nil];
    }
    __block NSString * mappingKey = nil;
    [versions enumerateKeysAndObjectsUsingBlock:^(NSString * key, NSString * value, BOOL * stop) {
        if ([serverVersion isEqualToString:key] || [serverVersion hasPrefix:key] || [serverVersion hasPrefix:[key stringByAppendingString:@"."]]) {
            mappingKey = value;
            *stop = YES;
        }
    }];
    if (!mappingKey) {
        mappingKey = versions[@"*"];
        if (!mappingKey) {
            NSLog(@"Mapping for server %@ not found in known versions and fallback is not specified.", serverVersion);
            return nil;
        }
        NSLog(@"Mapping for server %@ not found in known versions. The latest known specification will be used.", serverVersion);
    }
    return [self loadBaseMapping:mappingKey mappings:mappings];
}

- (NSDictionary*) loadBaseMapping:(NSString*)mappingKey mappings:(NSDictionary*)mappings
{
    NSDictionary * endpointsMapping = mappings[mappingKey];
    if (!endpointsMapping) {
        @throw [NSException exceptionWithName:@"RestError" reason:[NSString stringWithFormat:@"Invalid mapping data. Mapping key '%@' not found", mappingKey] userInfo:nil];
    }
    NSString * inheritFrom = endpointsMapping[@"#base"];
    if (inheritFrom) {
        if ([inheritFrom isEqualToString:mappingKey]) {
            @throw [NSException exceptionWithName:@"RestError" reason:[NSString stringWithFormat:@"Invalid mapping data. Base mapping is equal to final mapping '%@'", mappingKey] userInfo:nil];
        }
        // Merge two mappings
        NSMutableDictionary * baseMapping = [[self loadBaseMapping:inheritFrom mappings:mappings] mutableCopy];
        [endpointsMapping enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL * stop) {
            baseMapping[key] = obj;
        }];
        endpointsMapping = baseMapping;
    }
    return endpointsMapping;
}

@end


