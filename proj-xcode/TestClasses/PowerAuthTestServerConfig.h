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

#ifndef PowerAuthTestServerConfig_h
#define PowerAuthTestServerConfig_h

/**
 The `POWERAUTH_BASE_URL` macro defines a base URL where are the running server instances
 located. The default config expects that the SOAP & REST servers are running at "http://paserver"
 domain. In case that you're using a locally installed docker, then more common for you 
 will be set the base URL to "http://localhost".
 */
#ifndef POWERAUTH_BASE_URL
#define POWERAUTH_BASE_URL @"http://paserver"
#endif

/**
 The `POWERAUTH_TEST_SERVER_URL` macro defines a full URL to exposed SOAP interface.
 */
#ifndef POWERAUTH_TEST_SERVER_URL
#define POWERAUTH_TEST_SERVER_URL POWERAUTH_BASE_URL @":20010/powerauth-java-server/soap"
#endif

/**
 The `POWERAUTH_TEST_SERVER_APP` macro defines an application name used during the testing.
 You can check "PowerAuth Admin" whether the application was created during the testing.
 */
#ifndef POWERAUTH_TEST_SERVER_APP
#define POWERAUTH_TEST_SERVER_APP @"AutomaticTest-IOS"
#endif

/**
 The `POWERAUTH_TEST_SERVER_APP_VERSION` macro defines an application's version used during 
 the testing. You can check "PowerAuth Admin" whether the appropriate version was created 
 during the testing.
 */
#ifndef POWERAUTH_TEST_SERVER_APP_VERSION
#define POWERAUTH_TEST_SERVER_APP_VERSION @"default"
#endif

/**
 The `POWERAUTH_REST_API_URL` macro defines a base endpoint URL for public PowerAuth's REST API.
 For the testing environment, the domain is usually the same as for SOAP server.
 */
#ifndef POWERAUTH_REST_API_URL
#define POWERAUTH_REST_API_URL POWERAUTH_BASE_URL @":18080/powerauth-rest-api"
#endif


#endif /* PowerAuthTestServerConfig_h */
