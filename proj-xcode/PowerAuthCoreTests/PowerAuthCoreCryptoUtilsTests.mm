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

#include <PowerAuthCore/PowerAuthCore.h>
#include <XCTest/XCTest.h>

#include <cc7/CC7.h>
#include <cc7/objc/ObjcHelper.h>

@interface PowerAuthCoreCryptoUtilsTests : XCTestCase
@end

@implementation PowerAuthCoreCryptoUtilsTests
{
}

struct EcdsaTestData {
    const char * data;
    const char * signature;
    const char * publicKey;
    BOOL expectedResult;
};

- (void) testEcdsaSignatureValidation
{
    struct EcdsaTestData testData[] = {
        {
            "108101B78FC2DC3119EFFC470099",
            "3044022100F754ADB4855A5053FB089E1675E91C4F593E1DD237F57A1BE77F5275EB2872F2021F1D2D6526184F26FE95302179F76EB18C8762832D1C48C0A11DD2AB0BBAC783",
            "03109BEED74DEA497F7B97EDA5953567170ED201F44E65D7B839F6D611AB35F971",
            YES
        },
        {
            "CCD13602DD3B68AA461A889F263CE2365C8D5B5D2B6EAC2C82C5C839A96829CFF98560C6FE",
            "3045022100F434EC655071E6F46DEA4EF501DE1A8F48B9D411202B2FB29C1E079B4D65B3170220175298B1B132F3A2AE49DC39747E535475CE70D415F6DD6943788131E36F45DC",
            "0358BD34E1BCD60B52D7298CE0BAB046DC2970070724D38C2122210874B8DE1F90",
            YES
        },
        {
            "5D219A60B57A8A2234B28D2DF80C54E0CB48C3E5",
            "3045022100F2F48A70EDF692EEB270D3FC9C22A6B6FD84538CCFB8A3DC562537EBAEF98786022031BC8AAFCCD9774D366A5964F38D5B9276CD8B56A529B03442BF1D524DAA1D0D",
            "02D4617423CDCBCA9906E61F187A40B58EB1256133657795353CA0707774D4D437",
            YES
        },
        {
            "B43C198B6312425F6807BF63997B02E81448",
            "304402201B1D910736253777248EE836838AB09336A05D0E9693DA337EDC37B2C95F835B02201D14FA621B3E9833D88C970015615A07D48547BD029B9D485B47E90841BC3350",
            "03866A7799BE9651AB480795745486C97B444EC90E1B64D3029E4B6B014E986759",
            YES
        },
        {
            "B43C198B6312425F6807BF63997B02E81418",
            "304402201B1D910736253777248EE836838AB09336A05D0E9693DA337EDC37B2C95F835B02201D14FA621B3E9833D88C970015615A07D48547BD029B9D485B47E90841BC3350",
            "03866A7799BE9651AB480795745486C97B444EC90E1B64D3029E4B6B014E986759",
            NO
        },
        {
            NULL, NULL, NULL, NO
        }
    };
    const struct EcdsaTestData * td = testData;
    while (td->data) {
        NSData * dataBytes = cc7::objc::CopyToNSData(cc7::FromHexString(std::string(td->data)));
        NSData * signatureBytes = cc7::objc::CopyToNSData(cc7::FromHexString(std::string(td->signature)));
        NSData * pubKeyBytes = cc7::objc::CopyToNSData(cc7::FromHexString(std::string(td->publicKey)));
        PowerAuthCoreECPublicKey * publicKey = [[PowerAuthCoreECPublicKey alloc] initWithData:pubKeyBytes];
        XCTAssertNotNil(publicKey);
        BOOL result = [PowerAuthCoreCryptoUtils ecdsaValidateSignature:signatureBytes forData:dataBytes forPublicKey:publicKey];
        XCTAssertEqual(result, td->expectedResult);
        td++;
    }
}

- (void) testEcdsaComputeSignature
{
    PowerAuthCoreECKeyPair * keyPair = [PowerAuthCoreCryptoUtils ecGenerateKeyPair];
    XCTAssertNotNil(keyPair);
    NSMutableData * testData = [[PowerAuthCoreCryptoUtils randomBytes:128] mutableCopy];
    XCTAssertNotNil(testData);
    NSData * signature = [PowerAuthCoreCryptoUtils ecdsaComputeSignature:testData withPrivateKey:keyPair.privateKey];
    BOOL result = [PowerAuthCoreCryptoUtils ecdsaValidateSignature:signature forData:testData forPublicKey:keyPair.publicKey];
    XCTAssertTrue(result);
    unsigned char * bytePtr = (unsigned char *)[testData mutableBytes];
    ++bytePtr[33];
    result = [PowerAuthCoreCryptoUtils ecdsaValidateSignature:signature forData:testData forPublicKey:keyPair.publicKey];
    XCTAssertFalse(result);
}

- (void) testEcdhComputeSharedSecret
{
    PowerAuthCoreECKeyPair * alice = [PowerAuthCoreCryptoUtils ecGenerateKeyPair];
    PowerAuthCoreECKeyPair * bob = [PowerAuthCoreCryptoUtils ecGenerateKeyPair];
    XCTAssertNotNil(alice);
    XCTAssertNotNil(bob);
    NSData * aliceSharedSecret = [PowerAuthCoreCryptoUtils ecdhComputeSharedSecret:bob.publicKey withPrivateKey:alice.privateKey];
    NSData * bobSharedSecret = [PowerAuthCoreCryptoUtils ecdhComputeSharedSecret:alice.publicKey withPrivateKey:bob.privateKey];
    XCTAssertTrue([aliceSharedSecret isEqual:bobSharedSecret]);
}

@end
