/*
 * Copyright 2021 Wultra s.r.o.
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

package io.getlime.security.powerauth.core;

import org.junit.Test;
import org.junit.runner.RunWith;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class CryptoUtilsTest {

    //
    // CryptoUtils.ecdsaValidateSignature(...)
    //

    private static class EcdsaTestData {
        final byte[] data;
        final byte[] signature;
        final byte[] publicKey;
        final boolean result;
        EcdsaTestData(String data, String signature, String publicKey, boolean result) {
            this.data = hexStringToByteArray(data);
            this.signature = hexStringToByteArray(signature);
            this.publicKey = hexStringToByteArray(publicKey);
            this.result = result;
        }
    }

    @Test
    public void testEcdsaSignatureValidation() throws Exception {
        EcdsaTestData[] testData = new EcdsaTestData[] {
                new EcdsaTestData(
                        "108101B78FC2DC3119EFFC470099",
                        "3044022100F754ADB4855A5053FB089E1675E91C4F593E1DD237F57A1BE77F5275EB2872F2021F1D2D6526184F26FE95302179F76EB18C8762832D1C48C0A11DD2AB0BBAC783",
                        "03109BEED74DEA497F7B97EDA5953567170ED201F44E65D7B839F6D611AB35F971",
                        true),
                new EcdsaTestData(
                        "CCD13602DD3B68AA461A889F263CE2365C8D5B5D2B6EAC2C82C5C839A96829CFF98560C6FE",
                        "3045022100F434EC655071E6F46DEA4EF501DE1A8F48B9D411202B2FB29C1E079B4D65B3170220175298B1B132F3A2AE49DC39747E535475CE70D415F6DD6943788131E36F45DC",
                        "0358BD34E1BCD60B52D7298CE0BAB046DC2970070724D38C2122210874B8DE1F90",
                        true),
                new EcdsaTestData(
                        "5D219A60B57A8A2234B28D2DF80C54E0CB48C3E5",
                        "3045022100F2F48A70EDF692EEB270D3FC9C22A6B6FD84538CCFB8A3DC562537EBAEF98786022031BC8AAFCCD9774D366A5964F38D5B9276CD8B56A529B03442BF1D524DAA1D0D",
                        "02D4617423CDCBCA9906E61F187A40B58EB1256133657795353CA0707774D4D437",
                        true),
                new EcdsaTestData(
                        "B43C198B6312425F6807BF63997B02E81448",
                        "304402201B1D910736253777248EE836838AB09336A05D0E9693DA337EDC37B2C95F835B02201D14FA621B3E9833D88C970015615A07D48547BD029B9D485B47E90841BC3350",
                        "03866A7799BE9651AB480795745486C97B444EC90E1B64D3029E4B6B014E986759",
                        true),
                new EcdsaTestData(
                        "B43C198B6312425F6807BF63997B02E81418",
                        "304402201B1D910736253777248EE836838AB09336A05D0E9693DA337EDC37B2C95F835B02201D14FA621B3E9833D88C970015615A07D48547BD029B9D485B47E90841BC3350",
                        "03866A7799BE9651AB480795745486C97B444EC90E1B64D3029E4B6B014E986759",
                        false),
                new EcdsaTestData(null, "00", "00", false),
                new EcdsaTestData("00", "00", null, false),
                new EcdsaTestData("00", "00", null, false)
        };
        for (EcdsaTestData data : testData) {
            boolean result = CryptoUtils.ecdsaValidateSignature(data.data, data.signature, new EcPublicKey(data.publicKey));
            assertEquals(data.result, result);
        }
    }

    @Test
    public void testEcdsaComputeSignature() throws Exception {
        final EcKeyPair keyPair = CryptoUtils.ecGenerateKeyPair();
        assertNotNull(keyPair);
        byte[] testData = CryptoUtils.randomBytes(128);
        assertNotNull(testData);
        byte[] signature = CryptoUtils.ecdsaComputeSignature(testData, keyPair.getPrivateKey());
        boolean validation = CryptoUtils.ecdsaValidateSignature(testData, signature, keyPair.getPublicKey());
        assertTrue(validation);
        testData[33] = (byte)(testData[33] + 1 & 0xFF);
        validation = CryptoUtils.ecdsaValidateSignature(testData, signature, keyPair.getPublicKey());
        assertFalse(validation);
    }

    @Test
    public void testEcdhComputeSharedSecret() throws Exception {
        final EcKeyPair alice = CryptoUtils.ecGenerateKeyPair();
        assertNotNull(alice);
        final EcKeyPair bob = CryptoUtils.ecGenerateKeyPair();
        assertNotNull(bob);

        final byte[] aliceSharedSecret = CryptoUtils.ecdhComputeSharedSecret(bob.getPublicKey(), alice.getPrivateKey());
        final byte[] bobSharedSecret = CryptoUtils.ecdhComputeSharedSecret(alice.getPublicKey(), bob.getPrivateKey());

        assertEquals(32, aliceSharedSecret.length);
        assertArrayEquals(aliceSharedSecret, bobSharedSecret);
    }

    @Test
    public void testDestroyedEcObjects() throws Exception {
        // ECDSA
        EcKeyPair keyPair = CryptoUtils.ecGenerateKeyPair();
        assertNotNull(keyPair);
        byte[] testData = CryptoUtils.randomBytes(128);
        assertNotNull(testData);

        final byte[] validSignature = CryptoUtils.ecdsaComputeSignature(testData, keyPair.getPrivateKey());
        assertNotNull(validSignature);

        keyPair.getPrivateKey().destroy();
        assertNull(keyPair.getPrivateKey().getPrivateKeyData());

        final byte[] emptySignature = CryptoUtils.ecdsaComputeSignature(testData, keyPair.getPrivateKey());
        assertNull(emptySignature);

        assertTrue(CryptoUtils.ecdsaValidateSignature(testData, validSignature, keyPair.getPublicKey()));
        keyPair.getPublicKey().destroy();
        assertNull(keyPair.getPublicKey().getPublicKeyData());
        assertFalse(CryptoUtils.ecdsaValidateSignature(testData, validSignature, keyPair.getPublicKey()));

        // ECDH
        final EcKeyPair alice = CryptoUtils.ecGenerateKeyPair();
        assertNotNull(alice);
        final EcKeyPair bob = CryptoUtils.ecGenerateKeyPair();
        assertNotNull(bob);

        bob.getPublicKey().destroy();
        bob.getPrivateKey().destroy();

        assertNull(CryptoUtils.ecdhComputeSharedSecret(bob.getPublicKey(), alice.getPrivateKey()));
        assertNull(CryptoUtils.ecdhComputeSharedSecret(alice.getPublicKey(), bob.getPrivateKey()));
    }

    //
    // CryptoUtils.randomBytes(...)
    //

    public void testRandomBytes() throws Exception {
        byte[] randomBytes;

        randomBytes = CryptoUtils.randomBytes(-1);
        assertNull(randomBytes);

        randomBytes = CryptoUtils.randomBytes(0);
        assertNotNull(randomBytes);
        assertEquals(0, randomBytes.length);

        randomBytes = CryptoUtils.randomBytes(16);
        assertNotNull(randomBytes);
        assertEquals(16, randomBytes.length);

        randomBytes = CryptoUtils.randomBytes(2000);
        assertNotNull(randomBytes);
        assertEquals(2000, randomBytes.length);
    }

    private static class HmacTestData {
        public final byte[] key;
        public final byte[] data;
        public final byte[] hmac;
        HmacTestData(String key, String data, String hmac) {
            this.key = hexStringToByteArray(key);
            this.data = hexStringToByteArray(data);
            this.hmac = hexStringToByteArray(hmac);
        }
    }

    //
    // CryptoUtils.hmacSha256(...)
    //

    @Test
    public void testHmacSha256() throws Exception {
        HmacTestData[] testData = new HmacTestData[] {
                new HmacTestData(
                        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                        "4869205468657265",
                        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
                new HmacTestData(
                        "4a656665",
                        "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
                        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
                new HmacTestData(
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                        "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
                new HmacTestData(
                        "0102030405060708090a0b0c0d0e0f10111213141516171819",
                        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
                        "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
                new HmacTestData(
                        "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
                        "546573742057697468205472756e636174696f6e",
                        "a3b6167473100ee06e0c796c2955552b"),
                new HmacTestData(
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"+
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"+
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"+
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a"+
                        "65204b6579202d2048617368204b6579204669727374",
                        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
                new HmacTestData(
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"+
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"+
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"+
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "5468697320697320612074657374207573696e672061206c6172676572207468"+
                        "616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074"+
                        "68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565"+
                        "647320746f20626520686173686564206265666f7265206265696e6720757365"+
                        "642062792074686520484d414320616c676f726974686d2e",
                        "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"),
                new HmacTestData(null, "00", null),
                new HmacTestData("00", null, null)
        };

        for (HmacTestData data : testData) {
            int outputLength = data.hmac == null ? 0 : data.hmac.length;
            byte[] mac = CryptoUtils.hmacSha256(data.data, data.key, outputLength);
            assertArrayEquals(data.hmac, mac);
        }

        // Test default impl.
        for (HmacTestData data : testData) {
            int outputLength = data.hmac == null ? 0 : data.hmac.length;
            if (outputLength != 32) {
                continue;
            }
            byte[] mac = CryptoUtils.hmacSha256(data.data, data.key);
            assertArrayEquals(data.hmac, mac);
        }
    }

    //
    // CryptoUtils.hashSha256(...)
    //

    private static class ShaTestData {
        final byte[] message;
        final byte[] hash;
        ShaTestData(String message, String hash) {
            this.message = hexStringToByteArray(message);
            this.hash = hexStringToByteArray(hash);
        }
    }

    @Test
    public void testSha256() throws Exception {
        ShaTestData[] testData = new ShaTestData[] {
                new ShaTestData(
                        "",
                        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
                new ShaTestData(
                        "d3",
                        "28969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c1"),
                new ShaTestData(
                        "11af",
                        "5ca7133fa735326081558ac312c620eeca9970d1e70a4b95533d956f072d1f98"),
                new ShaTestData(
                        "b4190e",
                        "dff2e73091f6c05e528896c4c831b9448653dc2ff043528f6769437bc7b975c2"),
                new ShaTestData(
                        "47991301156d1d977c0338efbcad41004133aefbca6bcf7e",
                        "feeb4b2b59fec8fdb1e55194a493d8c871757b5723675e93d3ac034b380b7fc9"),
                new ShaTestData(
                        "64cd363ecce05fdfda2486d011a3db95b5206a19d3054046819dd0d36783955d7e5bf8ba18bf738a",
                        "32caef024f84e97c30b4a7b9d04b678b3d8a6eb2259dff5b7f7c011f090845f8"),
                new ShaTestData(null, null)
        };
        for (ShaTestData data : testData) {
            byte[] hash = CryptoUtils.hashSha256(data.message);
            assertArrayEquals(data.hash, hash);
        }
    }

    /**
     * Helper function converts hexadecimal string into array of bytes.
     * @param s Hexadecimal string to convert.
     * @return converted bytes or null if 's' is also null.
     */
    private static byte[] hexStringToByteArray(String s) {
        if (s == null) {
            return null;
        }
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            int index = i * 2;
            int v = Integer.parseInt(s.substring(index, index + 2), 16);
            b[i] = (byte) v;
        }
        return b;
    }
}
