package io.getlime.security.powerauth.integration.support;

import android.support.annotation.NonNull;
import android.util.Base64;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * The {@code RandomGenerator} class helps with generate various random data. Note that this class
 * doesn't guarantee a cryptographic randomness. The implementation can be used for testing only
 * purposes.
 */
public class RandomGenerator {

    private final Random random;

    /**
     * Construct random generator object.
     */
    public RandomGenerator() {
        this.random = new Random();
    }

    /**
     * Generate random bytes.
     * @param length Number of bytes to produce.
     * @return Array of random bytes.
     */
    public @NonNull byte[] generateBytes(int length) {
        final byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }

    /**
     * Generate random bytes in Base64 format.
     * @param length Number of bytes to produce.
     * @return Array of random bytes.
     */
    public @NonNull String generateBase64Bytes(int length) {
        return Base64.encodeToString(generateBytes(length), Base64.NO_WRAP);
    }

    /**
     * Generate multiple random strings, each different from others.
     *
     * @param count Number of generated random strings.
     * @param minLength Minimum length for each random string.
     * @param maxLength Maximum length for each random string.
     * @return Different random strings.
     * @throws Exception In case that random generator failed to produce enough random data.
     */
    public @NonNull List<String> generateRandomStrings(int count, int minLength, int maxLength) throws Exception {
        if (count < 1) {
            throw new IllegalArgumentException("count must be greater than zero");
        }
        final ArrayList<String> strings = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            String randomString = null;
            for (int attempt = 0; attempt < 10; attempt++) {
                String str = generateRandomString(minLength, maxLength);
                if (-1 == strings.indexOf(str)) {
                    randomString = str;
                    break;
                }
            }
            if (randomString == null) {
                throw new Exception("Failed to generate different random string.");
            }
            strings.add(randomString);
        }
        return strings;
    }

    /**
     * Generate random string.
     * @param minLength Minimum string length.
     * @param maxLength Maximum string length.
     * @return Random string.
     */
    public @NonNull String generateRandomString(int minLength, int maxLength) {
        if (minLength < 0) {
            throw new IllegalArgumentException("minLength must be possitive number");
        }
        if (maxLength < minLength) {
            throw new IllegalArgumentException("maxLength must be greater or equal to minLength");
        }
        int length;
        if (minLength == maxLength) {
            length = minLength;
        } else {
            length = minLength + random.nextInt(maxLength - minLength);
        }
        StringBuilder buffer = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            // Generate random ASCII character in printable characters range.
            int randomChar = 32 + random.nextInt(128 - 32);
            buffer.append((char)randomChar);
        }
        return buffer.toString();
    }
}
