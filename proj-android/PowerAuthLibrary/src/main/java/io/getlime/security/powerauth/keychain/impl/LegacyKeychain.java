/*
 * Copyright 2020 Wultra s.r.o.
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

package io.getlime.security.powerauth.keychain.impl;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import android.util.Base64;

import java.util.Set;

import io.getlime.security.powerauth.keychain.Keychain;

/**
 * The {@code LegacyKeychain} class implements {@link Keychain} interface with no content
 * encryption. The class is used on all devices that doesn't support KeyStore reliably
 * (e.g. on all systems older than Android "M".)
 */
public class LegacyKeychain implements Keychain {

    private final String identifier;
    private final Context context;

    /**
     * Default constructor, initialize keychain with given identifier.
     * @param context Android context.
     * @param identifier Identifier.
     */
    public LegacyKeychain(@NonNull Context context, @NonNull String identifier) {
        this.context = context;
        this.identifier = identifier;
    }

    @NonNull
    @Override
    public String getIdentifier() {
        return identifier;
    }

    @Override
    public boolean isEncrypted() {
        return false;
    }

    @Override
    public boolean isStrongBoxBacked() {
        return false;
    }

    @Override
    public boolean isReservedKey(@NonNull String key) {
        return ReservedKeyImpl.isReservedKey(key);
    }

    // Byte array accessors

    @Override
    public synchronized boolean contains(@NonNull String key) {
        ReservedKeyImpl.failOnReservedKey(key);
        return getSharedPreferences().contains(key);
    }

    @Override
    public synchronized void remove(@NonNull String key) {
        ReservedKeyImpl.failOnReservedKey(key);
        getSharedPreferences()
                .edit()
                .remove(key)
                .apply();
    }

    @Override
    public synchronized void removeAll() {
        getSharedPreferences()
                .edit()
                .clear()
                .apply();
    }

    @Nullable
    @Override
    public synchronized byte[] getData(@NonNull String key) {
        final String serializedData = getStringValue(key);
        if (serializedData != null) {
            final byte[] data = Base64.decode(serializedData, Base64.DEFAULT);
            return data.length > 0 ? data : null;
        }
        return null;
    }

    @Override
    public synchronized void putData(@Nullable byte[] data, @NonNull String key) {
        final String serializedData = (data != null && data.length > 0) ? Base64.encodeToString(data, Base64.DEFAULT) : null;
        setStringValue(key, serializedData);
    }

    // String accessors

    @Nullable
    @Override
    public synchronized String getString(@NonNull String key) {
        return getStringValue(key);
    }

    @NonNull
    @Override
    public synchronized String getString(@NonNull String key, @NonNull String defaultValue) {
        String value = getStringValue(key);
        return value != null ? value : defaultValue;
    }

    @Override
    public synchronized void putString(@Nullable String string, @NonNull String key) {
        setStringValue(key, string);
    }

    // String Set accessors

    @Nullable
    @Override
    public Set<String> getStringSet(@NonNull String key) {
        ReservedKeyImpl.failOnReservedKey(key);
        return getSharedPreferences().getStringSet(key, null);
    }

    @Override
    public void putStringSet(@Nullable Set<String> stringSet, @NonNull String key) {
        ReservedKeyImpl.failOnReservedKey(key);
        getSharedPreferences()
                .edit()
                .putStringSet(key, stringSet)
                .apply();
    }

    // Boolean accessors

    @Override
    public synchronized boolean getBoolean(@NonNull String key, boolean defaultValue) {
        ReservedKeyImpl.failOnReservedKey(key);
        return getSharedPreferences().getBoolean(key, defaultValue);
    }

    @Override
    public synchronized void putBoolean(boolean value, @NonNull String key) {
        ReservedKeyImpl.failOnReservedKey(key);
        getSharedPreferences()
                .edit()
                .putBoolean(key, value)
                .apply();
    }

    // Long accessors

    @Override
    public synchronized long getLong(@NonNull String key, long defaultValue) {
        ReservedKeyImpl.failOnReservedKey(key);
        return getSharedPreferences().getLong(key, defaultValue);
    }

    @Override
    public synchronized void putLong(long value, @NonNull String key) {
        ReservedKeyImpl.failOnReservedKey(key);
        getSharedPreferences()
                .edit()
                .putLong(key, value)
                .apply();
    }

    // Float accessors

    @Override
    public float getFloat(@NonNull String key, float defaultValue) {
        ReservedKeyImpl.failOnReservedKey(key);
        return getSharedPreferences().getFloat(key, defaultValue);
    }

    @Override
    public void putFloat(float value, @NonNull String key) {
        ReservedKeyImpl.failOnReservedKey(key);
        getSharedPreferences()
                .edit()
                .putFloat(key, value)
                .apply();
    }

    // Private methods

    /**
     * @return Underlying {@code SharedPreferences} that contains content of keychain.
     */
    private @NonNull SharedPreferences getSharedPreferences() {
        return context.getSharedPreferences(identifier, Context.MODE_PRIVATE);
    }

    /**
     * Return value stored in the shared preferences.
     *
     * @param key Key to be used for string retrieval.
     * @return Stored value in case there are some data under given key, null otherwise.
     */
    private @Nullable String getStringValue(@NonNull String key) {
        ReservedKeyImpl.failOnReservedKey(key);
        return getSharedPreferences().getString(key, null);
    }

    /**
     * Put value to the shared preferences.
     *
     * @param key Key to be used for storing string.
     * @param value String to be stored. If value is null then it's equal to {@code removeDataForKey()}.
     */
    private void setStringValue(@NonNull String key, @Nullable String value) {
        ReservedKeyImpl.failOnReservedKey(key);
        getSharedPreferences()
                .edit()
                .putString(key, value)
                .apply();
    }
}

