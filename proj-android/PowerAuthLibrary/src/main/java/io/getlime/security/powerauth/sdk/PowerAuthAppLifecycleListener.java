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

package io.getlime.security.powerauth.sdk;

import android.app.Activity;
import android.app.Application;
import android.content.Context;
import android.os.Bundle;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import io.getlime.security.powerauth.system.PowerAuthLog;

import java.lang.ref.WeakReference;
import java.util.ArrayList;

/**
 * The {@code PowerAuthAppLifecycleListener} is a global listener that provides information about application's lifecycle
 * to PowerAuth mobile SDK.
 */
public class PowerAuthAppLifecycleListener implements Application.ActivityLifecycleCallbacks {

    /**
     * Contains true if object is properly registered for events.
     */
    private boolean isRegistered = false;

    /**
     * Private constructor.
     */
    private PowerAuthAppLifecycleListener() {
    }

    /**
     * Singleton
     */
    private static final PowerAuthAppLifecycleListener INSTANCE = new PowerAuthAppLifecycleListener();

    /**
     * @return Singleton instance of {@code PowerAuthAppLifecycleManager} class.
     */
    @NonNull
    public static PowerAuthAppLifecycleListener getInstance() {
        return INSTANCE;
    }

    /**
     * @return {@code true} if this object is already registered for activity lifecycle callbacks.
     */
    public boolean isRegistered() {
        synchronized (this) {
            return isRegistered;
        }
    }

    /**
     * Register this object to listen for activity lifecycle callbacks.
     * @param appContext Application's context or Application object.
     */
    public void registerForActivityLifecycleCallbacks(@NonNull Context appContext) {
        synchronized (this) {
            registerForActivityLifecycleCallbacksImpl(appContext);
        }
    }

    /**
     * Register {@code PowerAuthAppLifecycleManager} for application lifecycle events.
     * @param appContext Application's context.
     */
    private void registerForActivityLifecycleCallbacksImpl(@NonNull Context appContext) {
        if (!isRegistered) {
            appContext = appContext.getApplicationContext();
            if (appContext instanceof Application) {
                final Application application = (Application) appContext;
                application.registerActivityLifecycleCallbacks(this);
                isRegistered = true;
            }
        }
    }

    // Tasks

    /**
     * Time services registered for reset.
     */
    private final ArrayList<WeakReference<IPowerAuthTimeSynchronizationService>> registeredServices = new ArrayList<>();

    /**
     * Register instance of {@link IPowerAuthTimeSynchronizationService} for reset in case that app is going from
     * background to foreground.
     * @param appContext Application's context.
     * @param service Time synchronization service.
     */
    void registerTimeSynchronizationService(@NonNull Context appContext, @NonNull IPowerAuthTimeSynchronizationService service) {
        synchronized (this) {
            registerForActivityLifecycleCallbacksImpl(appContext);
            registeredServices.add(new WeakReference<>(service));
        }
    }

    private void resetTimeSynchronizationServices(boolean wasStartedBefore) {
        if (!wasStartedBefore) {
            // Application just started, we don't need to reset the service.
            return;
        }
        // Iterate over all weak references and reset the time service
        final ArrayList<WeakReference<IPowerAuthTimeSynchronizationService>> referencesToRemove = new ArrayList<>();
        for (WeakReference<IPowerAuthTimeSynchronizationService> weakReference : registeredServices) {
            final IPowerAuthTimeSynchronizationService service = weakReference.get();
            if (service != null) {
                service.resetTimeSynchronization();
            } else {
                referencesToRemove.add(weakReference);
            }
        }
        // Cleanup all references that no longer contains valid service
        registeredServices.removeAll(referencesToRemove);
    }

    // Transitions

    /**
     * Called when application is transitioning from background to foreground.
     * @param wasStartedBefore Contains false if this is a fresh start.
     */
    private void onTransitionFromBackgroundToForeground(boolean wasStartedBefore) {
        synchronized (this) {
            resetTimeSynchronizationServices(wasStartedBefore);
        }
    }

    // Application.ActivityLifecycleCallbacks implementation

    /**
     * If true, then this is a not first start.
     */
    private boolean wasStartedBefore = false;
    /**
     * Number of activities started.
     */
    private int numActivitiesStarted = 0;

    @Override
    public void onActivityCreated(@NonNull Activity activity, @Nullable Bundle savedInstanceState) {
    }

    @Override
    public void onActivityStarted(@NonNull Activity activity) {
        if (numActivitiesStarted == 0) {
            onTransitionFromBackgroundToForeground(wasStartedBefore);
        }
        numActivitiesStarted++;
    }

    @Override
    public void onActivityResumed(@NonNull Activity activity) {
    }

    @Override
    public void onActivityPaused(@NonNull Activity activity) {
    }

    @Override
    public void onActivityStopped(@NonNull Activity activity) {
        numActivitiesStarted--;
        if (numActivitiesStarted == 0) {
            wasStartedBefore = true;
        }
    }

    @Override
    public void onActivitySaveInstanceState(@NonNull Activity activity, @NonNull Bundle outState) {
    }

    @Override
    public void onActivityDestroyed(@NonNull Activity activity) {
    }
}
