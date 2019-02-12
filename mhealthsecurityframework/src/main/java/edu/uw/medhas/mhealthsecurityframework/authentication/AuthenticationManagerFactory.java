package edu.uw.medhas.mhealthsecurityframework.authentication;

import android.app.KeyguardManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.util.Log;

/**
 * Created by medhas on 2/4/19.
 */

public class AuthenticationManagerFactory {
    private static AuthenticationManager sAuthenticationManagerInstance;

    public static void init(FingerprintManager fingerprintManager,
                            KeyguardManager keyguardManager) {
        if (fingerprintManager.isHardwareDetected()) {
            Log.v("AuthenticationManagerFactory::init", "FingerPrint hardware detected");
            AuthenticationManagerFactory.sAuthenticationManagerInstance
                    = new FingerprintAuthenticationManager(fingerprintManager, keyguardManager);
        } else {
            Log.v("AuthenticationManagerFactory::init", "No fingerPrint hardware detected");
            AuthenticationManagerFactory.sAuthenticationManagerInstance
                    = new BasicAuthenticationManager();
        }
    }

    public static AuthenticationManager getAuthenticationManager() {
        return AuthenticationManagerFactory.sAuthenticationManagerInstance;
    }
}
