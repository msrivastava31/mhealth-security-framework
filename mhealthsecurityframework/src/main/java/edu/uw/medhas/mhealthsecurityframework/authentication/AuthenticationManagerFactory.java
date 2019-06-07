package edu.uw.medhas.mhealthsecurityframework.authentication;

import android.app.KeyguardManager;
import android.hardware.fingerprint.FingerprintManager;

/**
 * Factory Class to generate an appropriate AuthenticationManager object.
 *
 * @author Medha Srivastava
 * Created by medhas on 2/4/19.
 */

public class AuthenticationManagerFactory {
    // Create an instance of AuthenticationManager.
    private static AuthenticationManager sAuthenticationManagerInstance;

    /**
     * Depending on availability of fingerprint hardware in the phone,
     * initiates the authenticationManager object as FingerprintAuthenticationManager or
     * BasicAuthenticationManager.
     *
     * @param fingerprintManager Android FingerprintManager object
     * @param keyguardManager Android KeyguardManager object
     */
    public static void init(FingerprintManager fingerprintManager,
                            KeyguardManager keyguardManager) {
        // If fingerprint hardware is present, initiate the authenticationManager
        // object as FingerprintAuthenticationManager object.
        if (fingerprintManager.isHardwareDetected()) {
            AuthenticationManagerFactory.sAuthenticationManagerInstance
                    = new FingerprintAuthenticationManager(fingerprintManager, keyguardManager);
        }
        // Else if, fingerprint hardware is not present, initiate the authenticationManager
        // object as BasicAuthenticationManager object.
        else {
            AuthenticationManagerFactory.sAuthenticationManagerInstance
                    = new BasicAuthenticationManager();
        }
    }

    /**
     *  Returns the AuthenticationManager object.
     * @return AuthenticationManager
     */
    public static AuthenticationManager getAuthenticationManager() {
        return AuthenticationManagerFactory.sAuthenticationManagerInstance;
    }
}
