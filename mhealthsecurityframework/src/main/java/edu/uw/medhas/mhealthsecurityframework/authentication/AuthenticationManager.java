package edu.uw.medhas.mhealthsecurityframework.authentication;

import android.hardware.fingerprint.FingerprintManager;

import edu.uw.medhas.mhealthsecurityframework.storage.encryption.EncryptionServiceCallback;

/**
 * Created by medhas on 2/4/19.
 */

public interface AuthenticationManager {
    boolean isUserAuthenticationPossible();

    void performAuthentication(FingerprintManager.CryptoObject cryptoObject,
                                 EncryptionServiceCallback callback);
}
