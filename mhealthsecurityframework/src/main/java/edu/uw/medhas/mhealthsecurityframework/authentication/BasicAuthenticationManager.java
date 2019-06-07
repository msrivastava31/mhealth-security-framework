package edu.uw.medhas.mhealthsecurityframework.authentication;

import android.hardware.fingerprint.FingerprintManager;

import java.util.Optional;

import edu.uw.medhas.mhealthsecurityframework.storage.encryption.EncryptionServiceCallback;

/**
 * This class implements the interface AuthenticationManager.
 * It contains methods that initiate the authentication process
 * using pin.
 *
 * @author Medha Srivastava
 * Created on 2/4/19.
 */

public class BasicAuthenticationManager implements AuthenticationManager {
    /**
     * This method returns the duration for which the authentication
     * will stay valid.
     *
     * @return duration for which authentication will stay valid
     */
    @Override
    public Optional<Integer> getUserAuthenticationValidityDurationSeconds() {
        return Optional.of(5);
    }

    /**
     * This method performs basic (pin) authentication before
     * storing /retrieving sensitive data.
     *
     * @param cryptoObject object used in the authentication process
     * @param callback Used for encryption/decryption on successful authentication
     */
    @Override
    public void performAuthentication(FingerprintManager.CryptoObject cryptoObject,
                                      EncryptionServiceCallback callback) {
        callback.onSuccess(cryptoObject.getCipher());
    }
}
