package edu.uw.medhas.mhealthsecurityframework.authentication;

import android.hardware.fingerprint.FingerprintManager;

import java.util.Optional;

import edu.uw.medhas.mhealthsecurityframework.storage.encryption.EncryptionServiceCallback;

/**
 * This interface contains methods that initiate the authentication
 * process using fingerprint or pin.
 *
 * @author Medha Srivastava
 * Created by medhas on 2/4/19.
 */

public interface AuthenticationManager {
    /**
     * This method returns the duration for which the authentication
     * will stay valid.
     *
     * @return duration for which authentication will stay valid
     */
    Optional<Integer> getUserAuthenticationValidityDurationSeconds();

    /**
     * This method performs authentication (fingerprint/pin) before
     * storing /retrieving sensitive data.
     *
     * @param cryptoObject object used in the authentication process
     * @param callback Used for encryption/decryption on successful authentication
     */
    void performAuthentication(FingerprintManager.CryptoObject cryptoObject,
                                 EncryptionServiceCallback callback);
}
