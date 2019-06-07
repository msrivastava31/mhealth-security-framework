package edu.uw.medhas.mhealthsecurityframework.authentication;

import android.app.KeyguardManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.CancellationSignal;

import java.util.Optional;

import edu.uw.medhas.mhealthsecurityframework.storage.encryption.EncryptionServiceCallback;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResultErrorType;

/**
 * This class implements the interface AuthenticationManager.
 * It contains methods that initiate the authentication process
 * using fingerprint.
 *
 * @author Medha Srivastava
 * Created on 2/4/19.
 */

public class FingerprintAuthenticationManager implements AuthenticationManager {
    private final FingerprintManager mFingerprintManager;
    private final KeyguardManager mKeyguardManager;

    private final CancellationSignal mSignal = new CancellationSignal();

    /**
     * Constructs an object of FingerprintAuthenticationManager.
     *
     * @param fingerprintManager Android fingerprintManager object
     * @param keyguardManager keyguardManager object
     */
    public FingerprintAuthenticationManager(FingerprintManager fingerprintManager,
                                            KeyguardManager keyguardManager) {
        mFingerprintManager = fingerprintManager;
        mKeyguardManager = keyguardManager;
    }

    /**
     * This method returns the duration for which the authentication
     * will stay valid.
     *
     * @return duration for which authentication will stay valid
     */
    @Override
    public Optional<Integer> getUserAuthenticationValidityDurationSeconds() {
        return Optional.empty();
    }

    /**
     * This method performs fingerprint authentication before
     * storing /retrieving sensitive data.
     *
     * @param cryptoObject object used in the authentication process
     * @param callback Used for encryption/decryption on successful authentication
     */
    @Override
    public void performAuthentication(FingerprintManager.CryptoObject cryptoObject,
                                      final EncryptionServiceCallback callback) {

        // Check for enrolled (registered) fingerprints.
        if (!mFingerprintManager.hasEnrolledFingerprints()) {
            callback.onFailure(StorageResultErrorType.NO_FINGERPRINT_AVAILABLE);
            return;
        }
        // Check if password/pin authentication is enabled.
        else if (!mKeyguardManager.isKeyguardSecure()) {
            callback.onFailure(StorageResultErrorType.KEUGUARD_UNSECURE);
            return;
        }

        // Initiating fingerprint authentication process.
        mFingerprintManager.authenticate(cryptoObject,
                mSignal,
                0,
                new FingerprintManager.AuthenticationCallback() {
                    @Override
                    public void onAuthenticationError(int errorCode, CharSequence errString) {
                        callback.onFailure(StorageResultErrorType.AUTH_ERROR);
                    }

                    @Override
                    public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
                        callback.onFailure(StorageResultErrorType.AUTH_HELP);
                    }

                    @Override
                    public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
                        callback.onSuccess(result.getCryptoObject().getCipher());
                    }

                    @Override
                    public void onAuthenticationFailed() {
                        callback.onFailure(StorageResultErrorType.FINGERPRINT_INVALID);
                    }
                }, null);

        callback.onWaitingForAuthentication();
    }
}
