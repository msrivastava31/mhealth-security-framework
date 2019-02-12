package edu.uw.medhas.mhealthsecurityframework.authentication;

import android.app.KeyguardManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.CancellationSignal;

import edu.uw.medhas.mhealthsecurityframework.storage.encryption.EncryptionServiceCallback;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResultErrorType;

/**
 * Created by medhas on 2/4/19.
 */

public class FingerprintAuthenticationManager implements AuthenticationManager {
    private final FingerprintManager mFingerprintManager;
    private final KeyguardManager mKeyguardManager;

    private final CancellationSignal mSignal = new CancellationSignal();

    public FingerprintAuthenticationManager(FingerprintManager fingerprintManager,
                                            KeyguardManager keyguardManager) {
        mFingerprintManager = fingerprintManager;
        mKeyguardManager = keyguardManager;
    }

    public boolean isUserAuthenticationPossible() {
        return true;
    }

    @Override
    public void performAuthentication(FingerprintManager.CryptoObject cryptoObject,
                                      final EncryptionServiceCallback callback) {
        if (!mFingerprintManager.hasEnrolledFingerprints()) {
            callback.onFailure(StorageResultErrorType.NO_FINGERPRINT_AVAILABLE);
            return;
        } else if (!mKeyguardManager.isKeyguardSecure()) {
            callback.onFailure(StorageResultErrorType.KEUGUARD_UNSECURE);
            return;
        }

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

    /*
    @Override
    public Cipher performAuthentication(FingerprintManager.CryptoObject cryptoObject) {
        Log.i("FingerprintAuthenticationManager::performAuthentication", "Inside method");
        if (ActivityCompat.checkSelfPermission(ContextHolder.getInstance().getContext(),
                Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
            throw new FingerprintDisallowedException();
        } else if (!mFingerprintManager.hasEnrolledFingerprints()) {
            throw new NoFingerprintAvailableException();
        } else if (!mKeyguardManager.isKeyguardSecure()) {
            throw new KeyguardUnsecureException();
        }

        Log.i("FingerprintAuthenticationManager::performAuthentication",
                "All basic checks passed");

        final CancellationSignal cancellationSignal = new CancellationSignal();

        //final CountDownLatch latch = new CountDownLatch(1);

        final FingerprintAuthenticationResult authenticationResult
                = new FingerprintAuthenticationResult();

        Log.i("FingerprintAuthenticationManager::performAuthentication",
                "Going to authenticate");

        mFingerprintManager.authenticate(cryptoObject, cancellationSignal, 0,
                new FingerprintManager.AuthenticationCallback() {
            @Override
            public void onAuthenticationError(int errorCode, CharSequence errString) {
                super.onAuthenticationError(errorCode, errString);
                Log.i("AuthenticationCallback::onAuthenticationError",
                        "Inside method");
                //latch.countDown();
                authenticationResult.setResult(FingerprintAuthenticationResultType.ERROR);
            }

            @Override
            public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
                super.onAuthenticationHelp(helpCode, helpString);
                Log.i("AuthenticationCallback::onAuthenticationHelp",
                        "Inside method");
                //latch.countDown();
                authenticationResult.setResult(FingerprintAuthenticationResultType.HELP);
            }

            @Override
            public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
                super.onAuthenticationSucceeded(result);
                Log.i("AuthenticationCallback::onAuthenticationSucceeded",
                        "Inside method");
                //latch.countDown();
                authenticationResult.setResult(FingerprintAuthenticationResultType.SUCCESS);
            }

            @Override
            public void onAuthenticationFailed() {
                super.onAuthenticationFailed();
                Log.i("AuthenticationCallback::onAuthenticationFailed",
                        "Inside method");
                //latch.countDown();
                authenticationResult.setResult(FingerprintAuthenticationResultType.FAILURE);
            }
        }, null);

        //try {
            Log.i("FingerprintAuthenticationManager::performAuthentication",
                    "Waiting for authentication");
            //latch.await();

            Log.i("FingerprintAuthenticationManager::performAuthentication",
                    "Finished waiting for authentication");

            if (FingerprintAuthenticationResultType.INCOMPLETE.equals(authenticationResult.getResult())
                    || FingerprintAuthenticationResultType.FAILURE.equals(
                            authenticationResult.getResult())
                    || FingerprintAuthenticationResultType.ERROR.equals(
                    authenticationResult.getResult())
                    || FingerprintAuthenticationResultType.HELP.equals(
                    authenticationResult.getResult())) {
                throw new FingerprintFailureException();
            }
        /*} catch (InterruptedException iex) {
            iex.printStackTrace();
            throw new FingerprintFailureException();
        }

        return cryptoObject.getCipher();
    }*/
}
