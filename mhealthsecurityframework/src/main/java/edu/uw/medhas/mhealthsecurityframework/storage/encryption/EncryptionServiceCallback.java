package edu.uw.medhas.mhealthsecurityframework.storage.encryption;

import javax.crypto.Cipher;

import edu.uw.medhas.mhealthsecurityframework.authentication.AuthenticationServiceCallback;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResultErrorType;

/**
 * This interface extends AuthenticationServiceCallback.
 * It contains definitions of methods that on successful authentication,
 * perform encryption/decryption [onSuccess()] and set an error message
 * [onFailure()] on an un-successful authentication.
 *
 * @author Medha Srivastava
 * Created on 2/7/19.
 */

public interface EncryptionServiceCallback extends AuthenticationServiceCallback {
    /**
     * On successful authentication, encryption/decryption is performed.
     *
     * @param cipher to perform encryption/decryption
     */
    void onSuccess(Cipher cipher);

    /**
     * On un-successful authentication, an error message is set.
     *
     * @param storageResultErrorType to set the error message
     */
    void onFailure(StorageResultErrorType storageResultErrorType);
}
