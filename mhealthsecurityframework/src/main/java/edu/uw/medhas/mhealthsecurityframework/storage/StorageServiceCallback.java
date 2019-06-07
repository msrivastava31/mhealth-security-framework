package edu.uw.medhas.mhealthsecurityframework.storage;

import edu.uw.medhas.mhealthsecurityframework.authentication.AuthenticationServiceCallback;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResultErrorType;

/**
 * This interface extends AuthenticationServiceCallback.
 * It contains definitions of methods that on successful authentication,
 * convert the object to byte stream/byte stream to object [onSuccess()]
 * and set an error message [onFailure()] on an un-successful authentication.
 *
 * @author Medha Srivastava
 * Created by medhas on 2/7/19.
 */

public interface StorageServiceCallback<Test> extends AuthenticationServiceCallback {
    /**
     * On successful authentication, conversion of object to byte stream
     * /byte stream to object is performed.
     *
     * @param result contains the object/byte stream
     */
    void onSuccess(Test result);

    /**
     * On un-successful authentication, an error message is set.
     *
     * @param storageResultErrorType to set the error message
     */
    void onFailure(StorageResultErrorType storageResultErrorType);
}
