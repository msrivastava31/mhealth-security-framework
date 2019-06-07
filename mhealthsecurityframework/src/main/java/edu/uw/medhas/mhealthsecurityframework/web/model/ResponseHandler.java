package edu.uw.medhas.mhealthsecurityframework.web.model;

/**
 * This interface is a listener that is used to capture and transfer the response of a process.
 * It contains two methods onSuccess() and onFailure().
 *
 * @author Medha Srivastava
 * Created by medhas on 2/17/19.
 */

public interface ResponseHandler {
    /**
     * This method has course of actions to be performed on success of a process.
     * @param response the response object
     */
    void onSuccess(Response response);

    /**
     * This method has course of actions to be performed on failure of a process.
     * @param webError the webError object
     */
    void onError(WebError webError);
}
