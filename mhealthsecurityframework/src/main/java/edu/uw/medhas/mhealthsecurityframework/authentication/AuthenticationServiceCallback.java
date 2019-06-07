package edu.uw.medhas.mhealthsecurityframework.authentication;

/**
 * This interface contains a method which indicates that the process is
 * waiting for the user to complete the authentication process.
 *
 * @author Medha Srivastava
 * Created by medhas on 2/8/19.
 */

public interface AuthenticationServiceCallback {
    /**
     * Indicates that the process is waiting for the user to complete the
     * authentication process.
     */
    void onWaitingForAuthentication();
}
