package edu.uw.medhas.mhealthsecurityframework.acl.model;

import edu.uw.medhas.mhealthsecurityframework.acl.constants.DbConstants;

/**
 * This class contains the details of the current user. It has the current user Id and the current user context
 * used to check authorization of the user while performing an operation.
 *
 * @author Medha Srivastava
 * Created on 2/18/19.
 */

public class AuthContext {
    private final String mUserId;

    public AuthContext(String userId) {
        mUserId = userId;
    }

    public static AuthContext getRootContext() {
        return new AuthContext(DbConstants.ROOT_USER_ID);
    }

    public String getUserId() {
        return mUserId;
    }
}
