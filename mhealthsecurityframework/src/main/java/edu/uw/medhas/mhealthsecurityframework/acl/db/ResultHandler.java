package edu.uw.medhas.mhealthsecurityframework.acl.db;

/**
 * This interface is a listener that is used to capture and transfer the result of a process.
 * It contains two methods onSuccess() and onFailure().
 *
 * @author Medha Srivastava
 * Created on 2/22/19.
 */

public interface ResultHandler<T> {
    /**
     * This method has course of actions to be performed on success of a process.
     * @param result the result object
     */
    void onSuccess(T result);

    /**
     * This method has course of actions to be performed on failure of a process.
     * @param error the DbError object
     */
    void onFailure(DbError error);
}
