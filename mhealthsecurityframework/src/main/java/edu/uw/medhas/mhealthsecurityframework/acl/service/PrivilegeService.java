package edu.uw.medhas.mhealthsecurityframework.acl.service;

import edu.uw.medhas.mhealthsecurityframework.acl.db.ResultHandler;
import edu.uw.medhas.mhealthsecurityframework.acl.model.AuthContext;
import edu.uw.medhas.mhealthsecurityframework.acl.model.Privilege;
import edu.uw.medhas.mhealthsecurityframework.acl.model.Role;

/**
 * This interface contains methods to create a Privilege, delete a Privilege(and delete corresponding
 * resource and operation) and check for authorization (if a particular role can perform an operation on a resource).
 *
 * @author Medha Srivastava
 * Created on 2/18/19.
 */

public interface PrivilegeService {

    /**
     * Creates a privilege on a role to perform an operation on a resource.
     * @param roleName Name of the role
     * @param resourceName Name of the resource
     * @param operationName Name of the operation
     * @param authContext details of the current user
     * @param resultHandler listener to store the result of the query
     */
    void createPrivilege(final String roleName, final String resourceName, final String operationName,
                         final AuthContext authContext, final ResultHandler<Privilege> resultHandler);

    /**
     * Deletes a privilege on a role to perform an operation on a resource.
     * @param roleName Name of the role
     * @param resourceName Name of the resource
     * @param operationName Name of the operation
     * @param authContext details of the current user
     * @param resultHandler listener to store the result of the query
     */
    void deletePrivilege(final String roleName, final String resourceName, final String operationName,
                         final AuthContext authContext, final ResultHandler<Void> resultHandler);

    /**
     * Checks for authorization if a particular user can perform an operation on a resource.
     * @param userId User Id
     * @param resourceName Name of the resource
     * @param operationName Name of the operation
     * @param resultHandler listener to store the result of the query
     */
    void isAllowed(final String userId, final String resourceName, final String operationName,
                   final ResultHandler<Boolean> resultHandler);

    /**
     * Delete the resource when a privilege is deleted
     * @param resourceName Name of the resource to be deleted
     * @param authContext details of the current user
     * @param resultHandler listener to store the result of the query
     */
    void deleteResource(final String resourceName, final AuthContext authContext, final ResultHandler<Void> resultHandler);

    /**
     * Delete the operation when a privilege is deleted
     * @param operationName Name of the operation to be deleted
     * @param authContext details of the current user
     * @param resultHandler listener to store the result of the query
     */
    void deleteOperation(final String operationName, final AuthContext authContext, final ResultHandler<Void> resultHandler);
}
