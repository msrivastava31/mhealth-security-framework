package edu.uw.medhas.mhealthsecurityframework.acl.service;

import edu.uw.medhas.mhealthsecurityframework.acl.db.ResultHandler;
import edu.uw.medhas.mhealthsecurityframework.acl.model.AuthContext;
import edu.uw.medhas.mhealthsecurityframework.acl.model.Role;
import edu.uw.medhas.mhealthsecurityframework.acl.model.User;
import edu.uw.medhas.mhealthsecurityframework.acl.model.UserRole;

/**
 * This interface contains methods to create a User and delete a User.
 *
 * @author Medha Srivastava
 * Created by medhas on 2/18/19.
 */

public interface UserService {

    /**
     * Creates a user.
     * @param user User to be created
     * @param authContext details of the current user
     * @param resultHandler listener to store the result of the query
     */
    void createUser(final User user, final AuthContext authContext, final ResultHandler<User> resultHandler);

    /**
     * Assigns a Role to a user.
     * @param userId Id of the user
     * @param roleName Name of the role
     * @param authContext details of the current user
     * @param resultHandler listener to store the result of the query
     */
    void assignRoleToUser(final String userId, final String roleName, final AuthContext authContext,
                          final ResultHandler<UserRole> resultHandler);

    /**
     * Deletes a user.
     * @param userId Id of the user to be deleted
     * @param authContext details of the current user
     * @param resultHandler listener to store the result of the query
     */
    void deleteUser(final String userId, final AuthContext authContext, final ResultHandler<Void> resultHandler);
}
