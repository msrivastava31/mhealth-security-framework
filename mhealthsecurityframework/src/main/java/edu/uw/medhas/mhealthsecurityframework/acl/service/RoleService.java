package edu.uw.medhas.mhealthsecurityframework.acl.service;

import edu.uw.medhas.mhealthsecurityframework.acl.db.ResultHandler;
import edu.uw.medhas.mhealthsecurityframework.acl.model.AuthContext;
import edu.uw.medhas.mhealthsecurityframework.acl.model.Role;

/**
 * This interface contains methods to create a Role and delete a Role.
 *
 * @author Medha Srivastava
 * Created by medhas on 2/18/19.
 */

public interface RoleService {

    /**
     * Creates a role.
     * @param role role to be created
     * @param authContext details of the current user
     * @param resultHandler listener to store the result of the query
     */
    void createRole(final Role role, final AuthContext authContext, final ResultHandler<Role> resultHandler);

    /**
     * Deletes a role.
     * @param roleName Name of role to be deleted
     * @param authContext details of the current user
     * @param resultHandler listener to store the result of the query
     */
    void deleteRole(final String roleName, final AuthContext authContext, final ResultHandler<Void> resultHandler);
}
