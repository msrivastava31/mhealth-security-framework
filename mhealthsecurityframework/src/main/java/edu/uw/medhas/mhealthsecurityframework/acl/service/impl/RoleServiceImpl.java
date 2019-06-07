package edu.uw.medhas.mhealthsecurityframework.acl.service.impl;

import android.util.Log;

import java.time.Instant;

import edu.uw.medhas.mhealthsecurityframework.acl.constants.DbConstants;
import edu.uw.medhas.mhealthsecurityframework.acl.db.AccessControlDb;
import edu.uw.medhas.mhealthsecurityframework.acl.db.DbError;
import edu.uw.medhas.mhealthsecurityframework.acl.db.ResultHandler;
import edu.uw.medhas.mhealthsecurityframework.acl.model.AuthContext;
import edu.uw.medhas.mhealthsecurityframework.acl.model.Role;
import edu.uw.medhas.mhealthsecurityframework.acl.service.PrivilegeService;
import edu.uw.medhas.mhealthsecurityframework.acl.service.RoleService;

/**
 * This class implements the RoleService interface.
 * It contains methods to create a Role and delete a Role.
 *
 * @author Medha Srivastava
 * Created on 2/20/19.
 */

public class RoleServiceImpl implements RoleService {
    private final AccessControlDb mAclDb;
    private final PrivilegeService mPrivilegeService;

    public RoleServiceImpl(AccessControlDb aclDb) {
        mAclDb = aclDb;
        mPrivilegeService = new PrivilegeServiceImpl(aclDb);
    }

    /**
     * Creates a role.
     * @param role role to be created
     * @param authContext details of the current user
     * @param resultHandler listener to store the result of the query
     */
    @Override
    public void createRole(final Role role, final AuthContext authContext, final ResultHandler<Role> resultHandler) {
        // Check if the current user is authorized to perform this operation
        mPrivilegeService.isAllowed(authContext.getUserId(), DbConstants.ROLE_RESOURCE, DbConstants.CREATE_OP,
                new ResultHandler<Boolean>() {
                    @Override
                    public void onSuccess(Boolean result) {
                        if (!result) {
                            resultHandler.onFailure(DbError.UNAUTHORIZED);
                            return;
                        }

                        try {
                            role.setCreated(Instant.now());
                            role.setUpdated(Instant.now());
                            role.setCreatedBy(authContext.getUserId());
                            role.setUpdatedBy(authContext.getUserId());

                            final long roleId = mAclDb.getRoleDao().insert(role);
                            role.setId(roleId);

                            resultHandler.onSuccess(role);
                        } catch (RuntimeException rex) {
                            Log.e("RoleServiceImpl/createRole", DbError.UNEXPECTED_ERROR.getMessage(), rex);
                            resultHandler.onFailure(DbError.UNEXPECTED_ERROR);
                        }
                    }

                    @Override
                    public void onFailure(DbError error) {
                        resultHandler.onFailure(error);
                    }
                }
        );
    }

    /**
     * Deletes a role.
     * @param roleName Name of role to be deleted
     * @param authContext details of the current user
     * @param resultHandler listener to store the result of the query
     */
    @Override
    public void deleteRole(final String roleName, final AuthContext authContext, final ResultHandler<Void> resultHandler) {
        // Check if the current user is authorized to perform this operation
        mPrivilegeService.isAllowed(authContext.getUserId(), DbConstants.ROLE_RESOURCE, DbConstants.DELETE_OP,
                new ResultHandler<Boolean>() {
                    @Override
                    public void onSuccess(Boolean result) {
                        if (!result) {
                            resultHandler.onFailure(DbError.UNAUTHORIZED);
                            return;
                        }

                        try {
                            final Role role = mAclDb.getRoleDao().fetchByName(roleName);
                            if (role == null) {
                                resultHandler.onFailure(DbError.INVALID_ROLE);
                                return;
                            }

                            mAclDb.runInTransaction(new Runnable() {
                                @Override
                                public void run() {
                                    mAclDb.getUserRoleDao().deleteByRole(role.getId());
                                    mAclDb.getPrivilegeDao().deleteByRole(role.getId());
                                    mAclDb.getRoleDao().delete(role);

                                    resultHandler.onSuccess(null);
                                }
                            });
                        } catch (RuntimeException rex) {
                            Log.e("RoleServiceImpl/deleteRole", DbError.UNEXPECTED_ERROR.getMessage(), rex);
                            resultHandler.onFailure(DbError.UNEXPECTED_ERROR);
                        }
                    }

                    @Override
                    public void onFailure(DbError error) {
                        resultHandler.onFailure(error);
                    }
                }
        );
    }
}
