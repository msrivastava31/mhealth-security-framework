package edu.uw.medhas.mhealthsecurityframework.acl.service.impl;

import android.util.Log;

import java.time.Instant;

import edu.uw.medhas.mhealthsecurityframework.acl.constants.DbConstants;
import edu.uw.medhas.mhealthsecurityframework.acl.db.AccessControlDb;
import edu.uw.medhas.mhealthsecurityframework.acl.db.DbError;
import edu.uw.medhas.mhealthsecurityframework.acl.db.ResultHandler;
import edu.uw.medhas.mhealthsecurityframework.acl.model.AuthContext;
import edu.uw.medhas.mhealthsecurityframework.acl.model.Operation;
import edu.uw.medhas.mhealthsecurityframework.acl.model.Privilege;
import edu.uw.medhas.mhealthsecurityframework.acl.model.Resource;
import edu.uw.medhas.mhealthsecurityframework.acl.model.Role;
import edu.uw.medhas.mhealthsecurityframework.acl.service.PrivilegeService;

/**
 * This class implements the PrivilegeService interface.
 * It contains methods to create a Privilege, delete a Privilege(and delete corresponding
 * resource and operation) and check for authorization (if a particular role can perform an operation on a resource).
 *
 * @author Medha Srivastava
 * Created by medhas on 2/20/19.
 */

public class PrivilegeServiceImpl implements PrivilegeService {
    private final AccessControlDb mAclDb;

    public PrivilegeServiceImpl(AccessControlDb aclDb) {
        mAclDb = aclDb;
    }

    /**
     * Creates a privilege on a role to perform an operation on a resource.
     * @param roleName Name of the role
     * @param resourceName Name of the resource
     * @param operationName Name of the operation
     * @param authContext details of the current user
     * @param resultHandler listener to store the result of the query
     */
    @Override
    public void createPrivilege(final String roleName, final String resourceName, final String operationName,
                                final AuthContext authContext, final ResultHandler<Privilege> resultHandler) {
        // Check if the current user is authorized to perform this operation
        isAllowed(authContext.getUserId(), DbConstants.PRIVILEGE_RESOURCE, DbConstants.CREATE_OP,
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

                            Resource res = mAclDb.getResourceDao().fetchByName(resourceName);
                            if (res == null) {
                                res = new Resource();
                                res.setName(resourceName);
                                res.setCreated(Instant.now());
                                res.setUpdated(Instant.now());
                                res.setCreatedBy(authContext.getUserId());
                                res.setUpdatedBy(authContext.getUserId());

                                final long resId = mAclDb.getResourceDao().insert(res);
                                res.setId(resId);
                            }

                            Operation op = mAclDb.getOperationDao().fetchByName(operationName);
                            if (op == null) {
                                op = new Operation();
                                op.setName(operationName);
                                op.setCreated(Instant.now());
                                op.setUpdated(Instant.now());
                                op.setCreatedBy(authContext.getUserId());
                                op.setUpdatedBy(authContext.getUserId());

                                final long opId = mAclDb.getOperationDao().insert(op);
                                op.setId(opId);
                            }

                            final Privilege priv = new Privilege();
                            priv.setRoleId(role.getId());
                            priv.setResourceId(res.getId());
                            priv.setOperationId(op.getId());
                            priv.setCreated(Instant.now());
                            priv.setUpdated(Instant.now());
                            priv.setCreatedBy(authContext.getUserId());
                            priv.setUpdatedBy(authContext.getUserId());

                            mAclDb.getPrivilegeDao().insert(priv);

                            resultHandler.onSuccess(priv);
                        } catch (RuntimeException rex) {
                            Log.e("PrivilegeServiceImpl/createPrivilege", DbError.UNEXPECTED_ERROR.getMessage(), rex);
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
     * Deletes a privilege on a role to perform an operation on a resource.
     * @param roleName Name of the role
     * @param resourceName Name of the resource
     * @param operationName Name of the operation
     * @param authContext details of the current user
     * @param resultHandler listener to store the result of the query
     */
    @Override
    public void deletePrivilege(final String roleName, final String resourceName, final String operationName,
                                final AuthContext authContext, final ResultHandler<Void> resultHandler) {
        // Check if the current user is authorized to perform this operation
        isAllowed(authContext.getUserId(), DbConstants.PRIVILEGE_RESOURCE, DbConstants.DELETE_OP,
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

                            final Resource res = mAclDb.getResourceDao().fetchByName(resourceName);
                            if (res == null) {
                                resultHandler.onFailure(DbError.INVALID_RESOURCE);
                                return;
                            }

                            final Operation op = mAclDb.getOperationDao().fetchByName(operationName);
                            if (op == null) {
                                resultHandler.onFailure(DbError.INVALID_OPERATION);
                                return;
                            }

                            final Privilege priv = new Privilege();
                            priv.setRoleId(role.getId());
                            priv.setResourceId(res.getId());
                            priv.setOperationId(op.getId());

                            mAclDb.getPrivilegeDao().delete(priv);

                            resultHandler.onSuccess(null);
                        } catch (RuntimeException rex) {
                            Log.e("PrivilegeServiceImpl/deletePrivilege", DbError.UNEXPECTED_ERROR.getMessage(), rex);
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
     * Checks for authorization if a particular user can perform an operation on a resource.
     * @param userId User Id
     * @param resourceName Name of the resource
     * @param operationName Name of the operation
     * @param resultHandler listener to store the result of the query
     */
    @Override
    public void isAllowed(final String userId, final String resourceName, final String operationName,
                          final ResultHandler<Boolean> resultHandler) {
        try {
            resultHandler.onSuccess((mAclDb.getPrivilegeDao().checkPermission(userId, resourceName, operationName) > 0));
        } catch (RuntimeException rex) {
            Log.e("PrivilegeServiceImpl/isAllowed", DbError.UNEXPECTED_ERROR.getMessage(), rex);
            resultHandler.onFailure(DbError.UNEXPECTED_ERROR);
        }
    }

    /**
     * Delete the resource when a privilege is deleted
     * @param resourceName Name of the resource to be deleted
     * @param authContext details of the current user
     * @param resultHandler listener to store the result of the query
     */
    @Override
    public void deleteResource(final String resourceName, final AuthContext authContext,
                               final ResultHandler<Void> resultHandler) {
        // Check if the current user is authorized to perform this operation
        isAllowed(authContext.getUserId(), DbConstants.PRIVILEGE_RESOURCE, DbConstants.DELETE_OP,
                new ResultHandler<Boolean>() {
                    @Override
                    public void onSuccess(Boolean result) {
                        if (!result) {
                            resultHandler.onFailure(DbError.UNAUTHORIZED);
                            return;
                        }

                        try {
                            final Resource res = mAclDb.getResourceDao().fetchByName(resourceName);
                            if (res == null) {
                                resultHandler.onFailure(DbError.INVALID_RESOURCE);
                                return;
                            }

                            mAclDb.runInTransaction(new Runnable() {
                                @Override
                                public void run() {
                                    mAclDb.getPrivilegeDao().deleteByResource(res.getId());
                                    mAclDb.getResourceDao().delete(res);

                                    resultHandler.onSuccess(null);
                                }
                            });
                        } catch (RuntimeException rex) {
                            Log.e("PrivilegeServiceImpl/deleteResource", DbError.UNEXPECTED_ERROR.getMessage(), rex);
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
     * Delete the operation when a privilege is deleted
     * @param operationName Name of the operation to be deleted
     * @param authContext details of the current user
     * @param resultHandler listener to store the result of the query
     */
    @Override
    public void deleteOperation(final String operationName, final AuthContext authContext,
                                final ResultHandler<Void> resultHandler) {
        // Check if the current user is authorized to perform this operation
        isAllowed(authContext.getUserId(), DbConstants.PRIVILEGE_RESOURCE, DbConstants.DELETE_OP,
                new ResultHandler<Boolean>() {
                    @Override
                    public void onSuccess(Boolean result) {
                        if (!result) {
                            resultHandler.onFailure(DbError.UNAUTHORIZED);
                            return;
                        }

                        try {
                            final Operation op = mAclDb.getOperationDao().fetchByName(operationName);
                            if (op == null) {
                                resultHandler.onFailure(DbError.INVALID_OPERATION);
                                return;
                            }

                            mAclDb.runInTransaction(new Runnable() {
                                @Override
                                public void run() {
                                    mAclDb.getPrivilegeDao().deleteByOperation(op.getId());
                                    mAclDb.getOperationDao().delete(op);

                                    resultHandler.onSuccess(null);
                                }
                            });
                        } catch (RuntimeException rex) {
                            Log.e("PrivilegeServiceImpl/deleteOperation", DbError.UNEXPECTED_ERROR.getMessage(), rex);
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
