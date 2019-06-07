package edu.uw.medhas.mhealthsecurityframework.acl.dao;

import android.arch.persistence.room.Dao;
import android.arch.persistence.room.Delete;
import android.arch.persistence.room.Insert;
import android.arch.persistence.room.OnConflictStrategy;
import android.arch.persistence.room.Query;
import android.arch.persistence.room.Update;

import edu.uw.medhas.mhealthsecurityframework.acl.model.Role;

/**
 * This interface is the Role Dao used to interact with the database.
 * It contains methods to insert a role,view a role (by Id and name), update a role
 * and delete a role.
 *
 * @author Medha Srivastava
 * Created on 2/18/19.
 */
@Dao
public interface RoleDao {
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    long insert(Role role);

    @Query("SELECT * FROM roles WHERE id = :id")
    Role fetchOne(long id);

    @Query("SELECT * FROM roles WHERE name = :name")
    Role fetchByName(String name);

    @Update
    void update(Role role);

    @Delete
    void delete(Role role);
}
