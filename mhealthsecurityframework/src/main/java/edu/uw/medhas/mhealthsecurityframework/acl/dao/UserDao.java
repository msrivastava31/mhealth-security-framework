package edu.uw.medhas.mhealthsecurityframework.acl.dao;

import android.arch.persistence.room.Dao;
import android.arch.persistence.room.Delete;
import android.arch.persistence.room.Insert;
import android.arch.persistence.room.OnConflictStrategy;
import android.arch.persistence.room.Query;
import android.arch.persistence.room.Update;

import edu.uw.medhas.mhealthsecurityframework.acl.model.User;

/**
 * This interface is the User Dao used to interact with the database.
 * It contains methods to insert a user,view a user (by Id and name), update a user
 * and delete a user.
 *
 * @author Medha Srivastava
 * Created on 2/18/19.
 */
@Dao
public interface UserDao {
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    void insert(User user);

    @Query("SELECT * FROM users WHERE id = :id")
    User fetchOne(String id);

    @Update
    void update(User user);

    @Delete
    void delete(User user);
}
