package edu.uw.medhas.mhealthsecurityframework.acl.model;

import android.arch.persistence.room.ColumnInfo;
import android.arch.persistence.room.Entity;
import android.arch.persistence.room.PrimaryKey;
import android.support.annotation.NonNull;

import java.time.Instant;

/**
 * This is the User model class that extends AbstractAuditModel class.
 * It contains columns that map to user Id and User name.
 *
 * @author Medha Srivastava
 * Created on 2/18/19.
 */

@Entity(tableName = "users")
public class User extends AbstractAuditModel {
    @NonNull
    @PrimaryKey
    @ColumnInfo(name = "id")
    private String mId;

    @ColumnInfo(name = "name")
    private String mName;

    @NonNull
    public String getId() {
        return mId;
    }

    public void setId(@NonNull String id) {
        mId = id;
    }

    public String getName() {
        return mName;
    }

    public void setName(String name) {
        mName = name;
    }
}
