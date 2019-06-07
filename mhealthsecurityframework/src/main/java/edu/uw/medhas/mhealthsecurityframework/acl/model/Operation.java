package edu.uw.medhas.mhealthsecurityframework.acl.model;

import android.arch.persistence.room.ColumnInfo;
import android.arch.persistence.room.Entity;
import android.arch.persistence.room.Index;
import android.arch.persistence.room.PrimaryKey;
import android.support.annotation.NonNull;

import java.time.Instant;

/**
 * This is the Operation model class that extends AbstractAuditModel class.
 * It contains columns that map to Operation Id and Operation name.
 *
 * @author Medha Srivastava
 * Created on 2/18/19.
 */

@Entity(tableName = "operations",
        indices = {@Index(name = "op_unique_name", value = "name", unique = true)})
public class Operation extends AbstractAuditModel {
    @NonNull
    @PrimaryKey(autoGenerate = true)
    @ColumnInfo(name = "id")
    private long mId;

    @ColumnInfo(name = "name")
    private String mName;

    @NonNull
    public long getId() {
        return mId;
    }

    public void setId(@NonNull long id) {
        mId = id;
    }

    public String getName() {
        return mName;
    }

    public void setName(String name) {
        mName = name;
    }
}
