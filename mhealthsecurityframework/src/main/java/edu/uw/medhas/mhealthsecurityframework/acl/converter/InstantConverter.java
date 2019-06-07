package edu.uw.medhas.mhealthsecurityframework.acl.converter;

import android.arch.persistence.room.TypeConverter;
import java.time.Instant;

/**
 * This class converts the instant to timestamp and vice versa.
 *
 * @author Medha Srivastava
 * Created on 2/18/19.
 */

public class InstantConverter {
    @TypeConverter
    public long fromInstantToTimestamp(Instant value){
        return (value == null) ? 0L : value.getEpochSecond();
    }

    @TypeConverter
    public Instant fromTimestampToInstant(long value) {
        return (value == 0L) ? null : Instant.ofEpochSecond(value);
    }
}
