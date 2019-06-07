package edu.uw.medhas.mhealthsecurityframework.storage.database.model;

/**
 * This class is a Wrapper of Long object and signifies a sensitive Long object.
 *
 * @author Medha Srivastava
 * Created on 1/28/19.
 */

public class SecureLong {
    private final Long value;

    public SecureLong(Long value) {
        this.value = value;
    }

    public Long getValue() {
        return value;
    }
}
