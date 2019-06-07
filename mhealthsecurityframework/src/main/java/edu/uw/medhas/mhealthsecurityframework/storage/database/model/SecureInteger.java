package edu.uw.medhas.mhealthsecurityframework.storage.database.model;

/**
 * This class is a Wrapper of Integer object and signifies a sensitive Integer object.
 *
 * @author Medha Srivastava
 * Created on 1/28/19.
 */

public class SecureInteger {
    private final Integer value;

    public SecureInteger(Integer value) {
        this.value = value;
    }

    public Integer getValue() {
        return value;
    }
}
