package edu.uw.medhas.mhealthsecurityframework.storage.database.model;

/**
 * This class is a Wrapper of Float object and signifies a sensitive Float object.
 *
 * @author Medha Srivastava
 * Created on 1/28/19.
 */

public class SecureFloat {
    private final Float value;

    public SecureFloat(Float value) {
        this.value = value;
    }

    public Float getValue() {
        return value;
    }
}
