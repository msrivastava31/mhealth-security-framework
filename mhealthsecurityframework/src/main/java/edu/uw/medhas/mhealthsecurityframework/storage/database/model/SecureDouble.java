package edu.uw.medhas.mhealthsecurityframework.storage.database.model;

/**
 * This class is a Wrapper of Double object and signifies a sensitive Double object.
 *
 * @author Medha Srivastava
 * Created on 1/28/19.
 */

public class SecureDouble {
    private final Double value;

    public SecureDouble(Double value) {
        this.value = value;
    }

    public Double getValue() {
        return value;
    }
}
