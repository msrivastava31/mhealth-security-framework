package edu.uw.medhas.mhealthsecurityframework.storage.database.model;

/**
 * This class is a Wrapper of String object and signifies a sensitive String object.
 *
 * @author Medha Srivastava
 * Created on 1/28/19.
 */

public class SecureString {
    private final String value;

    public SecureString(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
