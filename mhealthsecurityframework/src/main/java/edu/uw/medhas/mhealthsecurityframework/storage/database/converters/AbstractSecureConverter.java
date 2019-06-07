package edu.uw.medhas.mhealthsecurityframework.storage.database.converters;

/**
 * This is an abstract class that returns the key alias used for database storage encryption.
 *
 * @author Medha Srivastava
 * Created on 1/29/19.
 */

public abstract class AbstractSecureConverter {
    /**
     * Returns the key alias used for database storage encryption
     * @return Key alias
     */
    protected String getKeyAlias() {
        return "mhealth-security-framework-database-storage";
    }
}
