package edu.uw.medhas.mhealthsecurityframework.storage;

import java.io.Serializable;

/**
 * This interface extends the Serializable interface.
 * Any object that is an instance of this interface is deemed as
 * sensitive and is encrypted before storing it in cache/internal/external
 * storage.
 *
 * @author Medha Srivastava
 * Created on 5/18/18.
 */
public interface SecureSerializable extends Serializable {
}
