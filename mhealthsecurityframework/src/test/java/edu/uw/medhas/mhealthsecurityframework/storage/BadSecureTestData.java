package edu.uw.medhas.mhealthsecurityframework.storage;

import edu.uw.medhas.mhealthsecurityframework.storage.metadata.model.SecureData;

/**
 * Created by medhasrivastava on 11/2/18.
 */

@SecureData
public class BadSecureTestData extends TestData {
    public BadSecureTestData(String data) {
        setData(data);
    }
}
