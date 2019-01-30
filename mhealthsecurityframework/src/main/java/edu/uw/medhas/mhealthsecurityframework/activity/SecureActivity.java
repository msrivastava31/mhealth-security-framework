package edu.uw.medhas.mhealthsecurityframework.activity;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;

import edu.uw.medhas.mhealthsecurityframework.storage.cache.SecureCacheHandler;
import edu.uw.medhas.mhealthsecurityframework.storage.external.SecureExternalFileHandler;
import edu.uw.medhas.mhealthsecurityframework.storage.internal.SecureInternalFileHandler;

/**
 * Created by medhasrivastava on 1/28/19.
 */

public class SecureActivity extends AppCompatActivity {
    private SecureInternalFileHandler mSecureInternalFileHandler = null;
    private SecureExternalFileHandler mSecureExternalFileHandler = null;
    private SecureCacheHandler mSecureCacheHandler = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        mSecureInternalFileHandler = new SecureInternalFileHandler(getBaseContext());
        mSecureExternalFileHandler = new SecureExternalFileHandler(getBaseContext());
        mSecureCacheHandler = new SecureCacheHandler(getBaseContext());
    }

    public SecureInternalFileHandler getSecureInternalFileHandler() {
        return mSecureInternalFileHandler;
    }

    public SecureExternalFileHandler getSecureExternalFileHandler() {
        return mSecureExternalFileHandler;
    }

    public SecureCacheHandler getSecureCacheHandler() {
        return mSecureCacheHandler;
    }
}
