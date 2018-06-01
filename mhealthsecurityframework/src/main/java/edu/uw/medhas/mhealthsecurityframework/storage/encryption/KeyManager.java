package edu.uw.medhas.mhealthsecurityframework.storage.encryption;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * Created by medhas on 5/30/18.
 */

public class KeyManager {
    private static final String sKeyStoreInstance = "AndroidKeyStore";

    public static SecretKey getKey(Context context) throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException, UnrecoverableEntryException, NoSuchProviderException,
            InvalidAlgorithmParameterException {
        KeyStore keyStore = KeyStore.getInstance(sKeyStoreInstance);
        keyStore.load(null);

        final String applicationName = getApplicationName(context);

        final SecretKeyEntry secretKeyEntry = (SecretKeyEntry) keyStore.getEntry(applicationName,
                null);

        if (secretKeyEntry == null) {
            final KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,
                    sKeyStoreInstance);
            final KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(applicationName,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build();

            keyGenerator.init(keyGenParameterSpec);

            return keyGenerator.generateKey();
        }

        return secretKeyEntry.getSecretKey();
    }

    private static String getApplicationName(Context context) {
        ApplicationInfo applicationInfo = context.getApplicationInfo();
        int applicationLabelResId = applicationInfo.labelRes;

        return applicationLabelResId == 0 ? applicationInfo.nonLocalizedLabel.toString()
                                            : context.getString(applicationLabelResId);
    }
}
