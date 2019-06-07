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

import edu.uw.medhas.mhealthsecurityframework.authentication.AuthenticationManager;

/**
 * This class manages the key required for encryption/decryption of sensitive data
 * while storage/retrieval in/from cache/internal/external/database storage.
 *
 * @author Medha Srivastava
 * Created on 5/30/18.
 */

public class KeyManager {

    /**
     * Constant containing name of Android KeyStore.
     */
    private static final String sAndroidKeyStore = "AndroidKeyStore";

    /**
     * Retrieves key for encryption/decryption (AES) using Android KeyStore.
     * If not present, it generates a new key, stores it in the Android
     * KeyStore and returns the newly generated key.
     *
     * @param keyAlias
     * @return SecretKey
     * @throws KeyStoreException Key Store Exception
     * @throws CertificateException Certificate Exception
     * @throws NoSuchAlgorithmException No Such Algorithm Exception
     * @throws IOException IO exception
     * @throws UnrecoverableEntryException Unrecoverable Entry Exception
     * @throws NoSuchProviderException No Such Provider Exception
     * @throws InvalidAlgorithmParameterException Invalid Algorithm Parameter Exception
     */
    public static SecretKey getKey(String keyAlias) throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException, UnrecoverableEntryException, NoSuchProviderException,
            InvalidAlgorithmParameterException {

        KeyStore keyStore = KeyStore.getInstance(sAndroidKeyStore);
        keyStore.load(null);

        final KeyStore.Entry keyEntry = keyStore.getEntry(keyAlias, null);

        SecretKey secretKey = null;

        // If a key does not exist, a new secretKey is generated for AES/CBC/PKCS7Padding (Encryption/Decryption).
        if (keyEntry == null) {
            final KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(keyAlias,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .setUserAuthenticationRequired(false)
                    .setKeySize(128)
                    .build();

            final KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,
                    sAndroidKeyStore);

            keyGenerator.init(keyGenParameterSpec);
            secretKey = keyGenerator.generateKey();
        } else {
            // If a key exists, it is retrieved and set as the secretKey.
            secretKey = ((SecretKeyEntry) keyEntry).getSecretKey();
        }

        return secretKey;
    }

    public static SecretKey getKey(String keyAlias,
                                   AuthenticationManager authenticationManager)
            throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException, UnrecoverableEntryException, NoSuchProviderException,
            InvalidAlgorithmParameterException {

        KeyStore keyStore = KeyStore.getInstance(sAndroidKeyStore);
        keyStore.load(null);

        final KeyStore.Entry keyEntry = keyStore.getEntry(keyAlias, null);

        SecretKey secretKey = null;

        if (keyEntry == null) {
            final KeyGenParameterSpec.Builder keyGenParameterSpecBuilder = new KeyGenParameterSpec.Builder(keyAlias,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .setUserAuthenticationRequired(true)
                    .setKeySize(128);

            if (authenticationManager.getUserAuthenticationValidityDurationSeconds().isPresent()) {
                keyGenParameterSpecBuilder.setUserAuthenticationValidityDurationSeconds(
                        authenticationManager.getUserAuthenticationValidityDurationSeconds().get());
            }


            final KeyGenParameterSpec keyGenParameterSpec = keyGenParameterSpecBuilder.build();

            final KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,
                    sAndroidKeyStore);

            keyGenerator.init(keyGenParameterSpec);
            secretKey = keyGenerator.generateKey();
        } else {
            secretKey = ((SecretKeyEntry) keyEntry).getSecretKey();
        }

        return secretKey;
    }
}
