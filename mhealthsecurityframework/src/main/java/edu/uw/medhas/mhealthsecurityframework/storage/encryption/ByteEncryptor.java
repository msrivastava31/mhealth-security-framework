package edu.uw.medhas.mhealthsecurityframework.storage.encryption;

import android.hardware.fingerprint.FingerprintManager;
import android.security.keystore.UserNotAuthenticatedException;
import android.util.Log;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import edu.uw.medhas.mhealthsecurityframework.authentication.AuthenticationManager;
import edu.uw.medhas.mhealthsecurityframework.storage.StorageServiceCallback;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.DecryptionException;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.EncryptionException;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResultErrorType;

/**
 * This class contains methods to encrypt/decrypt sensitive data prior to
 * storing/retrieving it in/from cache/internal/external/database storage.
 *
 * The encryption algorithm used is AES (128 bit) with CBC using PKCS7 Padding.
 *
 * @author Medha Srivastava
 * Created on 5/18/18
 */

public class ByteEncryptor {
    /**
     * Constant representing encryption transformation.
     */
    private static final String sTransformation = "AES/CBC/PKCS7Padding";

    /**
     * Constant representing Iv length for 128 bit AES encryption.
     */
    private static final int sIvLength = 16;

    /**
     * Encrypts the sensitive data prior to storing it in cache/internal/external/database storage.
     *
     * @param alias key alias used for Android KeyStore
     * @param plainText the plaintext byte stream prior to encryption
     * @param authenticationManager the fingerprint/basic authentication manager object
     * @param callback the callback to receive byte array of the data to be stored
     */
    public static void encrypt(String alias, final byte[] plainText,
                               AuthenticationManager authenticationManager,
                               final StorageServiceCallback<byte[]> callback) {
        try {
            // Get secret key from Android Key store.
            final SecretKey secretKey = KeyManager.getKey(alias, authenticationManager);

            // Create a cipher object for AES/CBC/PKCS7Padding & initialize it for encryption.
            final Cipher cipher = Cipher.getInstance(sTransformation);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            // Create a cryptoObject that is used to perform authentication.
            final FingerprintManager.CryptoObject cryptoObject = new FingerprintManager.CryptoObject(cipher);

            // Perform authentication (fingerprint/basic).
            authenticationManager.performAuthentication(cryptoObject, new EncryptionServiceCallback() {

                // Wait for authentication to complete.
                @Override
                public void onWaitingForAuthentication() {
                    callback.onWaitingForAuthentication();
                }

                // On successful authentication, perform the encryption.
                @Override
                public void onSuccess(Cipher cipher) {
                    try {
                        // Convert plaintext to ciphertext
                        final byte[] cipherText = cipher.doFinal(plainText);

                        // Create array to store iv and cipher text.
                        final byte[] ivAndCipherText = new byte[sIvLength + cipherText.length];

                        System.arraycopy(cipher.getIV(), 0, ivAndCipherText, 0, sIvLength);
                        System.arraycopy(cipherText, 0, ivAndCipherText, sIvLength, cipherText.length);

                        // Return the encrypted data via the callback.
                        callback.onSuccess(ivAndCipherText);
                    } catch (BadPaddingException | IllegalBlockSizeException ex) {
                        Log.e("ByteEncryptor::encrypt",
                                "WebError encrypting data", ex);
                        callback.onFailure(StorageResultErrorType.ENCRYPTION_ERROR);
                    }
                }

                // On un-successful authentication, set an error message.
                @Override
                public void onFailure(StorageResultErrorType storageResultErrorType) {
                    callback.onFailure(storageResultErrorType);
                }
            });
        } catch (UserNotAuthenticatedException unaex) {
            Log.e("ByteEncryptor::encrypt",
                    "User not authenticated recently", unaex);
            callback.onFailure(StorageResultErrorType.REAUTHENTICATION_NEEDED);
        } catch (IOException | CertificateException | UnrecoverableEntryException
                | NoSuchProviderException | KeyStoreException | NoSuchAlgorithmException
                | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException ex) {
            Log.e("ByteEncryptor::encrypt",
                    "WebError encrypting data", ex);
            callback.onFailure(StorageResultErrorType.ENCRYPTION_ERROR);
        }
    }

    /**
     * Decrypts the sensitive data post retrieval from cache/internal/external/database storage.
     *
     * @param alias key alias used for Android KeyStore
     * @param ivAndCipherText the iv and cipher text array post encryption
     * @param authenticationManager the fingerprint/basic authentication manager object
     * @param callback the callback to receive byte array of the retrieved data
     */
    public static void decrypt(String alias, byte[] ivAndCipherText,
                               AuthenticationManager authenticationManager,
                               final StorageServiceCallback<byte[]> callback) {
        try {
            // Create an array to store the iv text.
            final byte[] iv = new byte[sIvLength];
            System.arraycopy(ivAndCipherText, 0, iv, 0, iv.length);
            final IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            // Get secret key from Android Key store.
            final SecretKey secretKey = KeyManager.getKey(alias, authenticationManager);

            // Create an array to sore the cipher text.
            final byte[] cipherText = new byte[ivAndCipherText.length - sIvLength];
            System.arraycopy(ivAndCipherText, sIvLength, cipherText, 0, cipherText.length);

            // Create a cipher object for AES/CBC/PKCS7Padding & initialize it for decryption.
            final Cipher cipher = Cipher.getInstance(sTransformation);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

            // Create a cryptoObject that is used to perform authentication.
            final FingerprintManager.CryptoObject cryptoObject = new FingerprintManager.CryptoObject(cipher);

            // Perform authentication (fingerprint/basic).
            authenticationManager.performAuthentication(cryptoObject, new EncryptionServiceCallback() {

                // Wait for authentication to complete.
                @Override
                public void onWaitingForAuthentication() {
                    callback.onWaitingForAuthentication();
                }

                // On successful authentication, perform the decryption.
                @Override
                public void onSuccess(Cipher cipher) {
                    try {
                        // Convert the cipher text to plain text and return the encrypted data via the callback.
                        callback.onSuccess(cipher.doFinal(cipherText));
                    } catch (BadPaddingException | IllegalBlockSizeException ex) {
                        Log.e("ByteEncryptor::decrypt",
                                "WebError decrypting data", ex);
                        callback.onFailure(StorageResultErrorType.ENCRYPTION_ERROR);
                    }
                }

                // On un-successful authentication, set an error message.
                @Override
                public void onFailure(StorageResultErrorType storageResultErrorType) {
                    callback.onFailure(storageResultErrorType);
                }
            });
        } catch (UserNotAuthenticatedException unaex) {
            Log.e("ByteEncryptor::decrypt",
                    "User not authenticated recently", unaex);
            callback.onFailure(StorageResultErrorType.REAUTHENTICATION_NEEDED);
        } catch (IOException | CertificateException | UnrecoverableEntryException
                | NoSuchProviderException | KeyStoreException | NoSuchAlgorithmException
                | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException ex) {
            Log.e("ByteEncryptor::decrypt",
                    "WebError decrypting data", ex);
            callback.onFailure(StorageResultErrorType.DECRYPTION_ERROR);
        }
    }

    public static byte[] encrypt(String alias, byte[] plainText) {
        try {
            final SecretKey secretKey = KeyManager.getKey(alias);
            final Cipher cipher = Cipher.getInstance(sTransformation);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            final byte[] cipherText = cipher.doFinal(plainText);
            final byte[] ivAndCipherText = new byte[sIvLength + cipherText.length];

            System.arraycopy(cipher.getIV(), 0, ivAndCipherText, 0, sIvLength);
            System.arraycopy(cipherText, 0, ivAndCipherText, sIvLength, cipherText.length);

            return ivAndCipherText;
        } catch (IOException | CertificateException | UnrecoverableEntryException
                | NoSuchProviderException | KeyStoreException | NoSuchAlgorithmException
                | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException
                | BadPaddingException | IllegalBlockSizeException ex) {
            ex.printStackTrace();
            throw new EncryptionException();
        }
    }

    public static byte[] decrypt(String alias, byte[] ivAndCipherText) {
        try {
            final byte[] iv = new byte[sIvLength];
            System.arraycopy(ivAndCipherText, 0, iv, 0, iv.length);
            final IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            final SecretKey secretKey = KeyManager.getKey(alias);

            byte[] cipherText = new byte[ivAndCipherText.length - sIvLength];
            System.arraycopy(ivAndCipherText, sIvLength, cipherText, 0, cipherText.length);

            final Cipher cipher = Cipher.getInstance(sTransformation);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

            return cipher.doFinal(cipherText);
        } catch (IOException | CertificateException | UnrecoverableEntryException
                | NoSuchProviderException | KeyStoreException | NoSuchAlgorithmException
                | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException
                | BadPaddingException | IllegalBlockSizeException ex) {
            ex.printStackTrace();
            throw new DecryptionException();
        }
    }
}
