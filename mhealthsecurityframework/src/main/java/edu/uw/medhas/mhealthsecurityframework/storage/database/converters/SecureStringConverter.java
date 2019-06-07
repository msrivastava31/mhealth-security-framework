package edu.uw.medhas.mhealthsecurityframework.storage.database.converters;

import android.arch.persistence.room.TypeConverter;
import android.util.Log;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;

import edu.uw.medhas.mhealthsecurityframework.authentication.BasicAuthenticationManager;
import edu.uw.medhas.mhealthsecurityframework.storage.StorageServiceCallback;
import edu.uw.medhas.mhealthsecurityframework.storage.database.model.ConverterEncryptionResult;
import edu.uw.medhas.mhealthsecurityframework.storage.database.model.SecureString;
import edu.uw.medhas.mhealthsecurityframework.storage.encryption.ByteEncryptor;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.DecryptionException;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.EncryptionException;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.ReauthenticationException;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResultErrorType;

/**
 * This class extends the AbstractSecureConverter class.
 * It contains methods that convert a SecureString object to encrypted bytes and vice versa
 * using Android Room framework's TypeConverter annotation.
 *
 * @author Medha Srivastava
 * Created by medhasrivastava on 1/21/19.
 */

public class SecureStringConverter extends AbstractSecureConverter {
    /**
     * Encrypts the sensitive String object prior to storing it in database storage.
     * @param value the Secure String object
     * @return byte array of the encrypted object
     */
    @TypeConverter
    public byte[] fromSecureStringToEncryptedBytes(SecureString value){
        if (value == null) {
            return null;
        }

        // Convert the object into byte stream
        final byte[] objectAsBytes = value.getValue().getBytes(StandardCharsets.UTF_8);

        final ConverterEncryptionResult converterResult = new ConverterEncryptionResult();
        // Initialize a countdown latch to wait for 1 process
        final CountDownLatch latch = new CountDownLatch(1);

        // Encrypt the object
        ByteEncryptor.encrypt(getKeyAlias(), objectAsBytes, new BasicAuthenticationManager(),
                new StorageServiceCallback<byte[]>() {

                    // On successful authentication, set the result and set the count down
                    @Override
                    public void onSuccess(byte[] result) {
                        converterResult.setResult(result);
                        latch.countDown();
                    }

                    // On unsuccessful authentication, set the error and set the count down
                    @Override
                    public void onFailure(StorageResultErrorType storageResultErrorType) {
                        converterResult.setErrorType(storageResultErrorType);
                        latch.countDown();
                    }

                    // Wait for authentication to complete
                    @Override
                    public void onWaitingForAuthentication() {

                    }
                });

        try {
            // Block the thread until count reaches zero
            latch.await();
            // Perform re-authentication if authentication error is present
            if (converterResult.getErrorType().isPresent()) {
                if (StorageResultErrorType.REAUTHENTICATION_NEEDED.equals(converterResult.getErrorType().get())) {
                    throw new ReauthenticationException();
                } else {
                    throw new EncryptionException();
                }
            }
            return converterResult.getResult();
        } catch (InterruptedException e) {
            Log.e("SecureStringConverter::fromSecureStringToEncryptedBytes",
                    "Interrupted while encrypting data", e);
            throw new EncryptionException();
        }
    }

    /**
     * Retrieves the sensitive String object after decrypting it.
     * @param encryptedValue byte array of the encrypted object
     * @return the SecureString object
     */
    @TypeConverter
    public SecureString fromEncryptedBytesToSecureString(byte[] encryptedValue) {
        if (encryptedValue == null) {
            return null;
        }

        final ConverterEncryptionResult converterResult = new ConverterEncryptionResult();
        // Initialize a countdown latch to wait for 1 process
        final CountDownLatch latch = new CountDownLatch(1);

        // Decrypt the object
        ByteEncryptor.decrypt(getKeyAlias(), encryptedValue, new BasicAuthenticationManager(),
                new StorageServiceCallback<byte[]>() {

                    // On successful authentication, set the result and set the count down
                    @Override
                    public void onSuccess(byte[] result) {
                        converterResult.setResult(result);
                        latch.countDown();
                    }

                    // On unsuccessful authentication, set the error and set the count down
                    @Override
                    public void onFailure(StorageResultErrorType storageResultErrorType) {
                        converterResult.setErrorType(storageResultErrorType);
                        latch.countDown();
                    }

                    // Wait for authentication to complete
                    @Override
                    public void onWaitingForAuthentication() {
                    }
                });

        try {
            // Block the thread until count reaches zero
            latch.await();
            // Perform re-authentication if authentication error is present
            if (converterResult.getErrorType().isPresent()) {
                if (StorageResultErrorType.REAUTHENTICATION_NEEDED.equals(converterResult.getErrorType().get())) {
                    throw new ReauthenticationException();
                } else {
                    throw new DecryptionException();
                }
            }

            return new SecureString(new String(converterResult.getResult(), StandardCharsets.UTF_8));
        } catch (InterruptedException e) {
            Log.e("SecureStringConverter::fromEncryptedBytesToSecureString",
                    "Interrupted while decrypting data", e);
            throw new DecryptionException();
        }
    }
}
