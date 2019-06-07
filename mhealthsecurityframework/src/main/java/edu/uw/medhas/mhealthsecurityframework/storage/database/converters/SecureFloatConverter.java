package edu.uw.medhas.mhealthsecurityframework.storage.database.converters;

import android.arch.persistence.room.TypeConverter;
import android.util.Log;

import java.nio.ByteBuffer;
import java.util.concurrent.CountDownLatch;

import edu.uw.medhas.mhealthsecurityframework.authentication.BasicAuthenticationManager;
import edu.uw.medhas.mhealthsecurityframework.storage.StorageServiceCallback;
import edu.uw.medhas.mhealthsecurityframework.storage.database.model.ConverterEncryptionResult;
import edu.uw.medhas.mhealthsecurityframework.storage.database.model.SecureFloat;
import edu.uw.medhas.mhealthsecurityframework.storage.encryption.ByteEncryptor;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.DecryptionException;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.EncryptionException;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.ReauthenticationException;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResultErrorType;

/**
 * This class extends the AbstractSecureConverter class.
 * It contains methods that convert a SecureFloat object to encrypted bytes and vice versa
 * using Android Room framework's TypeConverter annotation.
 *
 * @author Medha Srivastava
 * Created on 1/21/19.
 */

public class SecureFloatConverter extends AbstractSecureConverter {
    /**
     * Encrypts the sensitive float object prior to storing it in database storage.
     * @param value sensitive float object
     * @return byte array of the encrypted object
     */
    @TypeConverter
    public byte[] fromSecureFloatToEncryptedBytes(SecureFloat value){
        if (value == null) {
            return null;
        }

        // Convert the object into byte stream
        final byte[] objectAsBytes = ByteBuffer.allocate(4).putFloat(value.getValue()).array();

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
            Log.e("SecureFloatConverter::fromSecureFloatToEncryptedBytes",
                    "Interrupted while encrypting data", e);
            throw new EncryptionException();
        }
    }

    /**
     * Retrieves the sensitive float object after decrypting it.
     * @param encryptedValue byte array of the encrypted object
     * @return SecureFloat object
     */
    @TypeConverter
    public SecureFloat fromEncryptedBytesToSecureFloat(byte[] encryptedValue) {
        if (encryptedValue == null) {
            return null;
        }

        final ConverterEncryptionResult converterResult = new ConverterEncryptionResult();
        // Initialize a countdown latch to wait for 1 process
        final CountDownLatch latch = new CountDownLatch(1);

        // Decrypt the encrypted object
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

            return new SecureFloat(ByteBuffer.wrap(converterResult.getResult()).getFloat());
        } catch (InterruptedException e) {
            Log.e("SecureFloatConverter::fromEncryptedBytesToSecureFloat",
                    "Interrupted while decrypting data", e);
            throw new DecryptionException();
        }
    }
}
