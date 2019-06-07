package edu.uw.medhas.mhealthsecurityframework.storage.cache;

import android.content.Context;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import edu.uw.medhas.mhealthsecurityframework.storage.StorageServiceCallback;
import edu.uw.medhas.mhealthsecurityframework.storage.AbstractSecureFileHandler;
import edu.uw.medhas.mhealthsecurityframework.storage.metadata.StorageReadObject;
import edu.uw.medhas.mhealthsecurityframework.storage.metadata.StorageWriteObject;
import edu.uw.medhas.mhealthsecurityframework.storage.metadata.model.SecureFile;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.EncryptionException;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.SerializationException;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResult;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResultCallback;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResultErrorType;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResultSuccess;

/**
 * This class extends the abstract class AbstractSecureFileHandler.
 * It also provides methods that handle read and write operations of sensitive/non-sensitive data
 * from/to the Cache Storage of the mHealth app in an Android phone.
 *
 * For secure storage (write) of sensitive data, a fingerprint/pin authentication is required.
 * If authentication is successful, data is encrypted and stored in the cache.
 * Similarly, for a secure retrieval(read) of sensitive data, successful authentication leads to
 * decryption of data and retrieval from the cache.
 *
 * For a non-sensitive data, no encryption/decryption is performed. Simply,
 * an object to byte stream conversion (& vice-versa) is done while storing (or retrieving) it.
 *
 * @author Medha Srivastava
 * Created on 5/18/18
 *
 */

public class SecureCacheHandler extends AbstractSecureFileHandler {
    /**
     * Constructs a SecureCacheHandler object with given context.
     *
     * @param context the Android context
     */
    public SecureCacheHandler(Context context) {
        super(context);
    }

    /**
     * Overridden method of superclass. Returns the alias for encryption key for cache storage.
     *
     * @return String alias
     */
    @Override
    protected String getKeyAlias() {
        return "mhealth-security-framework-cache-storage";
    }

    /**
     * Writes the sensitive/non-sensitive data to the cache. Performs encryption
     * in case of sensitive data before storing it.
     *
     * @param storageWriteObject the object to be written(stored)
     * @param storageResultCallback the object to store the result
     */
    public <S> void writeData(final StorageWriteObject<S> storageWriteObject,
                              final StorageResultCallback<StorageResultSuccess> storageResultCallback) {

        // Convert the object into byte stream and encrypt the data if it is sensitive.
        getSecureObjAsBytes(storageWriteObject, new StorageServiceCallback<byte[]>() {

            // Wait for authentication before storing sensitive data.
            @Override
            public void onWaitingForAuthentication() {
                storageResultCallback.onWaitingForAuthentication();
            }

            // On successful authentication, store the encrypted sensitive data.
            @Override
            public void onSuccess(byte[] result) {
                final File finalFileName = getFile(storageWriteObject.getSecureFile().getFinalFilename());

                try (final FileOutputStream fos = new FileOutputStream(finalFileName)) {
                    fos.write(result);
                    storageResultCallback.onSuccess(new StorageResult<>(new StorageResultSuccess()));
                } catch (IOException ioex) {
                    Log.e("SecureCacheHandler::writeData",
                            "WebError serializing object", ioex);
                    storageResultCallback.onFailure(StorageResultErrorType.SERIALIZATION_ERROR);
                }
            }

            // On un-successful authentication, set an error message.
            @Override
            public void onFailure(StorageResultErrorType storageResultErrorType) {
                storageResultCallback.onFailure(storageResultErrorType);
            }
        });
    }

    /**
     * Reads the sensitive/non-sensitive data from the cache. Performs decryption
     * in case of sensitive data before retrieving it.
     *
     * @param storageReadObject the object to be read(retrieved)
     * @param storageResultCallback the object to store the result
     */
    public <S> void readData(final StorageReadObject<S> storageReadObject,
                             final StorageResultCallback<S> storageResultCallback) {

        // Determine if the object to be read is json or is encrypted or both.
        if (getFile(storageReadObject.getSecureFile().getJsonEncryptedFileName()).exists()) {
            storageReadObject.getSecureFile().setJsonData(true);
            storageReadObject.getSecureFile().setEncryptedData(true);
        } else if (getFile(storageReadObject.getSecureFile().getJsonFileName()).exists()) {
            storageReadObject.getSecureFile().setJsonData(true);
        } else if (getFile(storageReadObject.getSecureFile().getEncryptedFileName()).exists()) {
            storageReadObject.getSecureFile().setEncryptedData(true);
        }

        // Prepare a byte[] to receive the byte stream of the object to be read.
        final File finalFileName = getFile(storageReadObject.getSecureFile().getFinalFilename());
        byte[] objectAsBytes = new byte[(int) finalFileName.length()];

        try (final FileInputStream fis = new FileInputStream(finalFileName)) {
            fis.read(objectAsBytes);
        } catch (FileNotFoundException fnfex) {
            Log.e("SecureCacheHandler::readData",
                    "File " + finalFileName.getName() + " not found", fnfex);
            storageResultCallback.onFailure(StorageResultErrorType.FILE_NOT_FOUND_ERROR);
            return;
        } catch (IOException ioex) {
            Log.e("SecureCacheHandler::readData",
                    "WebError deserializing object", ioex);
            storageResultCallback.onFailure(StorageResultErrorType.SERIALIZATION_ERROR);
            return;
        }

        storageReadObject.setObjectBytes(objectAsBytes);

        // Decrypt the data (if it is sensitive) and convert the byte stream to object.
        readObjFromBytes(storageReadObject, new StorageServiceCallback<S>() {

            // Wait for authentication before retrieving sensitive data.
            @Override
            public void onWaitingForAuthentication() {
                storageResultCallback.onWaitingForAuthentication();
            }

            // On successful authentication, retrieve the decrypted sensitive data.
            @Override
            public void onSuccess(S result) {
                storageResultCallback.onSuccess(new StorageResult<>(result));
            }

            // On un-successful authentication, set an error message.
            @Override
            public void onFailure(StorageResultErrorType storageResultErrorType) {
                storageResultCallback.onFailure(storageResultErrorType);
            }
        });
    }




    public <S> void writeData(S secureObj, String filename) {
        final SecureFile secureFile = new SecureFile(filename);

        final byte[] secureObjectAsBytes = getSecureObjAsBytes(secureObj, secureFile);

        final File finalFileName = getFile(secureFile.getFinalFilename());

        try (final FileOutputStream fos = new FileOutputStream(finalFileName)) {
            fos.write(secureObjectAsBytes);
        } catch (IOException ioex) {
            ioex.printStackTrace();
            throw new SerializationException();
        }
    }

    public <S> S readData(Class<S> clazz, String filename) throws FileNotFoundException {
        final SecureFile secureFile = new SecureFile(filename);

        if (getFile(secureFile.getJsonEncryptedFileName()).exists()) {
            secureFile.setJsonData(true);
            secureFile.setEncryptedData(true);
        } else if (getFile(secureFile.getJsonFileName()).exists()) {
            secureFile.setJsonData(true);
        } else if (getFile(secureFile.getEncryptedFileName()).exists()) {
            secureFile.setEncryptedData(true);
        }

        final File finalFileName = getFile(secureFile.getFinalFilename());
        byte[] objectAsBytes = new byte[(int) finalFileName.length()];

        try (final FileInputStream fis = new FileInputStream(finalFileName)) {
            fis.read(objectAsBytes);
        } catch (FileNotFoundException fnfex) {
            fnfex.printStackTrace();
            throw fnfex;
        } catch (IOException ioex) {
            ioex.printStackTrace();
            throw new SerializationException();
        }

        return readObjFromBytes(clazz, objectAsBytes, secureFile);
    }

    private File getFile(String filename) {
        return new File(getContext().getCacheDir(), filename);
    }
}
