package edu.uw.medhas.mhealthsecurityframework.storage.internal;

import android.content.Context;
import android.util.Log;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import edu.uw.medhas.mhealthsecurityframework.storage.AbstractSecureFileHandler;
import edu.uw.medhas.mhealthsecurityframework.storage.StorageServiceCallback;
import edu.uw.medhas.mhealthsecurityframework.storage.metadata.StorageReadObject;
import edu.uw.medhas.mhealthsecurityframework.storage.metadata.StorageWriteObject;
import edu.uw.medhas.mhealthsecurityframework.storage.metadata.model.SecureFile;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.EncryptionException;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.NoDefaultConstructorException;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.SerializationException;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResult;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResultCallback;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResultErrorType;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResultSuccess;

/**
 * This class extends the abstract class AbstractSecureFileHandler.
 * It also provides methods that handle read and write operations of sensitive/non-sensitive data
 * from/to an Internal Storage of the mHealth app in an Android phone.
 *
 * For secure storage (write) of sensitive data, a fingerprint/pin authentication is required.
 * If authentication is successful, data is encrypted and stored in internal storage .
 * Similarly, for a secure retrieval(read) of sensitive data, successful authentication leads to
 * decryption of data and retrieval from internal storage.
 *
 * For a non-sensitive data, no encryption/decryption is performed. Simply,
 * an object to byte stream conversion (& vice-versa) is done while storing (or retrieving) it.
 *
 * @author Medha Srivastava
 * Created on 5/18/18
 *
 */

public class SecureInternalFileHandler extends AbstractSecureFileHandler {
    /**
     * Constructs a SecureInternalFileHandler object with given context.
     *
     * @param context the Android context
     */
    public SecureInternalFileHandler(Context context) {
        super(context);
    }

    /**
     * Overridden method of superclass. Returns the alias for encryption key for internal storage.
     *
     * @return String alias
     */
    @Override
    protected String getKeyAlias() {
        return "mhealth-security-framework-internal-storage";
    }

    /**
     * Writes the sensitive/non-sensitive data to internal storage. Performs encryption
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
                try (final FileOutputStream fos = getContext().openFileOutput(
                        storageWriteObject.getSecureFile().getFinalFilename(), Context.MODE_PRIVATE)) {
                    fos.write(result);
                    storageResultCallback.onSuccess(new StorageResult<>(new StorageResultSuccess()));
                } catch (IOException ioex) {
                    Log.e("SecureInternalFileHandler::writeData",
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
     * Reads the sensitive/non-sensitive data from internal storage. Performs decryption
     * in case of sensitive data before retrieving it.
     *
     * @param storageReadObject the object to be read(retrieved)
     * @param storageResultCallback the object to store the result
     */
    public <S> void readData(final StorageReadObject<S> storageReadObject,
                             final StorageResultCallback<S> storageResultCallback) {

        // Determine if the object to be read is json or is encrypted or both.
        if (fileExists(storageReadObject.getSecureFile().getJsonEncryptedFileName())) {
            storageReadObject.getSecureFile().setJsonData(true);
            storageReadObject.getSecureFile().setEncryptedData(true);
        } else if (fileExists(storageReadObject.getSecureFile().getJsonFileName())) {
            storageReadObject.getSecureFile().setJsonData(true);
        } else if (fileExists(storageReadObject.getSecureFile().getEncryptedFileName())) {
            storageReadObject.getSecureFile().setEncryptedData(true);
        }

        // Prepare a byte[] to receive the byte stream of the object to be read.
        final String finalFileName = storageReadObject.getSecureFile().getFinalFilename();
        byte[] objectAsBytes = new byte[(int) getContext().getFileStreamPath(finalFileName).length()];

        try (final FileInputStream fis = getContext().openFileInput(finalFileName)) {
            fis.read(objectAsBytes);
        } catch (FileNotFoundException fnfex) {
            Log.e("SecureInternalFileHandler::readData",
                    "File " + finalFileName + " not found", fnfex);
            storageResultCallback.onFailure(StorageResultErrorType.FILE_NOT_FOUND_ERROR);
            return;
        } catch (IOException ioex) {
            Log.e("SecureInternalFileHandler::readData",
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

        try (final FileOutputStream fos = getContext().openFileOutput(secureFile.getFinalFilename(),
                Context.MODE_PRIVATE)) {
            fos.write(secureObjectAsBytes);
        } catch (IOException ioex) {
            ioex.printStackTrace();
            throw new SerializationException();
        }
    }

    public <S> S readData(Class<S> clazz, String filename) throws FileNotFoundException {
        final SecureFile secureFile = new SecureFile(filename);

        if (fileExists(secureFile.getJsonEncryptedFileName())) {
            secureFile.setJsonData(true);
            secureFile.setEncryptedData(true);
        } else if (fileExists(secureFile.getJsonFileName())) {
            secureFile.setJsonData(true);
        } else if (fileExists(secureFile.getEncryptedFileName())) {
            secureFile.setEncryptedData(true);
        }

        final String finalFileName = secureFile.getFinalFilename();
        byte[] objectAsBytes = new byte[(int) getContext().getFileStreamPath(finalFileName).length()];

        try (final FileInputStream fis = getContext().openFileInput(finalFileName)) {
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

    private boolean fileExists(String filename) {
        return getContext().getFileStreamPath(filename).exists();
    }
}
