package edu.uw.medhas.mhealthsecurityframework.storage;

import android.content.Context;
import android.util.Log;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.lang.reflect.Constructor;

import edu.uw.medhas.mhealthsecurityframework.authentication.AuthenticationManagerFactory;
import edu.uw.medhas.mhealthsecurityframework.storage.encryption.ByteEncryptor;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.NoDefaultConstructorException;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.SerializationException;
import edu.uw.medhas.mhealthsecurityframework.storage.metadata.StorageReadObject;
import edu.uw.medhas.mhealthsecurityframework.storage.metadata.StorageWriteObject;
import edu.uw.medhas.mhealthsecurityframework.storage.metadata.model.SecureData;
import edu.uw.medhas.mhealthsecurityframework.storage.metadata.model.SecureFile;
import edu.uw.medhas.mhealthsecurityframework.storage.metadata.model.SecureSerializable;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResultErrorType;

/**
 * This class is an abstract class containing methods that convert an object
 * into a byte stream and vice-versa.
 *
 * For storing sensitive and non-sensitive data, the object is converted into
 * a byte stream and then if it is a sensitive data, the byte stream is encrypted
 * prior to storing it in cache/internal/external storage.
 *
 * For retrieving sensitive and non-sensitive data, the byte stream is first checked
 * if it is encrypted (sensitive data). If yes, then it is decrypted first before converting
 * the byte stream to object.
 *
 * @author Medha Srivastava
 * Created on 5/18/18
 */

public abstract class AbstractSecureFileHandler {
    /**
     * The Android Context.
     */
    private final Context mContext;

    /**
     * The Jackson JSON ObjectMapper.
     */
    private final ObjectMapper mObjectMapper;

    /**
     * Constructs a AbstractSecureFileHandler object with a given context
     * and a new instance of ObjectMapper.
     *
     * @param context the Android context
     */
    public AbstractSecureFileHandler(Context context) {
        mContext = context;
        mObjectMapper = new ObjectMapper();
    }

    /**
     * Returns the Android context.
     *
     * @return context
     */
    protected Context getContext() {
        return mContext;
    }

    /**
     * Returns the Jackson JSON ObjectMapper.
     *
     * @return ObjectMapper
     */
    protected ObjectMapper getObjectMapper() {
        return mObjectMapper;
    }

    /**
     * Abstract method that returns the alias for encryption key
     * for cache/internal/external storage.
     *
     * @return String alias
     */
    protected abstract String getKeyAlias();

    /**
     * Converts the object into byte stream and encrypts the data if it is sensitive.
     *
     * @param storageWriteObject the storage object with details of data to be written(stored)
     * @param callback the callback to receive byte array of the data to be stored
     */
    protected <S> void getSecureObjAsBytes(StorageWriteObject<S> storageWriteObject,
                                         StorageServiceCallback<byte[]> callback) {
        // byte array of the result.
        final byte[] objectAsBytes;

        // Check if the object to be written is an instance of the Serializable interface.
        // If yes, convert the object to byte stream.
        if (storageWriteObject.getObject() instanceof Serializable) {
            try (final ByteArrayOutputStream baos = new ByteArrayOutputStream();
                 final ObjectOutputStream oos = new ObjectOutputStream(baos);) {
                oos.writeObject(storageWriteObject.getObject());
                oos.flush();
                objectAsBytes = baos.toByteArray();
            } catch (IOException ioex) {
                Log.e("AbstractSecureFileHandler::getSecureObjAsBytes",
                        "WebError serializing object", ioex);
                callback.onFailure(StorageResultErrorType.SERIALIZATION_ERROR);
                return;
            }
        } else {
            // check if an empty constructor is available
            boolean emptyConstructorAvailable = false;
            for (Constructor<?> constructor : storageWriteObject.getObject().getClass().getConstructors()) {
                if (constructor.getParameterCount() == 0) {
                    emptyConstructorAvailable = true;
                }
            }

            // If an empty constructor is not available, thrown an error and exit.
            if (!emptyConstructorAvailable) {
                callback.onFailure(StorageResultErrorType.DEFAULT_CONSTRUCTOR_ERROR);
                return;
            }

            try {
                // If an empty constructor is available, convert the object to byte stream
                // using the Jackson JSON ObjectMapper.
                objectAsBytes = getObjectMapper().writeValueAsBytes(storageWriteObject.getObject());
                storageWriteObject.getSecureFile().setJsonData(true);
            } catch (IOException ioex) {
                Log.e("AbstractSecureFileHandler::getSecureObjAsBytes",
                        "WebError serializing object", ioex);
                callback.onFailure(StorageResultErrorType.SERIALIZATION_ERROR);
                return;
            }
        }

        // Check if the object to be stored is sensitive. If yes, encrypt it.
        if (storageWriteObject.getObject() instanceof SecureSerializable
                || storageWriteObject.getObject().getClass().isAnnotationPresent(SecureData.class)) {
            storageWriteObject.getSecureFile().setEncryptedData(true);
            ByteEncryptor.encrypt(getKeyAlias(), objectAsBytes,
                    AuthenticationManagerFactory.getAuthenticationManager(), callback);
            return;
        }

        // If not sensitive, return the object as byte stream.
        callback.onSuccess(objectAsBytes);
    }

    /**
     * Converts the byte stream into object and decrypts the data if it is sensitive.
     *
     * @param storageReadObject the storage object with details of data to be read(retrieved)
     * @param callback the callback to receive byte array of the retrieved data
     */
    protected <S> void readObjFromBytes(final StorageReadObject<S> storageReadObject,
                                        final StorageServiceCallback<S> callback) {

        //If object to be read is encrypted(sensitive), then decrypt it.
        if (storageReadObject.getSecureFile().isEncryptedData()) {
            ByteEncryptor.decrypt(getKeyAlias(), storageReadObject.getObjectBytes(),
                    AuthenticationManagerFactory.getAuthenticationManager(),
                    new StorageServiceCallback<byte[]>() {

                        // Wait for authentication before retrieving sensitive data.
                        @Override
                        public void onWaitingForAuthentication() {
                            callback.onWaitingForAuthentication();
                        }

                        // On successful authentication, store the decrypted data.
                        @Override
                        public void onSuccess(byte[] result) {
                            // Check if the decrypted data is json.
                            if (storageReadObject.getSecureFile().isJsonData()) {
                                try {
                                    // If data is json, convert the byte stream to object
                                    // using the Jackson JSON ObjectMapper.
                                    callback.onSuccess(getObjectMapper().readValue(result,
                                            storageReadObject.getClazz()));
                                } catch (IOException ioex) {
                                    Log.e("AbstractSecureFileHandler::readObjFromBytes",
                                            "WebError deserializing object", ioex);
                                    callback.onFailure(StorageResultErrorType.SERIALIZATION_ERROR);
                                }
                            } else {
                                // If data is not json, convert the byte stream to object.
                                try (final ByteArrayInputStream bais = new ByteArrayInputStream(result);
                                     final ObjectInputStream ois = new ObjectInputStream(bais);) {
                                    callback.onSuccess((S) ois.readObject());
                                } catch (IOException | ClassNotFoundException ex) {
                                    Log.e("AbstractSecureFileHandler::readObjFromBytes",
                                            "WebError deserializing object", ex);
                                    callback.onFailure(StorageResultErrorType.SERIALIZATION_ERROR);
                                }
                            }
                        }

                        // On un-successful authentication, set an error message.
                        @Override
                        public void onFailure(StorageResultErrorType storageResultErrorType) {
                            callback.onFailure(storageResultErrorType);
                        }
                    });
        }
        //If object to be read is not encrypted(sensitive).
        else {
            // Check if the data is json.
            if (storageReadObject.getSecureFile().isJsonData()) {
                try {
                    // If data is json, convert the byte stream to object
                    // using the Jackson JSON ObjectMapper.
                    callback.onSuccess(getObjectMapper().readValue(storageReadObject.getObjectBytes(),
                            storageReadObject.getClazz()));
                } catch (IOException ioex) {
                    Log.e("AbstractSecureFileHandler::readObjFromBytes",
                            "WebError deserializing object", ioex);
                    callback.onFailure(StorageResultErrorType.SERIALIZATION_ERROR);
                }
            } else {
                // If data is not json, convert the byte stream to object.
                try (final ByteArrayInputStream bais = new ByteArrayInputStream(
                        storageReadObject.getObjectBytes());
                     final ObjectInputStream ois = new ObjectInputStream(bais);) {
                    callback.onSuccess((S) ois.readObject());
                } catch (IOException | ClassNotFoundException ex) {
                    Log.e("AbstractSecureFileHandler::readObjFromBytes",
                            "WebError deserializing object", ex);
                    callback.onFailure(StorageResultErrorType.SERIALIZATION_ERROR);
                }
            }
        }
    }

    protected <S> byte[] getSecureObjAsBytes(S secureObj, SecureFile secureFile) {
        final byte[] objectAsBytes;

        if (secureObj instanceof Serializable) {
            try (final ByteArrayOutputStream baos = new ByteArrayOutputStream();
                 final ObjectOutputStream oos = new ObjectOutputStream(baos);) {
                oos.writeObject(secureObj);
                oos.flush();
                objectAsBytes = baos.toByteArray();
            } catch (IOException ioex) {
                Log.e("AbstractSecureFileHandler::getSecureObjAsBytes",
                        "WebError serializing object", ioex);
                throw new SerializationException();
            }
        } else {
            boolean emptyConstructorAvailable = false;
            for (Constructor<?> constructor : secureObj.getClass().getConstructors()) {
                if (constructor.getParameterCount() == 0) {
                    emptyConstructorAvailable = true;
                }
            }

            if (!emptyConstructorAvailable) {
                throw new NoDefaultConstructorException();
            }

            try {
                objectAsBytes = mObjectMapper.writeValueAsBytes(secureObj);
                secureFile.setJsonData(true);
            } catch (IOException ioex) {
                Log.e("AbstractSecureFileHandler::getSecureObjAsBytes",
                        "WebError serializing object", ioex);
                throw new SerializationException();
            }
        }

        if (secureObj instanceof SecureSerializable
                || secureObj.getClass().isAnnotationPresent(SecureData.class)) {
            secureFile.setEncryptedData(true);
            return ByteEncryptor.encrypt(getKeyAlias(), objectAsBytes);
        }

        return objectAsBytes;
    }

    protected <S> S readObjFromBytes(Class<S> clazz, byte[] secureObjectAsBytes, SecureFile secureFile) {
        final byte[] unsecureObjectAsBytes = secureFile.isEncryptedData()
                                                ? ByteEncryptor.decrypt(getKeyAlias(), secureObjectAsBytes)
                                                : secureObjectAsBytes;

        if (secureFile.isJsonData()) {
            try {
                return mObjectMapper.readValue(unsecureObjectAsBytes, clazz);
            } catch (IOException ioex) {
                Log.e("AbstractSecureFileHandler::getSecureObjAsBytes",
                        "WebError deserializing object", ioex);
                throw new SerializationException();
            }
        } else {
            try (final ByteArrayInputStream bais = new ByteArrayInputStream(unsecureObjectAsBytes);
                 final ObjectInputStream ois = new ObjectInputStream(bais);) {
                return (S) ois.readObject();
            } catch (IOException | ClassNotFoundException ex) {
                Log.e("AbstractSecureFileHandler::getSecureObjAsBytes",
                        "WebError deserializing object", ex);
                throw new SerializationException();
            }
        }
    }
}
