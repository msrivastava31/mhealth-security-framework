package edu.uw.medhas.mhealthsecurityframework.storage;

import android.content.Context;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.lang.reflect.Constructor;

import edu.uw.medhas.mhealthsecurityframework.storage.encryption.ByteEncryptor;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.NoDefaultConstructorException;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.SerializationException;

/**
 * Created by medhas on 5/18/18.
 */

public abstract class AbstractSecureFileHandler {
    private final Context mContext;
    private final ObjectMapper mObjectMapper;

    public AbstractSecureFileHandler(Context context) {
        mContext = context;
        mObjectMapper = new ObjectMapper();
    }

    protected Context getContext() {
        return mContext;
    }

    protected ObjectMapper getObjectMapper() {
        return mObjectMapper;
    }

    protected abstract String getKeyAlias();

    protected <S> byte[] getSecureObjAsBytes(S secureObj, SecureFile secureFile) {
        final byte[] objectAsBytes;

        if (secureObj instanceof Serializable) {
            try (final ByteArrayOutputStream baos = new ByteArrayOutputStream();
                 final ObjectOutputStream oos = new ObjectOutputStream(baos);) {
                oos.writeObject(secureObj);
                oos.flush();
                objectAsBytes = baos.toByteArray();
            } catch (IOException ioex) {
                ioex.printStackTrace();
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
                ioex.printStackTrace();
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
                ioex.printStackTrace();
                throw new SerializationException();
            }
        } else {
            try (final ByteArrayInputStream bais = new ByteArrayInputStream(unsecureObjectAsBytes);
                 final ObjectInputStream ois = new ObjectInputStream(bais);) {
                return (S) ois.readObject();
            } catch (IOException | ClassNotFoundException ex) {
                ex.printStackTrace();
                throw new SerializationException();
            }
        }
    }
}
