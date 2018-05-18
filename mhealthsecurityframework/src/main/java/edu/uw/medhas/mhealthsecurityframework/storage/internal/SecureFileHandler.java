package edu.uw.medhas.mhealthsecurityframework.storage.internal;

import android.content.Context;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;

import com.fasterxml.jackson.databind.ObjectMapper;

import edu.uw.medhas.mhealthsecurityframework.storage.SecureData;
import edu.uw.medhas.mhealthsecurityframework.storage.SecureSerializable;
import edu.uw.medhas.mhealthsecurityframework.storage.encryption.ByteEncryptor;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.SerializationException;

/**
 * Created by medhas on 5/18/18.
 */

public class SecureFileHandler {
    private final Context mContext;
    private final ObjectMapper mObjectMapper;

    public SecureFileHandler(Context context) {
        mContext = context;
        mObjectMapper = new ObjectMapper();
    }

    public <S> void writeData(S secureObj, String filename) {
        final byte[] objectAsBytes;

        if (secureObj instanceof Serializable) {
            try (final ByteArrayOutputStream baos = new ByteArrayOutputStream();
                 final ObjectOutputStream oos = new ObjectOutputStream(baos);) {
                oos.writeObject(secureObj);
                oos.flush();
                objectAsBytes = baos.toByteArray();
            } catch (IOException ioex) {
                throw new SerializationException();
            }
        } else {
            try {
                objectAsBytes = mObjectMapper.writeValueAsBytes(secureObj);
            } catch (IOException ioex) {
                throw new SerializationException();
            }
        }

        final byte[] secureObjectAsBytes;

        if (secureObj instanceof SecureSerializable
                || secureObj.getClass().isAnnotationPresent(SecureData.class)) {
            secureObjectAsBytes = ByteEncryptor.encrypt(objectAsBytes);
        } else {
            secureObjectAsBytes = objectAsBytes;
        }

        try (final FileOutputStream fos = mContext.openFileOutput(filename, Context.MODE_PRIVATE)) {
            fos.write(secureObjectAsBytes);
        } catch (IOException ioex) {
            throw new SerializationException();
        }
    }

    public <S> S readData(Class<S> clazz, String filename) {
        return null;
    }
}
