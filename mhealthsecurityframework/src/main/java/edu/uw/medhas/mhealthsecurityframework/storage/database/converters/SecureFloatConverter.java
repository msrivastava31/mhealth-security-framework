package edu.uw.medhas.mhealthsecurityframework.storage.database.converters;

import android.arch.persistence.room.TypeConverter;

import java.nio.ByteBuffer;

import edu.uw.medhas.mhealthsecurityframework.storage.AbstractSecureFileHandler;
import edu.uw.medhas.mhealthsecurityframework.storage.database.model.SecureFloat;
import edu.uw.medhas.mhealthsecurityframework.storage.encryption.ByteEncryptor;

/**
 * Created by medhasrivastava on 1/21/19.
 */

public class SecureFloatConverter {
    @TypeConverter
    public byte[] fromSecureFloatToEncryptedBytes(SecureFloat value){
        if (value == null) {
            return null;
        }

        final byte[] objectAsBytes = ByteBuffer.allocate(4).putFloat(value.getValue()).array();
        return ByteEncryptor.encrypt(objectAsBytes, AbstractSecureFileHandler.key);
    }

    @TypeConverter
    public SecureFloat fromEncryptedBytesToSecureFloat(byte[] encryptedValue) {
        if (encryptedValue == null) {
            return null;
        }

        final Float decryptType = ByteBuffer.wrap(ByteEncryptor.decrypt(encryptedValue,
                AbstractSecureFileHandler.key)).getFloat();
        return new SecureFloat(decryptType);
    }
}
