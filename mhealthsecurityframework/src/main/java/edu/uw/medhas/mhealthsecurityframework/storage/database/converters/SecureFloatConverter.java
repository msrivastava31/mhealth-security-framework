package edu.uw.medhas.mhealthsecurityframework.storage.database.converters;

import android.arch.persistence.room.TypeConverter;

import java.nio.ByteBuffer;

import edu.uw.medhas.mhealthsecurityframework.storage.database.model.SecureFloat;
import edu.uw.medhas.mhealthsecurityframework.storage.encryption.ByteEncryptor;

/**
 * Created by medhasrivastava on 1/21/19.
 */

public class SecureFloatConverter extends AbstractSecureConverter {
    @TypeConverter
    public byte[] fromSecureFloatToEncryptedBytes(SecureFloat value){
        if (value == null) {
            return null;
        }

        final byte[] objectAsBytes = ByteBuffer.allocate(4).putFloat(value.getValue()).array();
        return ByteEncryptor.encrypt(keyAlias, objectAsBytes);
    }

    @TypeConverter
    public SecureFloat fromEncryptedBytesToSecureFloat(byte[] encryptedValue) {
        if (encryptedValue == null) {
            return null;
        }

        final Float decryptType = ByteBuffer.wrap(ByteEncryptor.decrypt(keyAlias, encryptedValue)).getFloat();
        return new SecureFloat(decryptType);
    }
}
