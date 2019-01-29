package edu.uw.medhas.mhealthsecurityframework.storage.database.converters;

import android.arch.persistence.room.TypeConverter;

import java.nio.ByteBuffer;

import edu.uw.medhas.mhealthsecurityframework.storage.AbstractSecureFileHandler;
import edu.uw.medhas.mhealthsecurityframework.storage.database.model.SecureLong;
import edu.uw.medhas.mhealthsecurityframework.storage.encryption.ByteEncryptor;

/**
 * Created by medhasrivastava on 1/21/19.
 */

public class SecureLongConverter {
    @TypeConverter
    public byte[] fromSecureLongToEncryptedBytes(SecureLong value){
        if (value == null) {
            return null;
        }

        final byte[] objectAsBytes = ByteBuffer.allocate(8).putLong(value.getValue()).array();
        return ByteEncryptor.encrypt(objectAsBytes, AbstractSecureFileHandler.key);
    }

    @TypeConverter
    public SecureLong fromEncryptedBytesToSecureLong(byte[] encryptedValue) {
        if (encryptedValue == null) {
            return null;
        }

        final Long decryptType = ByteBuffer.wrap(ByteEncryptor.decrypt(encryptedValue,
                AbstractSecureFileHandler.key)).getLong();
        return new SecureLong(decryptType);
    }
}
