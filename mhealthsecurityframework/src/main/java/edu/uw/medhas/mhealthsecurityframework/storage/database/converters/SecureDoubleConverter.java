package edu.uw.medhas.mhealthsecurityframework.storage.database.converters;

import android.arch.persistence.room.TypeConverter;

import java.nio.ByteBuffer;

import edu.uw.medhas.mhealthsecurityframework.storage.database.model.SecureDouble;
import edu.uw.medhas.mhealthsecurityframework.storage.encryption.ByteEncryptor;

/**
 * Created by medhasrivastava on 1/21/19.
 */

public class SecureDoubleConverter extends AbstractSecureConverter {
    @TypeConverter
    public byte[] fromSecureDoubleToEncryptedBytes(SecureDouble value){
        if (value == null) {
            return null;
        }

        final byte[] objectAsBytes = ByteBuffer.allocate(8).putDouble(value.getValue()).array();
        return ByteEncryptor.encrypt(keyAlias, objectAsBytes);
    }

    @TypeConverter
    public SecureDouble fromEncryptedBytesToSecureDouble(byte[] encryptedValue) {
        if (encryptedValue == null) {
            return null;
        }

        final Double decryptType = ByteBuffer.wrap(ByteEncryptor.decrypt(keyAlias, encryptedValue)).getDouble();
        return new SecureDouble(decryptType);
    }
}
