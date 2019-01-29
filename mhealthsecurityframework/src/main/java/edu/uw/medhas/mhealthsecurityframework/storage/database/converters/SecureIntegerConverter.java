package edu.uw.medhas.mhealthsecurityframework.storage.database.converters;

import android.arch.persistence.room.*;

import java.nio.ByteBuffer;

import edu.uw.medhas.mhealthsecurityframework.storage.AbstractSecureFileHandler;
import edu.uw.medhas.mhealthsecurityframework.storage.database.model.SecureInteger;
import edu.uw.medhas.mhealthsecurityframework.storage.encryption.ByteEncryptor;

/**
 * Created by medhasrivastava on 1/21/19.
 */

public class SecureIntegerConverter {
    @TypeConverter
    public byte[] fromSecureIntegerToEncryptedBytes(SecureInteger value){
        if (value == null) {
            return null;
        }

        final byte[] objectAsBytes = ByteBuffer.allocate(4).putInt(value.getValue()).array();
        return ByteEncryptor.encrypt(objectAsBytes, AbstractSecureFileHandler.key);
    }

    @TypeConverter
    public SecureInteger fromEncryptedBytesToSecureInteger(byte[] encryptedValue){
        if (encryptedValue == null) {
            return null;
        }

        final Integer decryptType = ByteBuffer.wrap(ByteEncryptor.decrypt(encryptedValue,
                AbstractSecureFileHandler.key)).getInt();
        return new SecureInteger(decryptType);
    }
}
