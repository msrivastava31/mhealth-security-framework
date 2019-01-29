package edu.uw.medhas.mhealthsecurityframework.storage.database.converters;

import android.arch.persistence.room.TypeConverter;

import java.nio.charset.StandardCharsets;

import edu.uw.medhas.mhealthsecurityframework.storage.AbstractSecureFileHandler;
import edu.uw.medhas.mhealthsecurityframework.storage.database.model.SecureString;
import edu.uw.medhas.mhealthsecurityframework.storage.encryption.ByteEncryptor;

/**
 * Created by medhasrivastava on 1/21/19.
 */

public class SecureStringConverter {
    @TypeConverter
    public byte[] fromSecureStringToEncryptedBytes(SecureString value){
        if (value == null) {
            return null;
        }

        final byte[] objectAsBytes = value.getValue().getBytes(StandardCharsets.UTF_8);
        return ByteEncryptor.encrypt(objectAsBytes, AbstractSecureFileHandler.key);
    }

    @TypeConverter
    public SecureString fromEncryptedBytesToSecureString(byte[] encryptedValue) {
        if (encryptedValue == null) {
            return null;
        }

        final String decryptType = new String(ByteEncryptor.decrypt(encryptedValue,
                AbstractSecureFileHandler.key), StandardCharsets.UTF_8);
        return new SecureString(decryptType);
    }
}
