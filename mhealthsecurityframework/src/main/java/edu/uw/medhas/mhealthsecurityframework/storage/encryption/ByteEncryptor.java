package edu.uw.medhas.mhealthsecurityframework.storage.encryption;

import android.content.Context;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import edu.uw.medhas.mhealthsecurityframework.storage.exception.DecryptionException;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.EncryptionException;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.KeyTooShortException;

/**
 * Created by medhas on 5/18/18.
 */

public class ByteEncryptor {
    private static final String sTransformation = "AES/CBC/PKCS5Padding";
    private static final String sKeyAlgorithm = "AES";
    private static final int sMinKeySize = 16;
    private static final int sKeyLength = 16;
    private static final int sIvLength = 16;

    public static byte[] encrypt(byte[] plainText, Context context) {
        try {
            final IvParameterSpec ivParameterSpec = generateIvParameterSpec();

            final SecretKey secretKey = KeyManager.getKey(context);

            final Cipher cipher = Cipher.getInstance(sTransformation);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
            final byte[] cipherText = cipher.doFinal(plainText);

            final byte[] ivAndCipherText = new byte[sIvLength + cipherText.length];
            System.arraycopy(ivParameterSpec.getIV(), 0, ivAndCipherText, 0, sIvLength);
            System.arraycopy(cipherText, 0, ivAndCipherText, sIvLength, cipherText.length);

            return ivAndCipherText;
        } catch (IOException | CertificateException | UnrecoverableEntryException
                 | NoSuchProviderException | KeyStoreException | NoSuchAlgorithmException
                 | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException
                 | BadPaddingException | IllegalBlockSizeException ex) {
            ex.printStackTrace();
            throw new EncryptionException();
        }
    }

    public static byte[] decrypt(byte[] ivAndCipherText, Context context) {
        try {
            final byte[] iv = new byte[sIvLength];
            System.arraycopy(ivAndCipherText, 0, iv, 0, iv.length);
            final IvParameterSpec ivParameterSpec = generateIvParameterSpec(iv);

            final SecretKey secretKey = KeyManager.getKey(context);

            byte[] cipherText = new byte[ivAndCipherText.length - sIvLength];
            System.arraycopy(ivAndCipherText, sIvLength, cipherText, 0, cipherText.length);

            final Cipher cipher = Cipher.getInstance(sTransformation);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

            return cipher.doFinal(cipherText);
        } catch (IOException | CertificateException | UnrecoverableEntryException
                | NoSuchProviderException | KeyStoreException | NoSuchAlgorithmException
                | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException
                | BadPaddingException | IllegalBlockSizeException ex) {
            ex.printStackTrace();
            throw new DecryptionException();
        }
    }

    public static byte[] encrypt(byte[] plainText, String key) {
        try {
            final IvParameterSpec ivParameterSpec = generateIvParameterSpec();

            final SecretKeySpec secretKeySpec = generateKeySpec(key);

            final Cipher cipher = Cipher.getInstance(sTransformation);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
            final byte[] cipherText = cipher.doFinal(plainText);

            final byte[] ivAndCipherText = new byte[sIvLength + cipherText.length];
            System.arraycopy(ivParameterSpec.getIV(), 0, ivAndCipherText, 0, sIvLength);
            System.arraycopy(cipherText, 0, ivAndCipherText, sIvLength, cipherText.length);

            return ivAndCipherText;
        } catch (UnsupportedEncodingException | NoSuchAlgorithmException | NoSuchPaddingException |
                InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException |
                 IllegalBlockSizeException ex) {
            ex.printStackTrace();
            throw new EncryptionException();
        }
    }

    public static byte[] decrypt(byte[] ivAndCipherText, String key) {
        try {
            final byte[] iv = new byte[sIvLength];
            System.arraycopy(ivAndCipherText, 0, iv, 0, iv.length);
            final IvParameterSpec ivParameterSpec = generateIvParameterSpec(iv);

            final SecretKeySpec secretKeySpec = generateKeySpec(key);

            byte[] cipherText = new byte[ivAndCipherText.length - sIvLength];
            System.arraycopy(ivAndCipherText, sIvLength, cipherText, 0, cipherText.length);

            final Cipher cipher = Cipher.getInstance(sTransformation);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

            return cipher.doFinal(cipherText);
        } catch (UnsupportedEncodingException | NoSuchPaddingException | NoSuchAlgorithmException |
                InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException |
                IllegalBlockSizeException ex) {
            ex.printStackTrace();
            throw new DecryptionException();
        }
    }

    private static IvParameterSpec generateIvParameterSpec() {
        byte[] iv = new byte[sIvLength];
        final SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        return generateIvParameterSpec(iv);
    }

    private static IvParameterSpec generateIvParameterSpec(byte[] key) {

        return new IvParameterSpec(key);
    }

    private static SecretKeySpec generateKeySpec(String key) throws NoSuchAlgorithmException,
            UnsupportedEncodingException {
        if (key.length() < sMinKeySize) {
            throw new KeyTooShortException();
        }

        final MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(key.getBytes("UTF-8"));

        final byte[] keyBytes = new byte[sKeyLength];
        System.arraycopy(digest.digest(), 0, keyBytes, 0, keyBytes.length);

        return new SecretKeySpec(keyBytes, sKeyAlgorithm);
    }
}
