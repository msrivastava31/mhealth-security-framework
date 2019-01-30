package edu.uw.medhas.mhealthsecurityframework.storage.cache;

import android.content.Context;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import edu.uw.medhas.mhealthsecurityframework.storage.AbstractSecureFileHandler;
import edu.uw.medhas.mhealthsecurityframework.storage.SecureFile;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.InvalidEnvironmentDirectoryException;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.SerializationException;

/**
 * Created by medhas on 10/18/18.
 */

public class SecureCacheHandler extends AbstractSecureFileHandler {
    public SecureCacheHandler(Context context) {
        super(context);
    }

    @Override
    protected String getKeyAlias() {
        return "mhealth-security-framework-cache-storage";
    }

    public <S> void writeData(S secureObj, String filename) {
        final SecureFile secureFile = new SecureFile();
        secureFile.setFilename(filename);

        final byte[] secureObjectAsBytes = getSecureObjAsBytes(secureObj, secureFile);

        final File finalFileName = getFile(secureFile.getFinalFilename());

        /*try {
            finalFileName = File.createTempFile(secureFile.getFinalFilename(), null,
                    getContext().getCacheDir());
        } catch (IOException ioex) {
            ioex.printStackTrace();
            throw new SerializationException();
        }*/

        try (final FileOutputStream fos = new FileOutputStream(finalFileName)) {
            fos.write(secureObjectAsBytes);
        } catch (IOException ioex) {
            ioex.printStackTrace();
            throw new SerializationException();
        }
    }

    public <S> S readData(Class<S> clazz, String filename) throws FileNotFoundException {
        final SecureFile secureFile = new SecureFile();
        secureFile.setFilename(filename);

        if (getFile(secureFile.getJsonEncryptedFileName()).exists()) {
            secureFile.setJsonData(true);
            secureFile.setEncryptedData(true);
        } else if (getFile(secureFile.getJsonFileName()).exists()) {
            secureFile.setJsonData(true);
        } else if (getFile(secureFile.getEncryptedFileName()).exists()) {
            secureFile.setEncryptedData(true);
        }

        final File finalFileName = getFile(secureFile.getFinalFilename());
        byte[] objectAsBytes = new byte[(int) finalFileName.length()];

        try (final FileInputStream fis = new FileInputStream(finalFileName)) {
            fis.read(objectAsBytes);
        } catch (FileNotFoundException fnfex) {
            fnfex.printStackTrace();
            throw fnfex;
        } catch (IOException ioex) {
            ioex.printStackTrace();
            throw new SerializationException();
        }

        return readObjFromBytes(clazz, objectAsBytes, secureFile);
    }

    private File getFile(String filename) {
        return new File(getContext().getCacheDir(), filename);
    }
}
