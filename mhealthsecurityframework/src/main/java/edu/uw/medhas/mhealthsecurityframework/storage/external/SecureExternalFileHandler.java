package edu.uw.medhas.mhealthsecurityframework.storage.external;

import android.content.Context;
import android.os.Environment;

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
 * Created by medhas on 5/18/18.
 */

public class SecureExternalFileHandler extends AbstractSecureFileHandler {
    public SecureExternalFileHandler(Context context) {
        super(context);
    }

    @Override
    protected String getKeyAlias() {
        return "mhealth-security-framework-external-storage";
    }

    public <S> void writeData(S secureObj, String environmentDir, String filename) {
        if (!getContext().getExternalFilesDir(environmentDir).exists()) {
            throw new InvalidEnvironmentDirectoryException();
        }

        final SecureFile secureFile = new SecureFile();
        secureFile.setFilename(filename);

        final byte[] secureObjectAsBytes = getSecureObjAsBytes(secureObj, secureFile);

        final File finalFileName = getFile(environmentDir, secureFile.getFinalFilename());

        try (final FileOutputStream fos = new FileOutputStream(finalFileName)) {
            fos.write(secureObjectAsBytes);
        } catch (IOException ioex) {
            ioex.printStackTrace();
            throw new SerializationException();
        }
    }

    public <S> S readData(Class<S> clazz, String environmentDir, String filename) throws FileNotFoundException {
        if (!getContext().getExternalFilesDir(environmentDir).exists()) {
            throw new InvalidEnvironmentDirectoryException();
        }

        final SecureFile secureFile = new SecureFile();
        secureFile.setFilename(filename);

        if (getFile(environmentDir, secureFile.getJsonEncryptedFileName()).exists()) {
            secureFile.setJsonData(true);
            secureFile.setEncryptedData(true);
        } else if (getFile(environmentDir, secureFile.getJsonFileName()).exists()) {
            secureFile.setJsonData(true);
        } else if (getFile(environmentDir, secureFile.getEncryptedFileName()).exists()) {
            secureFile.setEncryptedData(true);
        }

        final File finalFileName = getFile(environmentDir, secureFile.getFinalFilename());
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

    private File getFile(String environmentDir, String filename) {
        return new File(getContext().getExternalFilesDir(environmentDir), filename);
    }
}
