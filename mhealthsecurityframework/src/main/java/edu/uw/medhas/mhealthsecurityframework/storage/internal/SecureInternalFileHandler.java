package edu.uw.medhas.mhealthsecurityframework.storage.internal;

import android.content.Context;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import edu.uw.medhas.mhealthsecurityframework.storage.AbstractSecureFileHandler;
import edu.uw.medhas.mhealthsecurityframework.storage.SecureFile;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.SerializationException;

/**
 * Created by medhas on 5/18/18.
 */

public class SecureInternalFileHandler extends AbstractSecureFileHandler {
    public SecureInternalFileHandler(Context context) {
        super(context);
    }

    public <S> void writeData(S secureObj, String filename) {
        final SecureFile secureFile = new SecureFile();
        secureFile.setFilename(filename);

        final byte[] secureObjectAsBytes = getSecureObjAsBytes(secureObj, secureFile);

        try (final FileOutputStream fos = getContext().openFileOutput(secureFile.getFinalFilename(),
                Context.MODE_PRIVATE)) {
            fos.write(secureObjectAsBytes);
        } catch (IOException ioex) {
            ioex.printStackTrace();
            throw new SerializationException();
        }
    }

    public <S> S readData(Class<S> clazz, String filename) throws FileNotFoundException {
        final SecureFile secureFile = new SecureFile();
        secureFile.setFilename(filename);

        if (fileExists(secureFile.getJsonEncryptedFileName())) {
            secureFile.setJsonData(true);
            secureFile.setEncryptedData(true);
        } else if (fileExists(secureFile.getJsonFileName())) {
            secureFile.setJsonData(true);
        } else if (fileExists(secureFile.getEncryptedFileName())) {
            secureFile.setEncryptedData(true);
        }

        final String finalFileName = secureFile.getFinalFilename();
        byte[] objectAsBytes = new byte[(int) getContext().getFileStreamPath(finalFileName).length()];

        try (final FileInputStream fis = getContext().openFileInput(finalFileName)) {
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

    private boolean fileExists(String filename) {
        return getContext().getFileStreamPath(filename).exists();
    }
}
