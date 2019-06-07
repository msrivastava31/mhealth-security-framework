package edu.uw.medhas.mhealthsecurityframework.storage;

/**
 * This class contains the metadata of the data to be stored/retrieved
 * in/from cache/internal/external storage.
 *
 * @author Medha Srivastava
 * Created on 5/18/18
 */

public class SecureFile {
    /**
     * Name of the file where data is stored/retrieved
     */
    private String mFilename;

    /**
     * Flag to hold true if data to be stored/retrieved is json.
     */
    private boolean mIsJsonData;

    /**
     * Flag to hold true if data to be stored/retrieved is encrypted (only for sensitive data).
     */
    private boolean mIsEncryptedData;

    public String getFilename() {
        return mFilename;
    }

    public String getFinalFilename() {
        final StringBuilder sb = new StringBuilder(mFilename);
        if (isJsonData()) {
            sb.append(StorageConstants.sJsonExtension);
        }
        if (isEncryptedData()) {
            sb.append(StorageConstants.sEncryptedExtension);
        }
        return sb.toString();
    }

    public String getJsonEncryptedFileName() {
        return new StringBuilder(mFilename)
                .append(StorageConstants.sJsonExtension)
                .append(StorageConstants.sEncryptedExtension)
                .toString();
    }

    public String getJsonFileName() {
        return new StringBuilder(mFilename)
                .append(StorageConstants.sJsonExtension)
                .toString();
    }

    public String getEncryptedFileName() {
        return new StringBuilder(mFilename)
                .append(StorageConstants.sEncryptedExtension)
                .toString();
    }

    public void setFilename(String filename) {
        mFilename = filename;
    }

    public boolean isJsonData() {
        return mIsJsonData;
    }

    public void setJsonData(boolean isJsonData) {
        mIsJsonData = isJsonData;
    }

    public boolean isEncryptedData() {
        return mIsEncryptedData;
    }

    public void setEncryptedData(boolean isEncryptedData) {
        mIsEncryptedData = isEncryptedData;
    }
}
