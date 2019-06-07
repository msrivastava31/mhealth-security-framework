package edu.uw.medhas.mhealthsecurityframework.password;

import java.util.regex.Pattern;

import edu.uw.medhas.mhealthsecurityframework.password.exception.PasswordNoLowerCaseCharacterException;
import edu.uw.medhas.mhealthsecurityframework.password.exception.PasswordNoNumberCharacterException;
import edu.uw.medhas.mhealthsecurityframework.password.exception.PasswordNoSpecialCharacterException;
import edu.uw.medhas.mhealthsecurityframework.password.exception.PasswordNoUpperCaseCharacterException;
import edu.uw.medhas.mhealthsecurityframework.password.exception.PasswordTooShortException;

/**
 * This class is a utility class that provides various checks to validate the strength of the entered password
 * and throws an appropriate error if the entered password is not strong.
 *
 * @author Medha Srivastava
 * Created on 5/17/18.
 */
public class PasswordUtils {

    private static final Pattern mSpecialCharPattern = Pattern.compile("[^a-z0-9 ]",
            Pattern.CASE_INSENSITIVE);

    /**
     * Validates the strength of the entered password and throws an appropriate error if it is not strong.
     * @param password the entered password
     */
    public static void validatePassword(String password) {

        // Check if password has at least 8 characters
        if (password.length() < 8) {
            throw new PasswordTooShortException();
        }

        // Check if password has a lower case character
        if (password.equals(password.toLowerCase())) {
            throw new PasswordNoUpperCaseCharacterException();
        }

        // Check if password has an upper case character
        if (password.equals(password.toUpperCase())) {
            throw new PasswordNoLowerCaseCharacterException();
        }

        // Check if password has a number
        if (!password.matches(".*\\d+.*")) {
            throw new PasswordNoNumberCharacterException();
        }

        // Check if password has a special character
        if (!mSpecialCharPattern.matcher(password).find()) {
            throw new PasswordNoSpecialCharacterException();
        }
    }
}
