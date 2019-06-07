package edu.uw.medhas.mhealthsecurityframework.password.widget;

import android.content.Context;
import android.util.AttributeSet;
import android.support.v7.widget.AppCompatEditText;
import android.view.View;
import android.widget.Toast;

import edu.uw.medhas.mhealthsecurityframework.password.PasswordUtils;
import edu.uw.medhas.mhealthsecurityframework.password.exception.PasswordNoLowerCaseCharacterException;
import edu.uw.medhas.mhealthsecurityframework.password.exception.PasswordNoNumberCharacterException;
import edu.uw.medhas.mhealthsecurityframework.password.exception.PasswordNoSpecialCharacterException;
import edu.uw.medhas.mhealthsecurityframework.password.exception.PasswordNoUpperCaseCharacterException;
import edu.uw.medhas.mhealthsecurityframework.password.exception.PasswordTooShortException;

/**
 * This class extends the Android AppCompatEditText component class.
 * It is a Password UI component that automatically checks the strength of the password entered
 * in it and raises an appropriate error.
 *
 * @author Medha Srivastava
 * Created on 10/20/18.
 */

public class PasswordEditText extends AppCompatEditText {
    public PasswordEditText(Context context) {
        super(context);
        setPasswordStrengthCheckListener();
    }

    public PasswordEditText(Context context, AttributeSet attrs) {
        super(context, attrs);
        setPasswordStrengthCheckListener();
    }

    public PasswordEditText(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        setPasswordStrengthCheckListener();
    }

    /**
     * This method is a listener that listens to the characters entered in the Password UI component
     * and on the change of focus throws an appropriate error after checking the strength of the password entered.
     */
    private void setPasswordStrengthCheckListener() {
        setOnFocusChangeListener(new OnFocusChangeListener() {
            @Override
            public void onFocusChange(View view, boolean focus) {
                if (!focus) {
                    final String passwordStr = getText().toString();
                    try {
                        PasswordUtils.validatePassword(passwordStr);
                        setError(null);
                    } catch (PasswordTooShortException ptsex) {
                        setError("Password is too small");
                    } catch (PasswordNoUpperCaseCharacterException pnuccex) {
                        setError("Password has no upper case character");
                    } catch (PasswordNoLowerCaseCharacterException pnlccex) {
                        setError("Password has no lower case character");
                    } catch (PasswordNoNumberCharacterException pnncex) {
                        setError("Password has no number");
                    } catch (PasswordNoSpecialCharacterException pnscex) {
                        setError("Password has no special character");
                    }

                }
            }
        });
    }
}
