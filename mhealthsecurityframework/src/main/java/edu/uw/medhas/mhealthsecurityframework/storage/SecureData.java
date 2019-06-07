package edu.uw.medhas.mhealthsecurityframework.storage;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * This is an annotation to identify sensitive data.
 * Data annotated as sensitive is encrypted before storing it in
 * cache/internal/external storage.
 *
 * @author Medha Srivastava
 * Created on 5/18/18
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface SecureData {
}
