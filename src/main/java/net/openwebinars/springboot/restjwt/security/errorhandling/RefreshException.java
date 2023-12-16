package net.openwebinars.springboot.restjwt.security.errorhandling;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.io.Serial;


public class RefreshException extends RuntimeException {

    public RefreshException(String token, String message) {
        super(String.format("Failed for [%s]: %s", token, message));
    }
}
