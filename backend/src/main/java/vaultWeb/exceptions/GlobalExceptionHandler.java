package vaultWeb.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import vaultWeb.exceptions.notfound.GroupNotFoundException;
import vaultWeb.exceptions.notfound.NotMemberException;
import vaultWeb.exceptions.notfound.UserNotFoundException;

import java.nio.file.AccessDeniedException;

/**
 * Global exception handler for all controllers in the "vaultWeb.controllers" package.
 * <p>
 * Catches specific exceptions and returns appropriate HTTP status codes and messages.
 */
@ControllerAdvice(basePackages = "vaultWeb.controllers")
public class GlobalExceptionHandler {

    /**
     * Handles UserNotFoundException and returns 404 Not Found.
     */
    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<String> handleUserNotFound(UserNotFoundException ex) {
        return ResponseEntity
                .status(HttpStatus.NOT_FOUND)
                .body("User not found: " + ex.getMessage());
    }

    /**
     * Handles GroupNotFoundException and returns 404 Not Found.
     */
    @ExceptionHandler(GroupNotFoundException.class)
    public ResponseEntity<String> handleGroupNotFound(GroupNotFoundException ex) {
        return ResponseEntity
                .status(HttpStatus.NOT_FOUND)
                .body("Group not found: " + ex.getMessage());
    }

    /**
     * Handles UnauthorizedException and returns 401 Unauthorized.
     */
    @ExceptionHandler(UnauthorizedException.class)
    public ResponseEntity<String> handleUnauthorized(UnauthorizedException ex) {
        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body("Unauthorized: " + ex.getMessage());
    }

    /**
     * Handles AccessDeniedException and returns 403 Forbidden.
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<String> handleAccessDenied(AccessDeniedException ex) {
        return ResponseEntity
                .status(HttpStatus.FORBIDDEN)
                .body("Access denied: " + ex.getMessage());
    }

    /**
     * Handles AdminAccessDeniedException and returns 403 Forbidden.
     */
    @ExceptionHandler(AdminAccessDeniedException.class)
    public ResponseEntity<String> handleAdminAccessDenied(AdminAccessDeniedException ex) {
        return ResponseEntity
                .status(HttpStatus.FORBIDDEN)
                .body("Admin access denied: " + ex.getMessage());
    }

    /**
     * Handles AlreadyMemberException and returns 409 Conflict.
     */
    @ExceptionHandler(AlreadyMemberException.class)
    public ResponseEntity<String> handleAlreadyMember(AlreadyMemberException ex) {
        return ResponseEntity
                .status(HttpStatus.CONFLICT)
                .body("Membership error: " + ex.getMessage());
    }

    /**
     * Handles NotMemberException and returns 403 Forbidden.
     */
    @ExceptionHandler(NotMemberException.class)
    public ResponseEntity<String> handleNotMember(NotMemberException ex) {
        return ResponseEntity
                .status(HttpStatus.FORBIDDEN)
                .body("Membership error: " + ex.getMessage());
    }

    /**
     * Handles DuplicateUsernameException and returns 409 Conflict.
     */
    @ExceptionHandler(DuplicateUsernameException.class)
    public ResponseEntity<String> handleDuplicateUsername(DuplicateUsernameException ex) {
        return ResponseEntity
                .status(HttpStatus.CONFLICT)
                .body("Registration error: " + ex.getMessage());
    }

    /**
     * Handles BadCredentialsException (invalid login) and returns 403 Forbidden.
     */
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<String> handleBadCredentials(BadCredentialsException ex) {
        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body("Invalid credentials: " + ex.getMessage());
    }

    /**
     * Handles any other RuntimeException and returns 500 Internal Server Error.
     */
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<String> handleRuntimeException(RuntimeException ex) {
        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("Internal error: " + ex.getMessage());
    }
}