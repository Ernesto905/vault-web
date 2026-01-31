package vaultWeb.validation;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import java.util.Set;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import vaultWeb.dtos.user.UserDto;

class UserDtoValidationTest {

  private static final String VALID_USERNAME = "testuser";
  private static final String VALID_PASSWORD = "TestPassword1!";

  private static Validator validator;

  @BeforeAll
  static void setUp() {
    try (ValidatorFactory factory = Validation.buildDefaultValidatorFactory()) {
      validator = factory.getValidator();
    }
  }

  @Test
  void shouldAcceptValidUserDto() {
    UserDto dto = new UserDto(VALID_USERNAME, VALID_PASSWORD);
    Set<ConstraintViolation<UserDto>> violations = validator.validate(dto);
    assertTrue(violations.isEmpty(), "Valid UserDto should have no violations");
  }

  @ParameterizedTest(name = "username: \"{0}\"")
  @NullSource
  @ValueSource(strings = {"", "   "})
  void shouldRejectInvalidUsername(String username) {
    UserDto dto = new UserDto(username, VALID_PASSWORD);
    Set<ConstraintViolation<UserDto>> violations = validator.validate(dto);
    assertFalse(violations.isEmpty(), "Username '" + username + "' should be rejected");
  }

  @ParameterizedTest(name = "password: \"{0}\"")
  @NullSource
  @ValueSource(strings = {""})
  void shouldRejectNullOrEmptyPassword(String password) {
    UserDto dto = new UserDto(VALID_USERNAME, password);
    Set<ConstraintViolation<UserDto>> violations = validator.validate(dto);
    assertFalse(violations.isEmpty(), "Password '" + password + "' should be rejected");
  }

  @ParameterizedTest(name = "password: \"{0}\"")
  @ValueSource(strings = {"Short1!", "nouppercase1!", "NoDigit!", "NoSpecial1"})
  void shouldRejectPasswordNotMeetingComplexity(String password) {
    UserDto dto = new UserDto(VALID_USERNAME, password);
    Set<ConstraintViolation<UserDto>> violations = validator.validate(dto);
    assertFalse(violations.isEmpty(), "Password '" + password + "' should be rejected");
  }
}
