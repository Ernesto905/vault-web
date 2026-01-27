package vaultWeb.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;

import jakarta.servlet.http.Cookie;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import vaultWeb.dtos.user.ChangePasswordRequest;
import vaultWeb.dtos.user.UserDto;
import vaultWeb.models.User;
import vaultWeb.security.JwtUtil;
import vaultWeb.support.TestJwtUtil;

class UserControllerIntegrationTest extends IntegrationTestBase {

  // ============================================================================
  // Test Constants
  // ============================================================================
  private static final String TEST_USERNAME = "testuser";
  private static final String TEST_PASSWORD = "TestPassword1!";
  private static final String NEW_PASSWORD = "NewPassword1!";
  private static final int REFRESH_TOKEN_MAX_AGE_SECONDS = 30 * 24 * 60 * 60; // 30 days
  private static final long EXPIRED_TOKEN_OFFSET_MS = -60 * 60 * 1000; // 1 hour in past

  // ============================================================================
  // Test Dependencies (mockMvc, objectMapper, userRepository inherited from base)
  // ============================================================================
  @Autowired private JwtUtil jwtUtil;
  @Autowired private TestJwtUtil testJwtUtil;

  /**
   * Creates a UserDto with the given username and password.
   *
   * @param username the username for the user
   * @param password the password for the user
   * @return a UserDto instance
   */
  private UserDto createUserDto(String username, String password) {
    UserDto dto = new UserDto();
    dto.setUsername(username);
    dto.setPassword(password);
    return dto;
  }

  /**
   * Extracts a cookie from the MvcResult response.
   *
   * @param result the MvcResult from a test request
   * @param cookieName the name of the cookie to extract
   * @return the Cookie object, or null if not found
   */
  private Cookie extractCookie(MvcResult result, String cookieName) {
    return result.getResponse().getCookie(cookieName);
  }

  /**
   * Extracts the JWT access token from a JSON response.
   *
   * @param result the MvcResult containing the JSON response
   * @return the access token string
   * @throws Exception if JSON parsing fails
   */
  private String extractTokenFromResponse(MvcResult result) throws Exception {
    String json = result.getResponse().getContentAsString();
    JsonNode node = objectMapper.readTree(json);
    JsonNode tokenNode = node.get("token");
    assertNotNull(tokenNode, "Response JSON does not contain 'token' field");
    return tokenNode.asText();
  }

  /**
   * Formats a JWT token into an Authorization header value.
   *
   * @param token the JWT access token
   * @return the formatted "Bearer {token}" string
   */
  private String authHeader(String token) {
    return "Bearer " + token;
  }

  /**
   * Performs a GET request to a protected endpoint using RestTemplate.
   *
   * <p>This helper method is used for testing filter-level authentication failures that occur
   * before Spring MVC's DispatcherServlet. RestTemplate makes real HTTP requests through the entire
   * servlet container stack, properly simulating how Spring Security filters handle invalid/expired
   * tokens and delegate to AuthenticationEntryPoint.
   *
   * @param endpoint the API endpoint path (e.g., "/api/auth/users")
   * @param authToken the Authorization header value, or null for no auth header
   * @return the ResponseEntity from the request
   */
  private ResponseEntity<String> performRestTemplateGet(String endpoint, String authToken) {
    HttpHeaders headers = new HttpHeaders();
    if (authToken != null) {
      headers.set("Authorization", authToken);
    }
    HttpEntity<String> entity = new HttpEntity<>(headers);

    return restTemplate.exchange(
        "http://localhost:" + port + endpoint, HttpMethod.GET, entity, String.class);
  }

  /**
   * Registers a new user via the /api/auth/register endpoint.
   *
   * @param testUser the user DTO containing registration details
   * @throws Exception if the registration request fails
   */
  private void registerUser(UserDto testUser) throws Exception {
    mockMvc
        .perform(
            post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(testUser)))
        .andExpect(status().isOk())
        .andExpect(content().string("User registered successfully"));
  }

  /**
   * Logs in a user via the /api/auth/login endpoint and returns the MvcResult containing the access
   * token and refresh token cookie.
   *
   * @param testUser the user DTO containing login credentials
   * @return the MvcResult with access token in response body and refresh token in cookie
   * @throws Exception if the login request fails
   */
  private MvcResult loginUser(UserDto testUser) throws Exception {
    return mockMvc
        .perform(
            post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(testUser)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.token").exists())
        .andReturn();
  }

  // ============================================================================
  // Stage 1: Foundation Setup
  // ============================================================================

  @Test
  void shouldLoadSpringContext() {
    assertNotNull(mockMvc);
    assertNotNull(userRepository);
  }

  // ============================================================================
  // Stage 2: Basic Authentication Flow (3 tests)
  // ============================================================================

  @Test
  void shouldRegisterNewUser() throws Exception {
    UserDto testUser = createUserDto(TEST_USERNAME, TEST_PASSWORD);

    // Perform registration request and verify response
    registerUser(testUser);

    // Verify user is saved in database
    assertTrue(userRepository.findByUsername(testUser.getUsername()).isPresent());

    // Verify password is properly BCrypt hashed
    User savedUser = userRepository.findByUsername(testUser.getUsername()).get();
    assertTrue(savedUser.getPassword().startsWith("$2a$"));
  }

  @Test
  void shouldFailRegistration_WhenDuplicateUsername() throws Exception {
    UserDto testUser = createUserDto(TEST_USERNAME, TEST_PASSWORD);
    registerUser(testUser);
    mockMvc
        .perform(
            post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(testUser)))
        .andExpect(status().isConflict())
        .andExpect(
            content()
                .string("Registration error: Username '" + TEST_USERNAME + "' is already taken"));

    assertTrue(userRepository.findByUsername(testUser.getUsername()).isPresent());
  }

  @Test
  void shouldLogin_WithValidCredentials() throws Exception {
    // Register a user first
    UserDto testUser = createUserDto(TEST_USERNAME, TEST_PASSWORD);
    registerUser(testUser);

    // Login with the registered user and capture result
    MvcResult result =
        mockMvc
            .perform(
                post("/api/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(testUser)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.token").exists())
            .andReturn();

    // Verify refresh_token cookie is set
    Cookie refreshTokenCookie = extractCookie(result, "refresh_token");
    assertNotNull(refreshTokenCookie, "refresh_token cookie should be set");
    assertNotNull(refreshTokenCookie.getValue(), "refresh_token should have a value");
    assertTrue(refreshTokenCookie.isHttpOnly(), "refresh_token should be HttpOnly");
    assertTrue(refreshTokenCookie.getSecure(), "refresh_token should be Secure");
    assertEquals(
        "/api/auth/refresh",
        refreshTokenCookie.getPath(),
        "refresh_token path should be /api/auth/refresh");
    assertEquals(
        REFRESH_TOKEN_MAX_AGE_SECONDS,
        refreshTokenCookie.getMaxAge(),
        "refresh_token should expire in 30 days");

    // Verify SameSite attribute via raw header (Cookie class doesn't expose SameSite)
    String setCookieHeader = result.getResponse().getHeader("Set-Cookie");
    assertNotNull(setCookieHeader, "Set-Cookie header should be present");
    assertTrue(
        setCookieHeader.contains("SameSite=None"),
        "refresh_token should have SameSite=None for cross-origin requests");
  }

  // ============================================================================
  // Stage 2b: Login Error Scenarios (3 tests)
  // ============================================================================

  @Test
  void shouldFailLogin_WithWrongPassword() throws Exception {
    // Register a user first
    UserDto testUser = createUserDto(TEST_USERNAME, TEST_PASSWORD);
    registerUser(testUser);

    // Attempt login with wrong password
    UserDto wrongPasswordUser = createUserDto(TEST_USERNAME, "WrongPassword1!");

    mockMvc
        .perform(
            post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(wrongPasswordUser)))
        .andExpect(status().isUnauthorized())
        .andExpect(content().string("Authentication failed"));
  }

  @Test
  void shouldFailLogin_WithNonExistentUser() throws Exception {
    // Attempt login with a user that does not exist
    UserDto nonExistentUser = createUserDto("nonexistent", TEST_PASSWORD);

    mockMvc
        .perform(
            post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(nonExistentUser)))
        .andExpect(status().isUnauthorized())
        .andExpect(content().string("Authentication failed"));
  }

  @Test
  void shouldFailLogin_WithNullCredentials() throws Exception {
    // Test with null username
    mockMvc
        .perform(
            post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\": null, \"password\": \"TestPassword1!\"}"))
        .andExpect(status().isBadRequest());

    // Test with null password
    mockMvc
        .perform(
            post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\": \"testuser\", \"password\": null}"))
        .andExpect(status().isBadRequest());

    // Test with empty/blank username
    mockMvc
        .perform(
            post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\": \"\", \"password\": \"TestPassword1!\"}"))
        .andExpect(status().isBadRequest());

    // Test with empty/blank password
    mockMvc
        .perform(
            post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\": \"testuser\", \"password\": \"\"}"))
        .andExpect(status().isBadRequest());
  }

  // ============================================================================
  // Stage 3: JWT Token Integration (5 tests)
  // ============================================================================

  @Test
  void shouldGenerateValidJwtToken_OnLogin() throws Exception {
    UserDto testUser = createUserDto(TEST_USERNAME, TEST_PASSWORD);
    registerUser(testUser);
    MvcResult result =
        mockMvc
            .perform(
                post("/api/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(testUser)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.token").exists())
            .andReturn();
    String token = extractTokenFromResponse(result);
    assertTrue(jwtUtil.validateToken(token));
    String username = jwtUtil.extractUsername(token);
    assertEquals(testUser.getUsername(), username);
  }

  @Test
  void shouldAccessProtectedEndpoint_WithValidToken() throws Exception {
    UserDto testUser = createUserDto(TEST_USERNAME, TEST_PASSWORD);
    registerUser(testUser);
    MvcResult result =
        mockMvc
            .perform(
                post("/api/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(testUser)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.token").exists())
            .andReturn();
    String token = extractTokenFromResponse(result);
    mockMvc
        .perform(get("/api/auth/users").header("Authorization", authHeader(token)))
        .andExpect(status().isOk())
        .andExpect(content().json("[{\"username\":\"" + TEST_USERNAME + "\"}]"));
  }

  // ============================================================================
  // Filter-Level Authentication Failures (RestTemplate Required)
  // ============================================================================
  // The following tests use RestTemplate instead of MockMvc because they test
  // authentication failures that occur in Spring Security filters, BEFORE reaching
  // Spring MVC's DispatcherServlet.
  //
  // When invalid/expired JWT tokens are processed:
  // 1. JwtAuthFilter throws JwtAuthenticationException (line 95 in JwtAuthFilter.java)
  // 2. Spring Security catches this and delegates to JwtAuthenticationEntryPoint
  // 3. The servlet container sends a 401 Unauthorized response
  //
  // MockMvc operates at the Spring MVC layer and may not fully simulate this
  // filter-level exception handling. RestTemplate makes real HTTP requests through
  // the entire servlet container stack, ensuring we test the actual behavior.
  // ============================================================================

  @Test
  void shouldReject_WithInvalidToken_UsingRestTemplate() {
    ResponseEntity<String> response =
        performRestTemplateGet("/api/auth/users", authHeader("invalid_token"));

    assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
  }

  @Test
  void shouldReject_WithMissingToken() {
    ResponseEntity<String> response = performRestTemplateGet("/api/auth/users", null);

    assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
  }

  @Test
  void shouldReject_WithExpiredToken() throws Exception {
    // Register a user first
    UserDto testUser = createUserDto(TEST_USERNAME, TEST_PASSWORD);
    registerUser(testUser);

    // Get the user from database to generate expired token
    User savedUser = userRepository.findByUsername(testUser.getUsername()).get();

    // Generate an expired token (expired 1 hour ago)
    String expiredToken =
        testJwtUtil.generateTokenWithExpiration(savedUser, EXPIRED_TOKEN_OFFSET_MS);

    // Try to access protected endpoint with expired token
    ResponseEntity<String> response =
        performRestTemplateGet("/api/auth/users", authHeader(expiredToken));

    assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
  }

  // ============================================================================
  // Authorization Header Variations
  // ============================================================================

  @Test
  void shouldReject_WithMalformedAuthorizationHeader() {
    // Test with completely malformed header value (random string)
    ResponseEntity<String> response = performRestTemplateGet("/api/auth/users", "random_string");

    assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
  }

  @Test
  void shouldReject_WithMissingBearerPrefix() throws Exception {
    // Test with valid JWT token but without "Bearer " prefix
    UserDto testUser = createUserDto(TEST_USERNAME, TEST_PASSWORD);
    registerUser(testUser);
    User savedUser = userRepository.findByUsername(testUser.getUsername()).get();
    String token = jwtUtil.generateToken(savedUser);

    ResponseEntity<String> response = performRestTemplateGet("/api/auth/users", token);

    assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
  }

  @Test
  void shouldReject_WithEmptyAuthorizationHeader() {
    // Test with empty Authorization header value
    ResponseEntity<String> response = performRestTemplateGet("/api/auth/users", "");

    assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
  }

  @Test
  void shouldReject_WithBearerPrefixOnly() {
    // Test with just "Bearer " and no token
    ResponseEntity<String> response = performRestTemplateGet("/api/auth/users", "Bearer ");

    assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
  }

  @Test
  void shouldReject_WithBearerPrefixWrongCase() throws Exception {
    // Test with wrong case prefix (e.g., "bearer ", "BEARER ")
    UserDto testUser = createUserDto(TEST_USERNAME, TEST_PASSWORD);
    registerUser(testUser);
    User savedUser = userRepository.findByUsername(testUser.getUsername()).get();
    String token = jwtUtil.generateToken(savedUser);

    ResponseEntity<String> lowerCaseResponse =
        performRestTemplateGet("/api/auth/users", "bearer " + token);
    assertEquals(HttpStatus.UNAUTHORIZED, lowerCaseResponse.getStatusCode());

    ResponseEntity<String> upperCaseResponse =
        performRestTemplateGet("/api/auth/users", "BEARER " + token);
    assertEquals(HttpStatus.UNAUTHORIZED, upperCaseResponse.getStatusCode());
  }

  // ============================================================================
  // Stage 4: Refresh Token Flow (4 tests)
  // ============================================================================

  @Test
  void shouldRefreshAccessToken_WithValidRefreshToken() throws Exception {
    UserDto testUser = createUserDto(TEST_USERNAME, TEST_PASSWORD);
    registerUser(testUser);
    MvcResult result = loginUser(testUser);
    String refreshToken = extractCookie(result, "refresh_token").getValue();
    result =
        mockMvc
            .perform(post("/api/auth/refresh").cookie(new Cookie("refresh_token", refreshToken)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.token").exists())
            .andReturn();
    // Verify the refresh token has been sent with the cookie
    Cookie newRefreshToken = extractCookie(result, "refresh_token");
    assertNotNull(newRefreshToken, "New refresh token should be set");
    assertNotNull(newRefreshToken.getValue(), "New refresh token should have a value");
    assertTrue(newRefreshToken.getValue().length() > 0, "New refresh token should have a value");
    assertNotEquals(newRefreshToken.getValue(), refreshToken, "Refresh token should be rotated");

    // Verify the old refresh token has been revoked in database
    String oldTokenId = jwtUtil.extractTokenId(refreshToken);
    assertTrue(
        refreshTokenRepository.findByTokenIdAndRevokedFalse(oldTokenId).isEmpty(),
        "Old refresh token should be revoked after rotation");
  }

  @Test
  void shouldRotateRefreshToken_AndRejectOldToken() throws Exception {
    UserDto testUser = createUserDto(TEST_USERNAME, TEST_PASSWORD);
    registerUser(testUser);
    MvcResult result = loginUser(testUser);
    String refreshToken = extractCookie(result, "refresh_token").getValue();

    // First refresh - should succeed and rotate the token
    result =
        mockMvc
            .perform(post("/api/auth/refresh").cookie(new Cookie("refresh_token", refreshToken)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.token").exists())
            .andReturn();

    // Second refresh with old token - should fail because token was rotated
    mockMvc
        .perform(post("/api/auth/refresh").cookie(new Cookie("refresh_token", refreshToken)))
        .andExpect(status().isUnauthorized());

    // Verify old token is revoked in database
    String oldTokenId = jwtUtil.extractTokenId(refreshToken);
    assertTrue(
        refreshTokenRepository.findByTokenIdAndRevokedFalse(oldTokenId).isEmpty(),
        "Old refresh token should be revoked after rotation");
  }

  @Test
  void shouldRejectRefresh_WithInvalidToken() throws Exception {
    UserDto testUser = createUserDto(TEST_USERNAME, TEST_PASSWORD);
    registerUser(testUser);
    MvcResult result = loginUser(testUser);
    String refreshToken = extractCookie(result, "refresh_token").getValue();

    // Attempt refresh with invalid token - should be rejected
    mockMvc
        .perform(post("/api/auth/refresh").cookie(new Cookie("refresh_token", "invalid_token")))
        .andExpect(status().isUnauthorized());

    // Verify the valid token is still active (not affected by invalid attempt)
    String validTokenId = jwtUtil.extractTokenId(refreshToken);
    assertTrue(
        refreshTokenRepository.findByTokenIdAndRevokedFalse(validTokenId).isPresent(),
        "Valid refresh token should still be active after invalid token attempt");
  }

  @Test
  void shouldLogout_AndRevokeRefreshToken() throws Exception {
    UserDto testUser = createUserDto(TEST_USERNAME, TEST_PASSWORD);
    registerUser(testUser);
    MvcResult result = loginUser(testUser);
    String refreshToken = extractCookie(result, "refresh_token").getValue();
    result =
        mockMvc
            .perform(post("/api/auth/logout").cookie(new Cookie("refresh_token", refreshToken)))
            .andExpect(status().isOk())
            .andReturn();

    String tokenId = jwtUtil.extractTokenId(refreshToken);
    assertTrue(refreshTokenRepository.findByTokenIdAndRevokedFalse(tokenId).isEmpty());

    Cookie deletedCookie = extractCookie(result, "refresh_token");
    assertNotNull(deletedCookie, "refresh_token cookie should be deleted");
    assertEquals(0, deletedCookie.getMaxAge(), "refresh_token should be deleted");

    mockMvc
        .perform(post("/api/auth/refresh").cookie(new Cookie("refresh_token", refreshToken)))
        .andExpect(status().isUnauthorized());
  }

  // ============================================================================
  // Stage 5: Spring Security Integration
  // ============================================================================

  @Test
  void shouldChangePassword_WithValidCurrentPassword() throws Exception {

    UserDto testUser = createUserDto(TEST_USERNAME, TEST_PASSWORD);
    registerUser(testUser);
    MvcResult result = loginUser(testUser);
    String token = extractTokenFromResponse(result);
    ChangePasswordRequest changePasswordRequest = new ChangePasswordRequest();
    changePasswordRequest.setCurrentPassword(TEST_PASSWORD);
    changePasswordRequest.setNewPassword(NEW_PASSWORD);

    mockMvc
        .perform(
            post("/api/auth/change-password")
                .header("Authorization", authHeader(token))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(changePasswordRequest)))
        .andExpect(status().isNoContent())
        .andReturn();

    testUser.setPassword(NEW_PASSWORD);
    result = loginUser(testUser);
    String newToken = extractTokenFromResponse(result);
    assertTrue(jwtUtil.validateToken(newToken), "New password should work for login");

    testUser.setPassword(TEST_PASSWORD);
    mockMvc
        .perform(
            post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(testUser)))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void shouldRejectChangePassword_WithWrongCurrentPassword() throws Exception {
    UserDto testUser = createUserDto(TEST_USERNAME, TEST_PASSWORD);
    registerUser(testUser);
    MvcResult result = loginUser(testUser);
    String token = extractTokenFromResponse(result);
    ChangePasswordRequest changePasswordRequest = new ChangePasswordRequest();
    changePasswordRequest.setCurrentPassword("TestPassword2!");
    changePasswordRequest.setNewPassword(NEW_PASSWORD);
    mockMvc
        .perform(
            post("/api/auth/change-password")
                .header("Authorization", authHeader(token))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(changePasswordRequest)))
        .andExpect(status().isUnauthorized());
  }

  // ============================================================================
  // Stage 6: Full E2E Scenarios
  // ============================================================================

  @Test
  void shouldCompleteFullAuthenticationFlow() throws Exception {

    UserDto testUser = createUserDto(TEST_USERNAME, TEST_PASSWORD);
    registerUser(testUser);
    MvcResult result = loginUser(testUser);
    String token = extractTokenFromResponse(result);
    String refreshToken = extractCookie(result, "refresh_token").getValue();

    // Access protected endpoint with valid token
    mockMvc
        .perform(get("/api/auth/users").header("Authorization", authHeader(token)))
        .andExpect(status().isOk())
        .andExpect(content().json("[{\"username\":\"" + TEST_USERNAME + "\"}]"));

    // Refresh token to get new tokens (this rotates the refresh token)
    result =
        mockMvc
            .perform(post("/api/auth/refresh").cookie(new Cookie("refresh_token", refreshToken)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.token").exists())
            .andReturn();
    String newAccessToken = extractTokenFromResponse(result);
    String newRefreshToken = extractCookie(result, "refresh_token").getValue();
    assertTrue(jwtUtil.validateToken(newAccessToken), "New access token should be valid");

    // Logout with the NEW refresh token
    mockMvc
        .perform(post("/api/auth/logout").cookie(new Cookie("refresh_token", newRefreshToken)))
        .andExpect(status().isOk());

    // Verify the NEW refresh token is revoked after logout
    String newTokenId = jwtUtil.extractTokenId(newRefreshToken);
    assertTrue(
        refreshTokenRepository.findByTokenIdAndRevokedFalse(newTokenId).isEmpty(),
        "New refresh token should be revoked after logout");

    // Verify refresh with revoked token fails
    mockMvc
        .perform(post("/api/auth/refresh").cookie(new Cookie("refresh_token", newRefreshToken)))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void shouldHandleMultipleSessions_PerUser() throws Exception {
    // Register user
    UserDto testUser = createUserDto(TEST_USERNAME, TEST_PASSWORD);
    registerUser(testUser);

    // Login from "client 1" to get first refresh token
    MvcResult result1 = loginUser(testUser);
    String refreshToken1 = extractCookie(result1, "refresh_token").getValue();
    String tokenId1 = jwtUtil.extractTokenId(refreshToken1);

    // Verify first token exists and is not revoked
    assertTrue(
        refreshTokenRepository.findByTokenIdAndRevokedFalse(tokenId1).isPresent(),
        "First refresh token should exist and not be revoked");

    // Login from "client 2" to get second refresh token (simulates login from another device)
    MvcResult result2 = loginUser(testUser);
    String refreshToken2 = extractCookie(result2, "refresh_token").getValue();
    String tokenId2 = jwtUtil.extractTokenId(refreshToken2);

    // Verify only one non-revoked refresh token exists in database (single session enforcement)
    User user = userRepository.findByUsername(TEST_USERNAME).orElseThrow();
    long nonRevokedCount =
        refreshTokenRepository.findAll().stream()
            .filter(token -> !token.isRevoked() && token.getUser().getId().equals(user.getId()))
            .count();
    assertEquals(1, nonRevokedCount, "Only one non-revoked refresh token should exist per user");

    // Verify first refresh token is revoked (second login should revoke first token)
    assertTrue(
        refreshTokenRepository.findByTokenIdAndRevokedFalse(tokenId1).isEmpty(),
        "First refresh token should be revoked after second login");

    // Verify second refresh token is active
    assertTrue(
        refreshTokenRepository.findByTokenIdAndRevokedFalse(tokenId2).isPresent(),
        "Second refresh token should be active");

    // Verify first token no longer works (returns 401)
    mockMvc
        .perform(post("/api/auth/refresh").cookie(new Cookie("refresh_token", refreshToken1)))
        .andExpect(status().isUnauthorized());

    // Verify second token works correctly
    mockMvc
        .perform(post("/api/auth/refresh").cookie(new Cookie("refresh_token", refreshToken2)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.token").exists());
  }

  @Test
  void shouldValidatePasswordComplexity_OnRegistration() throws Exception {
    String[] invalidPasswords = {"Short1!", "nouppercase1!", "NoDigit!"};

    for (int i = 0; i < invalidPasswords.length; i++) {
      UserDto testUser = createUserDto("testuser" + i, invalidPasswords[i]);
      mockMvc
          .perform(
              post("/api/auth/register")
                  .contentType(MediaType.APPLICATION_JSON)
                  .content(objectMapper.writeValueAsString(testUser)))
          .andExpect(status().isBadRequest());
    }
  }

  @Test
  void shouldCheckUsername_Availability() throws Exception {
    UserDto testUser = createUserDto(TEST_USERNAME, TEST_PASSWORD);
    registerUser(testUser);

    mockMvc
        .perform(get("/api/auth/check-username").param("username", "testuser"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.exists").value(true));

    mockMvc
        .perform(get("/api/auth/check-username").param("username", "nonexistent"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.exists").value(false));
  }
}
