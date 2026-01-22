package vaultWeb.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.Cookie;
import vaultWeb.dtos.user.ChangePasswordRequest;
import vaultWeb.dtos.user.UserDto;
import vaultWeb.models.User;
import vaultWeb.repositories.UserRepository;
import vaultWeb.security.JwtUtil;

class UserControllerIntegrationTest extends IntegrationTestBase {

  // ============================================================================
  // Test Utility Methods
  // ============================================================================
  @Autowired private MockMvc mockMvc;
  @Autowired private ObjectMapper objectMapper;
  @Autowired private UserRepository userRepository;
  @Autowired private JwtUtil jwtUtil;

  private UserDto createUserDto(String username, String password) {
    UserDto dto = new UserDto();
    dto.setUsername(username);
    dto.setPassword(password);
    return dto;
  }

  private Cookie extractCookie(MvcResult result, String cookieName) {
    return result.getResponse().getCookie(cookieName);
  }

  private String extractTokenFromResponse(MvcResult result) throws Exception {
    String json = result.getResponse().getContentAsString();
    JsonNode node = objectMapper.readTree(json);
    return node.get("token").asText();
  }

  private String authHeader(String token) {
    return "Bearer " + token;
  }

  private void registerUser(UserDto testUser) throws Exception {
    mockMvc
        .perform(
            post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(testUser)))
        .andExpect(status().isOk())
        .andExpect(content().string("User registered successfully"));
  }

  private MvcResult loginUser(UserDto testUser)throws Exception{

      return mockMvc.perform(
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
    UserDto testUser = createUserDto("testuser", "TestPassword1!");

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
    UserDto testUser = createUserDto("testuser", "TestPassword1!");
    registerUser(testUser);
    mockMvc
        .perform(
            post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(testUser)))
        .andExpect(status().isConflict())
        .andExpect(content().string("Registration error: Username 'testuser' is already taken"));

    assertTrue(userRepository.findByUsername(testUser.getUsername()).isPresent());
  }

  @Test
  void shouldLogin_WithValidCredentials() throws Exception {
    // Register a user first
    UserDto testUser = createUserDto("testuser", "TestPassword1!");
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
        30 * 24 * 60 * 60,
        refreshTokenCookie.getMaxAge(),
        "refresh_token should expire in 30 days");
  }

  // ============================================================================
  // Stage 3: JWT Token Integration (4 tests)
  // ============================================================================

  @Test
  void shouldGenerateValidJwtToken_OnLogin() throws Exception {
    UserDto testUser = createUserDto("testuser", "TestPassword1!");
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
    UserDto testUser = createUserDto("testuser", "TestPassword1!");
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
        .andExpect(content().json("[{\"username\":\"testuser\"}]"));
  }

  @Test
  void shouldReject_WithInvalidToken_UsingRestTemplate() {
    // Test with RestTemplate to verify real HTTP behavior
    org.springframework.http.HttpHeaders headers = new org.springframework.http.HttpHeaders();
    headers.set("Authorization", authHeader("invalid_token"));
    org.springframework.http.HttpEntity<String> entity =
        new org.springframework.http.HttpEntity<>(headers);

    org.springframework.http.ResponseEntity<String> response =
        restTemplate.exchange(
            "http://localhost:" + port + "/api/auth/users",
            org.springframework.http.HttpMethod.GET,
            entity,
            String.class);

    assertEquals(org.springframework.http.HttpStatus.UNAUTHORIZED, response.getStatusCode());
  }

  @Test
  void shouldReject_WithMissingToken() throws Exception {
    org.springframework.http.HttpHeaders headers = new org.springframework.http.HttpHeaders();

    org.springframework.http.HttpEntity<String> entity =
        new org.springframework.http.HttpEntity<>(headers);

    org.springframework.http.ResponseEntity<String> response =
        restTemplate.exchange(
            "http://localhost:" + port + "/api/auth/users",
            org.springframework.http.HttpMethod.GET,
            entity,
            String.class);

    assertEquals(org.springframework.http.HttpStatus.UNAUTHORIZED, response.getStatusCode());
  }

  @Test
  void shouldReject_WithExpiredToken() throws Exception {
    // Register a user first
    UserDto testUser = createUserDto("testuser", "TestPassword1!");
    registerUser(testUser);

    // Get the user from database to generate expired token
    User savedUser = userRepository.findByUsername(testUser.getUsername()).get();

    // Generate an expired token (expired 1 hour ago)
    String expiredToken = jwtUtil.generateTokenWithExpiration(savedUser, -60 * 60 * 1000);

    // Try to access protected endpoint with expired token using RestTemplate
    org.springframework.http.HttpHeaders headers = new org.springframework.http.HttpHeaders();
    headers.set("Authorization", authHeader(expiredToken));
    org.springframework.http.HttpEntity<String> entity =
        new org.springframework.http.HttpEntity<>(headers);

    org.springframework.http.ResponseEntity<String> response =
        restTemplate.exchange(
            "http://localhost:" + port + "/api/auth/users",
            org.springframework.http.HttpMethod.GET,
            entity,
            String.class);

    assertEquals(org.springframework.http.HttpStatus.UNAUTHORIZED, response.getStatusCode());
  }

  // ============================================================================
  // Stage 4: Refresh Token Flow (4 tests)
  // ============================================================================

  @Test
  void shouldRefreshAccessToken_WithValidRefreshToken() throws Exception {
    UserDto testUser = createUserDto("testuser", "TestPassword1!");
    registerUser(testUser);
    MvcResult result = loginUser(testUser);
    String refreshToken = extractCookie(result, "refresh_token").getValue();
    result= mockMvc
        .perform(post("/api/auth/refresh").cookie(new Cookie("refresh_token", refreshToken)))
        .andExpect(status().isOk())
          .andExpect(jsonPath("$.token").exists())
          .andReturn();
  //should verify the refresh token has been sent with the cookie
  Cookie newRefreshToken = extractCookie(result, "refresh_token");
  assertNotNull(newRefreshToken, "New refresh token should be set");
  assertTrue(newRefreshToken.getValue().length() > 0, "New refresh token should have a value");
  assertTrue(!newRefreshToken.getValue().equals(refreshToken), "Refresh token should be rotated");
  //should verify the refresh token has been revoked
  assertTrue(refreshTokenRepository.findByTokenIdAndRevokedFalse(refreshToken).isEmpty());
  }

  @Test
  void shouldRejectRefresh_WithRevokedToken() throws Exception {
    UserDto testUser = createUserDto("testuser", "TestPassword1!");
    registerUser(testUser);
    MvcResult result = loginUser(testUser);
    String refreshToken = extractCookie(result, "refresh_token").getValue();
    result= mockMvc
        .perform(post("/api/auth/refresh").cookie(new Cookie("refresh_token", refreshToken)))
        .andExpect(status().isOk())
          .andExpect(jsonPath("$.token").exists())
          .andReturn();

    mockMvc
        .perform(post("/api/auth/refresh").cookie(new Cookie("refresh_token", refreshToken)))
        .andExpect(status().isUnauthorized());
    assertTrue(refreshTokenRepository.findByTokenIdAndRevokedFalse(refreshToken).isEmpty());
  }

  @Test
  void shouldRejectRefresh_WithInvalidToken() throws Exception {
    UserDto testUser = createUserDto("testuser", "TestPassword1!");
    registerUser(testUser);
    MvcResult result = loginUser(testUser);
    String refreshToken = extractCookie(result, "refresh_token").getValue();
    mockMvc
        .perform(post("/api/auth/refresh").cookie(new Cookie("refresh_token", "invalid_token")))
        .andExpect(status().isUnauthorized());
    assertTrue(refreshTokenRepository.findByTokenIdAndRevokedFalse(refreshToken).isEmpty());
  }

  @Test
  void shouldLogout_AndRevokeRefreshToken() throws Exception {
    UserDto testUser = createUserDto("testuser", "TestPassword1!");
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

  // ==================== Stage 5: Spring Security Integration ====================

  @Test
  void shouldChangePassword_WithValidCurrentPassword() throws Exception {

    UserDto testUser = createUserDto("testuser", "TestPassword1!");
    registerUser(testUser);
    MvcResult result = loginUser(testUser);
    String token = extractTokenFromResponse(result);
    ChangePasswordRequest changePasswordRequest = new ChangePasswordRequest();
    changePasswordRequest.setCurrentPassword("TestPassword1!");
    changePasswordRequest.setNewPassword("NewPassword1!");

        mockMvc 
            .perform(post("/api/auth/change-password").header("Authorization", authHeader(token)).contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(changePasswordRequest)))
            .andExpect(status().isNoContent()).andReturn();

    
    testUser.setPassword("NewPassword1!");
    result = loginUser(testUser);
    String newToken = extractTokenFromResponse(result);
    assertTrue(jwtUtil.validateToken(newToken), "New password should work for login");

    testUser.setPassword("TestPassword1!");
    mockMvc
        .perform(
            post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(testUser)))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void shouldRejectChangePassword_WithWrongCurrentPassword() throws Exception {
    UserDto testUser = createUserDto("testuser", "TestPassword1!");
    registerUser(testUser);
    MvcResult result = loginUser(testUser);
    String token = extractTokenFromResponse(result);
    ChangePasswordRequest changePasswordRequest = new ChangePasswordRequest();
    changePasswordRequest.setCurrentPassword("TestPassword2!");
    changePasswordRequest.setNewPassword("NewPassword1!");
    mockMvc
    .perform(post("/api/auth/change-password").header("Authorization", authHeader(token)).contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(changePasswordRequest)))
    .andExpect(status().isUnauthorized());
  }

  // ==================== Stage 6: Full E2E Scenarios ====================

  @Test
  void shouldCompleteFullAuthenticationFlow() throws Exception {
    
    UserDto testUser = createUserDto("testuser", "TestPassword1!");
    registerUser(testUser);
    MvcResult result = loginUser(testUser);
    String token = extractTokenFromResponse(result);
    String refreshToken = extractCookie(result, "refresh_token").getValue();
    
    mockMvc
    .perform(get("/api/auth/users").header("Authorization", authHeader(token)))
    .andExpect(status().isOk())
    .andExpect(content().json("[{\"username\":\"testuser\"}]"));
    
    result = mockMvc
    .perform(post("/api/auth/refresh").cookie(new Cookie("refresh_token", refreshToken)))
    .andExpect(status().isOk())
    .andExpect(jsonPath("$.token").exists())
    .andReturn();
    String newToken = extractTokenFromResponse(result);
    assertTrue(jwtUtil.validateToken(newToken), "New token should work for refresh");
    
    mockMvc
    .perform(post("/api/auth/logout").cookie(new Cookie("refresh_token", refreshToken)))
    .andExpect(status().isOk());
    assertTrue(refreshTokenRepository.findByTokenIdAndRevokedFalse(refreshToken).isEmpty());
    
    mockMvc
    .perform(post("/api/auth/refresh").cookie(new Cookie("refresh_token", refreshToken)))
    .andExpect(status().isUnauthorized());
  
  }

  @Test
  void shouldHandleMultipleSessions_PerUser() throws Exception {
    // Register user
    UserDto testUser = createUserDto("testuser", "TestPassword1!");
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
    User user = userRepository.findByUsername("testuser").orElseThrow();
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
    String[] invalidPasswords = {
      "Short1!",
      "nouppercase1!",
      "NoDigit!",
      "NoSpecial1"
    };

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
    UserDto testUser = createUserDto("testuser", "TestPassword1!");
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
