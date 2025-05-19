package meety.services;

import meety.models.User;
import meety.repositories.UserRepository;
import meety.config.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class AuthService {
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserRepository userRepository;

    /**
     * Authenticates a user and returns a JWT token if successful.
     *
     * @param username The username provided by the client.
     * @param password The plaintext password provided by the client.
     * @return A JWT token containing user information and claims.
     *
     * Workflow:
     * 1. The AuthenticationManager handles credential validation (username and password).
     *    Internally, the password is checked against the stored hash.
     *    If invalid, an exception is thrown.
     *
     * 2. Upon successful authentication, an Authentication object is returned,
     *    containing the authenticated user's details (principal).
     *
     * 3. The Authentication object is stored in the SecurityContext,
     *    so Spring Security knows the user is currently authenticated.
     *
     * 4. UserDetails contains security-relevant user data (username, password hash, roles),
     *    but not necessarily all fields from the User entity.
     *
     * 5. To access full user information (e.g. role enum, additional fields),
     *    the User entity is loaded again from the database via the UserRepository.
     *
     * 6. A JWT token is generated using the full User object,
     *    including username and role claims,
     *    signed with HS256, and valid for 1 hour.
     *
     * Detailed explanation of authenticationManager.authenticate(...):
     *
     * - When you call:
     *   Authentication authentication = authenticationManager.authenticate(
     *       new UsernamePasswordAuthenticationToken(username, password)
     *   );
     *
     *   The following happens internally:
     *
     *   a) Spring Security detects the type UsernamePasswordAuthenticationToken
     *      and triggers a username-password authentication process.
     *
     *   b) It calls the UserDetailsService's loadUserByUsername(username) method,
     *      which loads the user details (including the stored password hash) from the DB.
     *
     *   c) Spring Security compares the plaintext password (from the token) with the stored hashed password
     *      using the configured PasswordEncoder (e.g. BCryptPasswordEncoder).
     *
     *   d) If the password matches, the authentication is successful.
     *      If not, a BadCredentialsException is thrown.
     *
     *   e) On success, Spring creates a fully authenticated Authentication object,
     *      including the principal (UserDetails) and authorities (roles).
     *
     * Notes:
     * - The password comparison is automatic, based on the PasswordEncoder bean.
     * - This process ensures your password is never stored or compared as plaintext.
     * The JWT token returned can then be used by clients in the Authorization header to access secured endpoints.
     *
     */
    public String login(String username, String password){
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        User user = userRepository.findByUsername(userDetails.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));

        return jwtUtil.generateToken(user);
    }
}
