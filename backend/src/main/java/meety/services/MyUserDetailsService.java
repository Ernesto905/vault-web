package meety.services;

import meety.models.User;
import meety.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class MyUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    /**
     * Loads the user's data given a username.
     *
     * This method is called by Spring Security during the authentication process.
     * It retrieves the user from the database and converts it into a UserDetails object
     * that Spring Security can use internally.
     *
     * @param username The username of the user trying to authenticate.
     * @return UserDetails object containing username, hashed password, and authorities (roles).
     * @throws UsernameNotFoundException if no user with the given username is found.
     *
     * Detailed explanation:
     *
     * 1. The method queries the UserRepository to find a User entity by username.
     *    If no User is found, it throws UsernameNotFoundException, which signals to Spring Security that authentication should fail.
     *
     * 3. If a User is found, the method returns an instance of Spring Security's UserDetails implementation.
     *
     *    - This UserDetails object includes:
     *      a) username: used as the identity in the security context.
     *      b) password: the hashed password stored in the database (e.g. BCrypt hash).
     *      c) authorities: a list of granted roles or permissions, prefixed with "ROLE_"
     *         because Spring Security expects roles to follow this naming convention.
     *
     * 4. Spring Security uses this UserDetails object internally during authentication:
     *    - It compares the supplied plaintext password (from the login request)
     *      with the stored hashed password using a PasswordEncoder.
     *    - If they match, the authentication is successful and the user is considered authenticated.
     *
     * 5. This abstraction (UserDetails) decouples the domain User entity
     *    from Spring Security's internal representation, allowing flexibility.
     *
     * Note:
     * - The "ROLE_" prefix is a Spring Security convention for role-based authorities.
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .authorities(new SimpleGrantedAuthority("ROLE_" + user.getRole().toString()))
                .build();
    }
}
