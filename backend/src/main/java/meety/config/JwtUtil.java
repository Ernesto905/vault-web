package meety.config;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import meety.models.User;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

/**
 * Utility class for creating and parsing JSON Web Tokens (JWT).
 *
 * <p>A JWT is a compact, URL-safe token format consisting of three parts: header, payload, and signature.
 * <ul>
 *   <li><b>Header:</b> contains metadata about the token, such as the signing algorithm (e.g., HS256) and token type.</li>
 *   <li><b>Payload:</b> contains <b>claims</b> — pieces of information about the user or the token itself.</li>
 *   <li><b>Signature:</b> cryptographic signature to ensure token integrity and authenticity.</li>
 * </ul></p>
 *
 * <p><b>Claims</b> are key-value pairs embedded inside the JWT payload that provide data such as:
 * <ul>
 *   <li><i>Registered claims</i> like <code>sub</code> (subject, often the username), <code>iat</code> (issued at), and <code>exp</code> (expiration time).</li>
 *   <li><i>Public claims</i> which can be custom, e.g. user roles, email, etc.</li>
 *   <li><i>Private claims</i> defined by your application for specific needs.</li>
 * </ul></p>
 *
 * <p>In this class, the "role" claim is a custom public claim used to store the user's role for authorization purposes.</p>
 *
 * <p>The token is cryptographically signed using the secret key to ensure its integrity and authenticity.</p>
 */

@Component
public class JwtUtil {

    /**
     * Secret key used for signing the JWT.
     * Generated using HS256 (HMAC with SHA-256) algorithm.
     */
    private final SecretKey SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    private final long EXPIRATION_TIME = 1000 * 60 * 60;

    /**
     * Generates a signed JWT token for the given user.
     * The token is signed with the {@link #SECRET_KEY} using HS256.</p>
     *
     * @param user the user entity containing username and role
     * @return a signed JWT token string
     */
    public String generateToken(User user) {
        return Jwts.builder()
                .setSubject(user.getUsername())                             // set "sub" claim
                .claim("role", user.getRole().toString())                // add custom "role" claim
                .setIssuedAt(new Date())                                    // current time as issue date
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))  // expiry time
                .signWith(SECRET_KEY)                                       // sign token with secret key
                .compact();                                                 // build token string
    }

    /**
     * Extracts the username (subject) from the provided JWT token.
     *
     * <p>This method also validates the token's signature using the {@link #SECRET_KEY}.
     * If the token is invalid or expired, parsing will throw an exception.</p>
     *
     * @param token the JWT token string
     * @return the username (subject) embedded in the token
     * @throws io.jsonwebtoken.JwtException if token parsing or validation fails
     */
    public String extractUsername(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)    // set key to verify signature
                .build()
                .parseClaimsJws(token)        // parse and validate token
                .getBody()
                .getSubject();                // extract "sub" claim (username)
    }
}
