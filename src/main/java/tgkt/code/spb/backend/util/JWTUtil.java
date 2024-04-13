package tgkt.code.spb.backend.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.annotation.Resource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Calendar;
import java.util.Date;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Component
public class JWTUtil {
    @Value("${spring.security.jwt.key}")
    String key;

    @Value("${spring.security.jwt.expires}")
    int expires;

    @Resource
    StringRedisTemplate template;

    public DecodedJWT resolveJWT(String headerToken) {
        String token = convertToken(headerToken);
        if (token == null) return null;

        var algorithm = Algorithm.HMAC256(key);
        JWTVerifier verifier = JWT.require(algorithm).build();
        try {
            DecodedJWT verify = verifier.verify(token);

            // Is token valid?
            if (isInvalidToken(verify.getId())) return null;

            // Is token expired?
            var expiresAt = verify.getExpiresAt();
            return new Date().after(expiresAt) ? null : verify;

        } catch (JWTVerificationException e) {
            return null;
        }
    }

    public String createJWT(UserDetails details, String userId, String username) {
        var algorithm = Algorithm.HMAC256(key);
        return JWT.create()
                .withJWTId(UUID.randomUUID().toString())
                .withClaim("id", userId)
                .withClaim("name", username)
                .withClaim("authorities",
                        details.getAuthorities().stream().map(
                                GrantedAuthority::getAuthority
                        ).toList())
                .withExpiresAt(this.expireTime())
                .withIssuedAt(new Date())
                .sign(algorithm);
    }

    public Date expireTime() {
        Calendar c = Calendar.getInstance();
        c.add(Calendar.HOUR, 24 * expires);
        return c.getTime();
    }

    private String convertToken(String header) {
        if (header == null || !header.startsWith("Bearer")) return null;
        return header.substring(7);
    }

    public UserDetails toUser(DecodedJWT jwt) {
        var claims = jwt.getClaims();
        return User.withUsername(claims.get("name").asString())
                .password("******")
                .authorities(claims.get("authorities").asArray(String.class))
                .build();
    }

    public String toId(DecodedJWT jwt) {
        return jwt.getClaims().get("id").asString();
    }

    public boolean invalidateJWT(String headerToken) {
        var token = convertToken(headerToken);
        if (token == null) return false;

        var algorithm = Algorithm.HMAC256(key);
        JWTVerifier verifier = JWT.require(algorithm).build();
        try {
            DecodedJWT jwt = verifier.verify(token);
            var jwtId = jwt.getId();
            return deleteToken(jwtId, jwt.getExpiresAt());
        } catch (JWTVerificationException e) {
            return false;
        }
    }

    private boolean deleteToken(String jwtId, Date time) {
        if (isInvalidToken(jwtId)) return false;

        long expire = Math.max(0, time.getTime() - new Date().getTime());
        template.opsForValue().set(Constant.PREFIX_JWT_BLACKLIST + jwtId,
                "", expire, TimeUnit.MILLISECONDS);
        return true;
    }

    private boolean isInvalidToken(String jwtId) {
        return Boolean.TRUE.equals(
                template.hasKey(
                        Constant.PREFIX_JWT_BLACKLIST
                                + jwtId
                ));
    }
}
