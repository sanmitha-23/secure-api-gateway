package dev.securegateway.secure_api_gateway.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;

@Component
public class JwtUtil {
    private final SecretKey signingKey;
    private final long expirationMillis;

    public JwtUtil(@Value("${security.jwt.secret}") String signingKey,
                   @Value("${security.jwt.expiration-ms}") long duration) {
        this.signingKey = Keys.hmacShaKeyFor(signingKey.getBytes());
        this.expirationMillis = duration;
    }

    public String generateToken(String username) {
        Date expirationDate = new Date(System.currentTimeMillis() + expirationMillis);
        return Jwts.builder().subject(username)
                .issuedAt(Date.from(Instant.now()))
                .expiration(expirationDate)
                .signWith(signingKey)
                .compact();
    }

    public String extractUsername(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }
}
