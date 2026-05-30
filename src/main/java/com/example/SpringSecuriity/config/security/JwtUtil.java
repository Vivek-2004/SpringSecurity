package com.example.SpringSecuriity.config.security;

import com.example.SpringSecuriity.entity.Role;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiry}")
    private Long expiration;

    private SecretKey getSecretKey() {
        byte[] bytes = secret.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(bytes);
    }

    private String createToken(Map<String, Object> claims) {
        return Jwts.builder()
                .claims(claims)
                .subject(claims.get("email").toString())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSecretKey())
                .compact();
    }

    public String generateToken(String email, Set<Role> roles) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("email", email);
        claims.put("roles", roles.stream().map(Role::name).collect(Collectors.toList()));
        return createToken(claims);
    }

    public Claims extractClaims(String token) throws JwtException {
        try {
            return Jwts.parser().verifyWith(getSecretKey()).build().parseSignedClaims(token).getPayload();
        } catch (SignatureException e) {
            throw new JwtException("Invalid JWT signature");
        } catch (MalformedJwtException e) {
            throw new JwtException("Invalid JWT token");
        } catch (ExpiredJwtException e) {
            throw new JwtException("Expired JWT token");
        } catch (UnsupportedJwtException e) {
            throw new JwtException("Unsupported JWT token");
        } catch (Exception e) {
            throw new JwtException("Invalid JWT token. Some unknown error happened.");
        }
    }

    public String extractEmailFromClaims(String token) {
        return extractClaims(token).get("email").toString();
    }

    public Date extractExpiration(String token) {
        return extractClaims(token).getExpiration();
    }

    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        try {
            String email = extractEmailFromClaims(token);
            boolean isTokenExpired = isTokenExpired(token);
            boolean userNameMatches = email.equals(userDetails.getUsername());
            return userNameMatches && isTokenExpired;
        } catch (Exception e) {
            return false;
        }
    }

}