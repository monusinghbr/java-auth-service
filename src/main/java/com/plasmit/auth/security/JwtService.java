package com.plasmit.auth.security;

import com.plasmit.auth.repository.AuthRepository.AuthUserRow;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Service
public class JwtService {

    private static final Logger log = LoggerFactory.getLogger(JwtService.class);

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.access-token-expiration-ms}")
    private Long accessTokenExpirationMs;

    @Value("${jwt.refresh-token-expiration-ms}")
    private Long refreshTokenExpirationMs;

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }

    public String generateAccessToken(AuthUserRow user) {
        log.debug("Generating access token for userId={}, tenantId={}", user.getId(), user.getTenantId());
        return generateToken(user, accessTokenExpirationMs, "ACCESS");
    }

    public String generateRefreshToken(AuthUserRow user) {
        log.debug("Generating refresh token for userId={}", user.getId());
        return generateToken(user, refreshTokenExpirationMs, "REFRESH");
    }

    private String generateToken(AuthUserRow user, Long expirationMs, String tokenType) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expirationMs);

        return Jwts.builder()
                .subject(String.valueOf(user.getId()))
                .claim("tokenType", tokenType)
                .claim("userId", user.getId())
                .claim("tenantId", user.getTenantId())
                .claim("hospitalId", user.getHospitalId())
                .claim("branchId", user.getBranchId())
                .claim("departmentId", user.getDepartmentId())
                .claim("name", user.getName())
                .claim("email", user.getEmail())
                .claim("role", user.getRoleCode())
                .claim("userType", user.getUserType())
                .claim("permissions", user.getPermissions())
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(getSigningKey())
                .compact();
    }

    public boolean isTokenValid(String token) {
        try {
            Claims claims = extractClaims(token);
            return claims.getExpiration().after(new Date());
        } catch (Exception ex) {
            log.warn("Invalid JWT token: {}", ex.getMessage());
            return false;
        }
    }

    public Long extractUserId(String token) {
        return Long.valueOf(extractClaims(token).getSubject());
    }

    public Long extractTenantId(String token) {
        Object tenantId = extractClaims(token).get("tenantId");

        if (tenantId == null) {
            return null;
        }

        if (tenantId instanceof Integer) {
            return ((Integer) tenantId).longValue();
        }

        if (tenantId instanceof Long) {
            return (Long) tenantId;
        }

        return Long.valueOf(String.valueOf(tenantId));
    }

    public String extractEmail(String token) {
        return extractClaims(token).get("email", String.class);
    }

    public String extractRole(String token) {
        return extractClaims(token).get("role", String.class);
    }

    public String extractUserType(String token) {
        return extractClaims(token).get("userType", String.class);
    }

    private Claims extractClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
