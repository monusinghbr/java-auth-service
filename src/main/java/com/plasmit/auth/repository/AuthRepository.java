package com.plasmit.auth.repository;

import com.plasmit.auth.dto.response.LoginResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public class AuthRepository {

    private static final Logger log = LoggerFactory.getLogger(AuthRepository.class);

    private final NamedParameterJdbcTemplate jdbcTemplate;

    public AuthRepository(NamedParameterJdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public Optional<AuthUserRow> findByEmail(String email) {
        String sql = """
                SELECT
                    u.id,
                    u.tenant_id,
                    u.full_name AS name,
                    u.email,
                    u.password_hash,
                    COALESCE(r.role_code, u.role_code) AS role_code,
                    u.user_type,
                    false AS mfa_enabled,
                    u.status
                FROM users u
                LEFT JOIN user_roles ur
                       ON ur.user_id = u.id
                      AND ur.tenant_id = u.tenant_id
                LEFT JOIN roles r
                       ON r.id = ur.role_id
                      AND r.is_deleted = 0
                      AND r.status = 'ACTIVE'
                WHERE u.email = :email
                  AND u.is_deleted = 0
                LIMIT 1
                """;

        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("email", email);

        try {
            AuthUserRow user = jdbcTemplate.queryForObject(sql, params, (rs, rowNum) ->
                    new AuthUserRow(
                            rs.getLong("id"),
                            rs.getObject("tenant_id") == null ? null : rs.getLong("tenant_id"),
                            rs.getString("name"),
                            rs.getString("email"),
                            rs.getString("password_hash"),
                            rs.getString("role_code"),
                            rs.getString("user_type"),
                            rs.getBoolean("mfa_enabled"),
                            rs.getString("status")
                    )
            );

            return Optional.ofNullable(user);

        } catch (EmptyResultDataAccessException ex) {
            log.warn("User not found for email={}", email);
            return Optional.empty();
        }
    }

    public Optional<LoginResponse.AuthUserResponse> findCurrentUserById(Long userId) {
        String sql = """
                SELECT
                    u.id,
                    u.tenant_id,
                    u.full_name AS name,
                    u.email,
                    COALESCE(r.role_code, u.role_code) AS role_code,
                    u.user_type
                FROM users u
                LEFT JOIN user_roles ur
                       ON ur.user_id = u.id
                      AND ur.tenant_id = u.tenant_id
                LEFT JOIN roles r
                       ON r.id = ur.role_id
                      AND r.is_deleted = 0
                      AND r.status = 'ACTIVE'
                WHERE u.id = :userId
                  AND u.status = 'ACTIVE'
                  AND u.is_deleted = 0
                LIMIT 1
                """;

        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("userId", userId);

        try {
            LoginResponse.AuthUserResponse user = jdbcTemplate.queryForObject(sql, params, (rs, rowNum) ->
                    new LoginResponse.AuthUserResponse(
                            rs.getLong("id"),
                            rs.getObject("tenant_id") == null ? null : rs.getLong("tenant_id"),
                            rs.getString("name"),
                            rs.getString("email"),
                            rs.getString("role_code"),
                            rs.getString("user_type")
                    )
            );

            return Optional.ofNullable(user);

        } catch (EmptyResultDataAccessException ex) {
            log.warn("Current user not found for id={}", userId);
            return Optional.empty();
        }
    }

    public void updateLastLoginAt(Long userId) {
        String sql = """
                UPDATE users
                SET last_login_at = NOW(),
                    updated_at = NOW()
                WHERE id = :userId
                """;

        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("userId", userId);

        int updated = jdbcTemplate.update(sql, params);
        log.debug("Last login updated for userId={}, affectedRows={}", userId, updated);
    }

    public static class AuthUserRow {

        private Long id;
        private Long tenantId;
        private String name;
        private String email;
        private String passwordHash;
        private String roleCode;
        private String userType;
        private boolean mfaEnabled;
        private String status;

        public AuthUserRow(Long id, Long tenantId, String name, String email, String passwordHash,
                           String roleCode, String userType, boolean mfaEnabled, String status) {
            this.id = id;
            this.tenantId = tenantId;
            this.name = name;
            this.email = email;
            this.passwordHash = passwordHash;
            this.roleCode = roleCode;
            this.userType = userType;
            this.mfaEnabled = mfaEnabled;
            this.status = status;
        }

        public Long getId() {
            return id;
        }

        public Long getTenantId() {
            return tenantId;
        }

        public String getName() {
            return name;
        }

        public String getEmail() {
            return email;
        }

        public String getPasswordHash() {
            return passwordHash;
        }

        public String getRoleCode() {
            return roleCode;
        }

        public String getUserType() {
            return userType;
        }

        public boolean isMfaEnabled() {
            return mfaEnabled;
        }

        public String getStatus() {
            return status;
        }
    }
}
