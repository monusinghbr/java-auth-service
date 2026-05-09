package com.plasmit.auth.repository;

import com.plasmit.auth.dto.response.LoginResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;
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
                    u.hospital_id,
                    u.branch_id,
                    u.department_id,
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
                            rs.getObject("hospital_id") == null ? null : rs.getLong("hospital_id"),
                            rs.getObject("branch_id") == null ? null : rs.getLong("branch_id"),
                            rs.getObject("department_id") == null ? null : rs.getLong("department_id"),
                            rs.getString("name"),
                            rs.getString("email"),
                            rs.getString("password_hash"),
                            rs.getString("role_code"),
                            rs.getString("user_type"),
                            rs.getBoolean("mfa_enabled"),
                            rs.getString("status")
                    )
            );

            if (user != null) {
                user.setPermissions(findPermissionsByUserId(user.getId()));
            }

            return Optional.ofNullable(user);

        } catch (EmptyResultDataAccessException ex) {
            log.warn("User not found for email={}", email);
            return Optional.empty();
        }
    }

    private List<String> findPermissionsByUserId(Long userId) {
        String sql = """
                SELECT DISTINCT p.permission_key
                FROM user_roles ur
                JOIN role_permissions rp
                  ON rp.role_id = ur.role_id
                 AND rp.tenant_id = ur.tenant_id
                JOIN permissions p
                  ON p.id = rp.permission_id
                 AND p.status = 'ACTIVE'
                WHERE ur.user_id = :userId
                ORDER BY p.permission_key
                """;

        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("userId", userId);

        return jdbcTemplate.query(sql, params, (rs, rowNum) -> rs.getString("permission_key"));
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
        private Long hospitalId;
        private Long branchId;
        private Long departmentId;
        private String name;
        private String email;
        private String passwordHash;
        private String roleCode;
        private String userType;
        private boolean mfaEnabled;
        private String status;
        private List<String> permissions = List.of();

        public AuthUserRow(Long id, Long tenantId, Long hospitalId, Long branchId, Long departmentId,
                           String name, String email, String passwordHash,
                           String roleCode, String userType, boolean mfaEnabled, String status) {
            this.id = id;
            this.tenantId = tenantId;
            this.hospitalId = hospitalId;
            this.branchId = branchId;
            this.departmentId = departmentId;
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

        public Long getHospitalId() {
            return hospitalId;
        }

        public Long getBranchId() {
            return branchId;
        }

        public Long getDepartmentId() {
            return departmentId;
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

        public List<String> getPermissions() {
            return permissions;
        }

        public void setPermissions(List<String> permissions) {
            this.permissions = permissions == null ? List.of() : permissions;
        }
    }
}
