package com.plasmit.auth.service.impl;

import com.plasmit.auth.dto.request.LoginRequest;
import com.plasmit.auth.dto.response.LoginResponse;
import com.plasmit.auth.repository.AuthRepository;
import com.plasmit.auth.security.JwtService;
import com.plasmit.auth.service.AuthService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthServiceImpl implements AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthServiceImpl.class);

    private final AuthRepository authRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;

    public AuthServiceImpl(AuthRepository authRepository,
                           JwtService jwtService,
                           PasswordEncoder passwordEncoder) {
        this.authRepository = authRepository;
        this.jwtService = jwtService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public LoginResponse login(LoginRequest request) {
        log.info("Login request received for email={}", request.getEmail());

        AuthRepository.AuthUserRow user = authRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> {
                    log.warn("Login failed. User not found. email={}", request.getEmail());
                    return new BadCredentialsException("Invalid email or password");
                });

        if (!"ACTIVE".equalsIgnoreCase(user.getStatus())) {
            log.warn("Login blocked. User inactive. userId={}, status={}", user.getId(), user.getStatus());
            throw new BadCredentialsException("User account is not active");
        }
        if (request.getPassword() == null || request.getPassword().isBlank()) {
            throw new BadCredentialsException("Password cannot be empty");
        }

        String rawPassword = request.getPassword().trim();
        if (!passwordEncoder.matches(rawPassword, user.getPasswordHash())) {
            log.warn("Login failed. Invalid password. userId={}", user.getId());
            throw new BadCredentialsException("Invalid email or password");
        }

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        authRepository.updateLastLoginAt(user.getId());

        LoginResponse.AuthUserResponse authUserResponse =
                new LoginResponse.AuthUserResponse(
                        user.getId(),
                        user.getTenantId(),
                        user.getName(),
                        user.getEmail(),
                        user.getRoleCode(),
                        user.getUserType()
                );

        log.info("Login successful. userId={}, tenantId={}, role={}",
                user.getId(), user.getTenantId(), user.getRoleCode());

        return new LoginResponse(
                accessToken,
                refreshToken,
                user.isMfaEnabled(),
                authUserResponse
        );
    }

    @Override
    public LoginResponse.AuthUserResponse getCurrentUser(Long userId) {
        log.debug("Fetching current user. userId={}", userId);

        return authRepository.findCurrentUserById(userId)
                .orElseThrow(() -> {
                    log.warn("Current user not found. userId={}", userId);
                    return new BadCredentialsException("User not found");
                });
    }
}
