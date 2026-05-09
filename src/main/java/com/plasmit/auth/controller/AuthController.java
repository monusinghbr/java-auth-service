package com.plasmit.auth.controller;

import com.plasmit.auth.common.ApiResponse;
import com.plasmit.auth.dto.request.LoginRequest;
import com.plasmit.auth.dto.response.LoginResponse;
import com.plasmit.auth.security.TenantContext;
import com.plasmit.auth.service.AuthService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public ApiResponse<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        log.info("Auth login API called for email={}", request.getEmail());
        return ApiResponse.success("Login successful", authService.login(request));
    }

    @GetMapping("/me")
    public ApiResponse<LoginResponse.AuthUserResponse> me(Authentication authentication) {
        Long userId = Long.valueOf(String.valueOf(authentication.getPrincipal()));

        log.debug("Current user API called. userId={}, tenantId={}",
                userId, TenantContext.getTenantId());

        return ApiResponse.success("Current user fetched", authService.getCurrentUser(userId));
    }

    @PostMapping("/logout")
    public ApiResponse<Object> logout() {
        log.info("Logout API called. userId={}, tenantId={}",
                TenantContext.getUserId(), TenantContext.getTenantId());

        return ApiResponse.success("Logged out successfully", null);
    }

    @PostMapping("/mfa/verify")
    public ApiResponse<Object> verifyMfa() {
        log.info("MFA verify API called. userId={}", TenantContext.getUserId());

        return ApiResponse.success("MFA verified", null);
    }
    @GetMapping("/encode-password")
    public String encodePassword(@RequestParam String password) {
        return new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder(12)
                .encode(password);
    }
}
