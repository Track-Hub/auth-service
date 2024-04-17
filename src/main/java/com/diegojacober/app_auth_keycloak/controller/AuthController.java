package com.diegojacober.app_auth_keycloak.controller;

import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.diegojacober.app_auth_keycloak.dtos.LoginDTO;
import com.diegojacober.app_auth_keycloak.dtos.RefreshDTO;
import com.diegojacober.app_auth_keycloak.dtos.RequestNewRoleDTO;
import com.diegojacober.app_auth_keycloak.dtos.RoleDTO;
import com.diegojacober.app_auth_keycloak.dtos.enums.Role;
import com.diegojacober.app_auth_keycloak.exceptions.IncorrectBodyException;
import com.diegojacober.app_auth_keycloak.exceptions.IncorrectCredentialsException;
import com.diegojacober.app_auth_keycloak.infra.OpenFeign.AuthServiceClient;

import feign.FeignException;
import jakarta.validation.Valid;

@RequestMapping("/auth")
@RestController
public class AuthController {

    @Autowired
    private AuthServiceClient authServiceClient;

    @PostMapping("/login")
    public ResponseEntity<String> accessToken(@RequestBody @Valid LoginDTO user) throws IncorrectCredentialsException {

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("client_id", "trackhub");
        formData.add("username", user.getUsername());
        formData.add("password", user.getPassword());
        formData.add("grant_type", "password");
        formData.add("client_secret", "gJSYrFwjBbc9mPA7uYbh1SDaf7TVXWIl");
        formData.add("scope", "openid profile email");

        try {
            return authServiceClient.getToken(formData);
        } catch (FeignException.Unauthorized ex) {
            throw new IncorrectCredentialsException("Credenciais incorretas.");
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<String> refreshToken(@RequestBody @Valid RefreshDTO dto)
            throws IncorrectCredentialsException {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("client_id", "trackhub");
        formData.add("refresh_token", dto.getRefresh_token());
        formData.add("grant_type", "refresh_token");
        formData.add("client_secret", "gJSYrFwjBbc9mPA7uYbh1SDaf7TVXWIl");
        formData.add("scope", "openid profile email");

        try {
            return authServiceClient.getToken(formData);
        } catch (FeignException.Unauthorized ex) {
            throw new IncorrectCredentialsException("Credenciais incorretas.");
        } catch (FeignException.FeignClientException ex) {
            throw new IncorrectCredentialsException("Credenciais incorretas.");
        }
    }

    @GetMapping("/userinfo")
    public Object getUserInfo() throws IncorrectCredentialsException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Jwt user = (Jwt) authentication.getPrincipal();

        String token = user.getTokenValue();

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("client_id", "trackhub");
        formData.add("scope", "openid");
        formData.add("grant_type", "client_credentials");
        formData.add("client_secret", "gJSYrFwjBbc9mPA7uYbh1SDaf7TVXWIl");

        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, ("Bearer " + token));

        try {
            return authServiceClient.getUserInfo(formData, headers);
        } catch (FeignException.Unauthorized ex) {
            throw new IncorrectCredentialsException("Credenciais incorretas.");
        }
    }

    @GetMapping("/users")
    @PreAuthorize("hasRole('instructor')")
    public Object getUsers(@RequestHeader HttpHeaders headers, @RequestParam String q)
            throws IncorrectCredentialsException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Jwt user = (Jwt) authentication.getPrincipal();

        String token = user.getTokenValue();

        headers.add(HttpHeaders.AUTHORIZATION, ("Bearer " + token));

        try {
            return authServiceClient.getUsers(headers, q);
        } catch (FeignException.Unauthorized ex) {
            throw new IncorrectCredentialsException("Credenciais incorretas.");
        }
    }

    @GetMapping("/users/{userId}/roles")
    @PreAuthorize("hasRole('instructor')")

    public Object getUserRoles(@PathVariable String userId) throws IncorrectCredentialsException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Jwt user = (Jwt) authentication.getPrincipal();
        String token = user.getTokenValue();
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, ("Bearer " + token));

        try {
            return authServiceClient.getUserRoles(userId, headers);
        } catch (FeignException.Unauthorized ex) {
            throw new IncorrectCredentialsException("Credenciais incorretas.");
        }
    }

    @PostMapping("/users/{userId}/roles")
    @PreAuthorize("hasRole('instructor')")
    public Object postUserRole(@PathVariable String userId, @RequestBody @Valid RequestNewRoleDTO dto)
            throws IncorrectBodyException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Jwt user = (Jwt) authentication.getPrincipal();
        String token = user.getTokenValue();
        HttpHeaders headers = new HttpHeaders();

        System.out.println(dto.getRole());
        String idRole = "";
        if (dto.getRole().equals(Role.APPRENTICE)) {
            // idRole = "257afb7f-7930-4dd3-a768-ffef905767db";
            idRole = "79234a79-b534-44fa-991c-575b9900998b";
        } else if (dto.getRole().equals(Role.INSTRUCTOR)) {
            // idRole = "47aaded2-ad99-43e5-b222-60be9449586d";
            idRole = "5c17ade7-0bfd-4604-9a0a-7637a23e45f2";
        }

        RoleDTO roleDTO = RoleDTO.builder()
                .composite(false)
                .clientRole(true)
                .name(dto.getRole().toString())
                .id(idRole)
                .containerId("d0bdc3b3-30be-4881-b7d9-9744cb26ed47")
                .build();
        try {

            headers.add(HttpHeaders.AUTHORIZATION, ("Bearer " + token));
            List<RoleDTO> roles = Arrays.asList(roleDTO);
            return authServiceClient.postUserRoles(userId, headers, roles);
        } catch (FeignException ex) {
            System.out.println(ex.getMessage());
            throw new IncorrectBodyException("campos inválidos");
        }
    }

    @GetMapping("/roles")
    @PreAuthorize("hasRole('instructor')")
    public Object getRoles() throws IncorrectCredentialsException {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Jwt user = (Jwt) authentication.getPrincipal();

            String token = user.getTokenValue();
            HttpHeaders headers = new HttpHeaders();
            headers.add(HttpHeaders.AUTHORIZATION, ("Bearer " + token));
            return authServiceClient.getClientRoles(headers);
        } catch (FeignException.Unauthorized ex) {
            throw new IncorrectCredentialsException("Credenciais incorretas.");
        }
    }

    @GetMapping("/users/{role}")
    @PreAuthorize("hasRole('instructor')")
    public Object getUsersByRole(@PathVariable String role) throws IncorrectCredentialsException {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Jwt user = (Jwt) authentication.getPrincipal();
            String token = user.getTokenValue();
            HttpHeaders headers = new HttpHeaders();
            headers.add(HttpHeaders.AUTHORIZATION, ("Bearer " + token));
            return authServiceClient.getUsersByRole(role, headers);
        } catch (FeignException.Unauthorized ex) {
            throw new IncorrectCredentialsException("Credenciais incorretas.");
        }
    }

}