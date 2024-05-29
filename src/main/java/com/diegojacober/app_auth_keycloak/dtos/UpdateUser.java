package com.diegojacober.app_auth_keycloak.dtos;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.util.*;

import com.diegojacober.app_auth_keycloak.domain.entities.Credentials;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class UpdateUser {
    private Map<String, String> attributes;

    private List<Credentials> credentials;

    private String username;

    private String firstName;

    private String lastName;

    private String email;

    private boolean emailVerified;

    private boolean enabled;
}