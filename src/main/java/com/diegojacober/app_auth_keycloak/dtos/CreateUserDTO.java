package com.diegojacober.app_auth_keycloak.dtos;

import java.util.List;

import com.diegojacober.app_auth_keycloak.domain.entities.Credentials;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class CreateUserDTO {
    private Attributes attributes;
    private List<Credentials> credentials;
    private String username;
    private String firstName;
    private String lastName;
    private String email;
    private boolean emailVerified;
    private boolean enabled;
}