package com.diegojacober.app_auth_keycloak.dtos;

import com.diegojacober.app_auth_keycloak.dtos.enums.Role;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class LoginDTOSSO {
    private String username;

    private String email;
    
    private String firstName;

    private String lastName;

    private Role role;
}
