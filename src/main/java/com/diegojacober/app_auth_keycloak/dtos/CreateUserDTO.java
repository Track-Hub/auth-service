package com.diegojacober.app_auth_keycloak.dtos;

import java.util.List;

import com.diegojacober.app_auth_keycloak.domain.entities.Credentials;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class CreateUserDTO {

    @NotNull(message = "Preencha o campo attributes")
    private Attributes attributes;

    @NotNull(message = "Preencha o campo credentials")
    private List<Credentials> credentials;

    @NotNull(message = "Preencha o campo username")
    private String username;

    @NotNull(message = "Preencha o campo firstName")
    private String firstName;

    @NotNull(message = "Preencha o campo lastName")
    private String lastName;

    @NotNull(message = "Preencha o campo email")
    private String email;

   @NotNull(message = "Preencha o campo emailVerified") 
    private boolean emailVerified;

    @NotNull(message = "Preencha o campo enabled")
    private boolean enabled;
}