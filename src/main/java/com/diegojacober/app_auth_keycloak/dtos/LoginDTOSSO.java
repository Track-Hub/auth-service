package com.diegojacober.app_auth_keycloak.dtos;

import com.diegojacober.app_auth_keycloak.dtos.enums.Role;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class LoginDTOSSO {

    @NotNull(message = "Preencha o campo username")
    @Size(max = 32, message = "O username deve ter no máximo 32 caracteres")
    private String username;

    @NotNull(message = "Preencha o campo email")
    @Size(max = 32, message = "O email deve ter no máximo 32 caracteres")
    private String email;
    
    @NotNull(message = "Preencha o campo firstName")
    @Size(max = 32, message = "O firstName deve ter no máximo 32 caracteres")
    private String firstName;

    @NotNull(message = "Preencha o campo lastName")
    @Size(max = 32, message = "O lastName deve ter no máximo 32 caracteres")
    private String lastName;

    @NotNull(message = "Insira uma permissão válida")
    private Role role;
}
