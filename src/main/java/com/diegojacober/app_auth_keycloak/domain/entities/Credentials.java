package com.diegojacober.app_auth_keycloak.domain.entities;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Credentials {
    private boolean temporary;
    private String type;
    private String value;
}
