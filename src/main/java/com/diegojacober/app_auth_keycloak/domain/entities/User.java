package com.diegojacober.app_auth_keycloak.domain.entities;

import java.util.Arrays;

import lombok.Data;

@Data
public class User {
    private String id;
    private String username;
    private String firstName;
    private String lastName;
    private String email;
    private boolean emailVerified;
    private long createdTimestamp;
    private boolean enabled;
    private boolean totp;
    private String[] disableableCredentialTypes;
    private String[] requiredActions;
    private long notBefore;
    private Access access;

    // Getters e setters aqui

    @Override
    public String toString() {
        return "User{" +
                "id='" + id + '\'' +
                ", username='" + username + '\'' +
                ", firstName='" + firstName + '\'' +
                ", lastName='" + lastName + '\'' +
                ", email='" + email + '\'' +
                ", emailVerified=" + emailVerified +
                ", createdTimestamp=" + createdTimestamp +
                ", enabled=" + enabled +
                ", totp=" + totp +
                ", disableableCredentialTypes=" + Arrays.toString(disableableCredentialTypes) +
                ", requiredActions=" + Arrays.toString(requiredActions) +
                ", notBefore=" + notBefore +
                ", access=" + access +
                '}';
    }
}
