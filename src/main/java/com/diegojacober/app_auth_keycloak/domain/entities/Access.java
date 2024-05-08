package com.diegojacober.app_auth_keycloak.domain.entities;

import lombok.Data;

@Data
public class Access {
    private boolean manageGroupMembership;
    private boolean view;
    private boolean mapRoles;
    private boolean impersonate;
    private boolean manage;

    // Getters e setters aqui

    @Override
    public String toString() {
        return "Access{" +
                "manageGroupMembership=" + manageGroupMembership +
                ", view=" + view +
                ", mapRoles=" + mapRoles +
                ", impersonate=" + impersonate +
                ", manage=" + manage +
                '}';
    }
}