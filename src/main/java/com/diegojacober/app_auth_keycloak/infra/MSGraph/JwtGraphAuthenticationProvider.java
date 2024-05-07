package com.diegojacober.app_auth_keycloak.infra.MSGraph;

import java.net.URL;
import java.util.concurrent.CompletableFuture;

import com.microsoft.graph.authentication.IAuthenticationProvider;

public class JwtGraphAuthenticationProvider implements IAuthenticationProvider {

    private CompletableFuture<String> accessTokenFuture;

    public JwtGraphAuthenticationProvider(String token) {
        this.accessTokenFuture = new CompletableFuture<>();
        this.accessTokenFuture.complete(token);
    }


    @Override
    public CompletableFuture<String> getAuthorizationTokenAsync(URL requestUrl) {
        return this.accessTokenFuture;
    }
}