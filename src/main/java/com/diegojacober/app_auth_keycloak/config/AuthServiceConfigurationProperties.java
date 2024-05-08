package com.diegojacober.app_auth_keycloak.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Primary;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@ConfigurationProperties("auth-service")
public class AuthServiceConfigurationProperties {
    private CorsProperties cors = new CorsProperties();
    private AzureProperties azure = new AzureProperties();

    @Getter
    @Setter
    public static class AzureProperties {
        private String tenantId = "";
        private String clientId = "";
        private GraphProperties graph = new GraphProperties();

        @Getter
        @Setter
        public static class GraphProperties {

            private ProxyCredentials proxy = new ProxyCredentials();

            @Getter
            @Setter
            public static class ProxyCredentials {
                private boolean enable = false;
                private String host = "";
                private String port = "";
                private String username = "";
                private String password = "";
            }
        }
    }

    @Getter
    @Setter
    public static class CorsProperties {
        private boolean enable = false;
        private String[] allowedOrigins = {};
        private String[] allowedHeaders = {};
    }

}
