package com.diegojacober.app_auth_keycloak;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.openfeign.EnableFeignClients;

import com.diegojacober.app_auth_keycloak.config.AuthServiceConfigurationProperties;

@EnableFeignClients
@SpringBootApplication
@EnableConfigurationProperties(AuthServiceConfigurationProperties.class)
public class AppAuthKeycloakApplication {

	public static void main(String[] args) {
		SpringApplication.run(AppAuthKeycloakApplication.class, args);
	}

}
