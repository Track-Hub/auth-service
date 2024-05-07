package com.diegojacober.app_auth_keycloak.controller;

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.OkHttp3ClientHttpRequestFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.azure.core.http.HttpClient;
import com.azure.identity.OnBehalfOfCredential;
import com.azure.identity.OnBehalfOfCredentialBuilder;
import com.diegojacober.app_auth_keycloak.config.AuthServiceConfigurationProperties;
import com.diegojacober.app_auth_keycloak.dtos.CreateUserDTO;
import com.diegojacober.app_auth_keycloak.dtos.LoginDTO;
import com.diegojacober.app_auth_keycloak.dtos.LoginDTOSSO;
import com.diegojacober.app_auth_keycloak.dtos.RefreshDTO;
import com.diegojacober.app_auth_keycloak.dtos.RequestNewRoleDTO;
import com.diegojacober.app_auth_keycloak.dtos.RoleDTO;
import com.diegojacober.app_auth_keycloak.dtos.enums.Role;
import com.diegojacober.app_auth_keycloak.exceptions.IncorrectBodyException;
import com.diegojacober.app_auth_keycloak.exceptions.IncorrectCredentialsException;
import com.diegojacober.app_auth_keycloak.infra.MSGraph.JwtGraphAuthenticationProvider;
import com.diegojacober.app_auth_keycloak.infra.OpenFeign.AuthServiceClient;
import com.microsoft.graph.authentication.IAuthenticationProvider;
import com.microsoft.graph.authentication.TokenCredentialAuthProvider;
import com.microsoft.graph.models.User;
import com.microsoft.graph.serviceclient.GraphServiceClient;
import com.microsoft.graph.httpcore.HttpClients;

import feign.FeignException;
import jakarta.validation.Valid;
import okhttp3.OkHttpClient;

@RequestMapping("/auth")
@RestController
public class AuthController {

    @Autowired
    private AuthServiceClient authServiceClient;

    @Autowired
    private AuthServiceConfigurationProperties configurations;

    @PostMapping("/login")
    public ResponseEntity<String> accessToken(@RequestBody @Valid LoginDTO user) throws IncorrectCredentialsException {

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("client_id", "trackhub");
        formData.add("username", user.getUsername());
        formData.add("password", user.getPassword());
        formData.add("grant_type", "password");
        formData.add("client_secret", "gJSYrFwjBbc9mPA7uYbh1SDaf7TVXWIl");
        formData.add("scope", "openid profile email");

        try {
            return authServiceClient.getToken(formData);
        } catch (FeignException.Unauthorized ex) {
            throw new IncorrectCredentialsException("Credenciais incorretas.");
        }
    }

    @PostMapping("/login/sso")
    public String loginBoschUser(@RequestBody @Valid LoginDTOSSO userDto) {
        // tenho sso, vou acessar
        // se eu ja tenho usuario no keycloak, so faz login

        final IAuthenticationProvider jwtAuthenticationProvider = new JwtGraphAuthenticationProvider(
                userDto.getToken());

        // OkHttpClient.Builder builder =
        // HttpClients.createDefault(jwtAuthenticationProvider).newBuilder();
        OkHttpClient.Builder builder = HttpClients.createDefault(jwtAuthenticationProvider).newBuilder();

        if (configurations.getAzure().getGraph().getProxy().isEnable()) {
            builder.proxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress(
                    configurations.getAzure().getGraph().getProxy().getHost(),
                    Integer.parseInt(
                            configurations.getAzure().getGraph().getProxy().getPort()))));
        }

        final String[] scopes = new String[] {"https://graph.microsoft.com/.default"};
         
        // This is the incoming token to exchange using on-behalf-of flow
        final String oboToken = userDto.getToken();

         
        // final OnBehalfOfCredential credential = new OnBehalfOfCredentialBuilder()
        // .clientId("5daa006a-c35a-40d4-935b-81e49cbc1f2e")
        // .tenantId("0ae51e19-07c8-4e4b-bb6d-648ee58410f4")
        // .clientSecret("")
        //     .userAssertion(oboToken).build();

        final AzureIdentityAuthenticationProvider authenticationProvider =  new AzureIdentityAuthenticationProvider(credential, null, scopes);
         
        if (null == scopes || null == credential) {
            throw new Exception("Unexpected error");
        }
         
        final GraphServiceClient graphClient = new GraphServiceClient(credential, scopes);










        // GraphServiceClient.getGraphClientOptions()
        // .authenticationProvider(jwtAuthenticationProvider)
        // .httpClient(builder.build())
        // .buildClient();

        // final User user = graphServiceClient.me()
        // .buildRequest().get();

        // se eu nao tenho no keycloak, chama graph, pega os dados e salva no keycloak
        // pra verificar se não existe no keycloak, usar a rota /users?q=email:

        // - login sso
        // - recuperar o jwt do sso
        // - gera um novo token da propria api, usando os dados do token do microsoft

        // return user.getCity();
        return null;
    }

    @PostMapping("/refresh")
    public ResponseEntity<String> refreshToken(@RequestBody @Valid RefreshDTO dto)
            throws IncorrectCredentialsException {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("client_id", "trackhub");
        formData.add("refresh_token", dto.getRefresh_token());
        formData.add("grant_type", "refresh_token");
        formData.add("client_secret", "gJSYrFwjBbc9mPA7uYbh1SDaf7TVXWIl");
        formData.add("scope", "openid profile email");

        try {
            return authServiceClient.getToken(formData);
        } catch (FeignException.Unauthorized ex) {
            throw new IncorrectCredentialsException("Credenciais incorretas.");
        } catch (FeignException.FeignClientException ex) {
            throw new IncorrectCredentialsException("Credenciais incorretas.");
        }
    }

    @GetMapping("/userinfo")
    public Object getUserInfo() throws IncorrectCredentialsException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Jwt user = (Jwt) authentication.getPrincipal();

        String token = user.getTokenValue();

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("client_id", "trackhub");
        formData.add("scope", "openid");
        formData.add("grant_type", "client_credentials");
        formData.add("client_secret", "gJSYrFwjBbc9mPA7uYbh1SDaf7TVXWIl");

        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, ("Bearer " + token));

        try {
            return authServiceClient.getUserInfo(formData, headers);
        } catch (FeignException.Unauthorized ex) {
            throw new IncorrectCredentialsException("Credenciais incorretas.");
        }
    }

    @GetMapping("/users")
    @PreAuthorize("hasRole('instructor')")
    public Object getUsers(@RequestHeader HttpHeaders headers, @RequestParam String q)
            throws IncorrectCredentialsException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Jwt user = (Jwt) authentication.getPrincipal();

        String token = user.getTokenValue();

        headers.add(HttpHeaders.AUTHORIZATION, ("Bearer " + token));

        try {
            return authServiceClient.getUsers(headers, q);
        } catch (FeignException.Unauthorized ex) {
            throw new IncorrectCredentialsException("Credenciais incorretas.");
        }
    }

    @GetMapping("/users/{userId}/roles")
    @PreAuthorize("hasRole('instructor')")

    public Object getUserRoles(@PathVariable String userId) throws IncorrectCredentialsException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Jwt user = (Jwt) authentication.getPrincipal();
        String token = user.getTokenValue();
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, ("Bearer " + token));

        try {
            return authServiceClient.getUserRoles(userId, headers);
        } catch (FeignException.Unauthorized ex) {
            throw new IncorrectCredentialsException("Credenciais incorretas.");
        }
    }

    @PostMapping("/users/{userId}/roles")
    @PreAuthorize("hasRole('instructor')")
    public Object postUserRole(@PathVariable String userId, @RequestBody @Valid RequestNewRoleDTO dto)
            throws IncorrectBodyException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Jwt user = (Jwt) authentication.getPrincipal();
        String token = user.getTokenValue();
        HttpHeaders headers = new HttpHeaders();

        System.out.println(dto.getRole());
        String idRole = "";
        if (dto.getRole().equals(Role.APPRENTICE)) {
            // idRole = "257afb7f-7930-4dd3-a768-ffef905767db";
            idRole = "79234a79-b534-44fa-991c-575b9900998b";
        } else if (dto.getRole().equals(Role.INSTRUCTOR)) {
            // idRole = "47aaded2-ad99-43e5-b222-60be9449586d";
            idRole = "5c17ade7-0bfd-4604-9a0a-7637a23e45f2";
        }

        RoleDTO roleDTO = RoleDTO.builder()
                .composite(false)
                .clientRole(true)
                .name(dto.getRole().toString())
                .id(idRole)
                .containerId("d0bdc3b3-30be-4881-b7d9-9744cb26ed47")
                .build();
        try {

            headers.add(HttpHeaders.AUTHORIZATION, ("Bearer " + token));
            List<RoleDTO> roles = Arrays.asList(roleDTO);
            return authServiceClient.postUserRoles(userId, headers, roles);
        } catch (FeignException ex) {
            System.out.println(ex.getMessage());
            throw new IncorrectBodyException("campos inválidos");
        }
    }

    @GetMapping("/roles")
    @PreAuthorize("hasRole('instructor')")
    public Object getRoles() throws IncorrectCredentialsException {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Jwt user = (Jwt) authentication.getPrincipal();

            String token = user.getTokenValue();
            HttpHeaders headers = new HttpHeaders();
            headers.add(HttpHeaders.AUTHORIZATION, ("Bearer " + token));
            return authServiceClient.getClientRoles(headers);
        } catch (FeignException.Unauthorized ex) {
            throw new IncorrectCredentialsException("Credenciais incorretas.");
        }
    }

    @GetMapping("/users/{role}")
    @PreAuthorize("hasRole('instructor')")
    public Object getUsersByRole(@PathVariable String role) throws IncorrectCredentialsException {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Jwt user = (Jwt) authentication.getPrincipal();
            String token = user.getTokenValue();
            HttpHeaders headers = new HttpHeaders();
            headers.add(HttpHeaders.AUTHORIZATION, ("Bearer " + token));
            return authServiceClient.getUsersByRole(role, headers);
        } catch (FeignException.Unauthorized ex) {
            throw new IncorrectCredentialsException("Credenciais incorretas.");
        }
    }

    @PostMapping("/users")
    @PreAuthorize("hasRole('instructor')")
    public Object createUser(@RequestBody @Valid CreateUserDTO userDTO)
            throws IncorrectBodyException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Jwt user = (Jwt) authentication.getPrincipal();
        String token = user.getTokenValue();
        HttpHeaders headers = new HttpHeaders();

        try {

            headers.add(HttpHeaders.AUTHORIZATION, ("Bearer " + token));

            return authServiceClient.createUser(userDTO, headers);
        } catch (FeignException ex) {
            System.out.println(ex.getMessage());
            throw new IncorrectBodyException("campos inválidos");
        }
    }

}
