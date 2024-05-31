package com.diegojacober.app_auth_keycloak.infra.OpenFeign;

import java.util.List;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;

import com.diegojacober.app_auth_keycloak.dtos.CreateUserDTO;
import com.diegojacober.app_auth_keycloak.dtos.RoleDTO;
import com.diegojacober.app_auth_keycloak.dtos.UpdateUser;

import feign.Headers;

@FeignClient(name = "auth-service", url = "http://keycloak:8080")
public interface AuthServiceClient {
   @PostMapping(value = "/realms/test/protocol/openid-connect/token")
   @Headers("Content-Type: application/x-www-form-urlencoded")
   ResponseEntity<String> getToken(@RequestBody MultiValueMap<String, String> formData);

   @PostMapping(value = "/realms/test/protocol/openid-connect/userinfo")
   @Headers("Content-Type: application/x-www-form-urlencoded")
   ResponseEntity<String> getUserInfo(@RequestBody MultiValueMap<String, String> formData,
         @RequestHeader HttpHeaders headers);

   @GetMapping(value = "/admin/realms/test/clients/d0bdc3b3-30be-4881-b7d9-9744cb26ed47/roles")
   @Headers("Content-Type: application/x-www-form-urlencoded")
   ResponseEntity<String> getClientRoles(@RequestHeader HttpHeaders headers);

   @GetMapping(value = "/admin/realms/test/users")
   @Headers("Content-Type: application/x-www-form-urlencoded")
   ResponseEntity<String> getUsers(@RequestHeader HttpHeaders headers, @RequestParam("q") String q);

   @GetMapping(value = "/admin/realms/test/users/{userId}/role-mappings/clients/d0bdc3b3-30be-4881-b7d9-9744cb26ed47/")
   @Headers("Content-Type: application/x-www-form-urlencoded")
   ResponseEntity<String> getUserRoles(@PathVariable("userId") String userId, @RequestHeader HttpHeaders headers);

   @PostMapping(value = "/admin/realms/test/users/{userId}/role-mappings/clients/d0bdc3b3-30be-4881-b7d9-9744cb26ed47/")
   ResponseEntity<String> postUserRoles(@PathVariable("userId") String userId, @RequestHeader HttpHeaders headers,
         @RequestBody List<RoleDTO> formData);

   @GetMapping(value = "/admin/realms/test/clients/d0bdc3b3-30be-4881-b7d9-9744cb26ed47/roles/{roleName}/users")
   ResponseEntity<String> getUsersByRole(@PathVariable("roleName") String roleName, @RequestHeader HttpHeaders headers);

   @PostMapping(value = "/admin/realms/test/users")
   ResponseEntity<String> createUser(@RequestBody CreateUserDTO userDTO, @RequestHeader HttpHeaders headers);

   @PutMapping(value = "/admin/realms/test/users/{id}")
   ResponseEntity<String> updateUser(@PathVariable("id") String id, @RequestBody UpdateUser userDTO, @RequestHeader HttpHeaders headers);

   @PutMapping(value = "/admin/realms/test/users/profile")
   ResponseEntity<String> updateUserProfile(@RequestBody UpdateUser userDTO, @RequestHeader HttpHeaders headers);

   @DeleteMapping(value = "/admin/realms/test/users/{id}")
   ResponseEntity<String> deleteUser(@PathVariable("id") String id, @RequestHeader HttpHeaders headers);
}
