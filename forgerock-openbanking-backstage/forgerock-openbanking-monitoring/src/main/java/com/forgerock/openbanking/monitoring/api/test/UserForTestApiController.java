/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.monitoring.api.test;

import com.forgerock.openbanking.am.config.AMOpenBankingConfiguration;
import com.forgerock.openbanking.am.gateway.AMASPSPGateway;
import com.forgerock.openbanking.am.services.AMAuthentication;
import com.forgerock.openbanking.exceptions.OBErrorResponseException;
import com.forgerock.openbanking.monitoring.model.user.UserRegistrationRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.UUID;

@Controller
@Slf4j
public class UserForTestApiController implements UserForTestApi {

    private static final String USER_PREFIX = "test_";
    private static final String USER_DEFAULT_PASSWORD = "changeit";

    @Autowired
    private AMASPSPGateway amGateway;
    @Autowired
    private AMOpenBankingConfiguration amOpenBankingConfiguration;
    @Autowired
    private AMAuthentication amAuthentication;

    @Override
    public ResponseEntity createUser() throws OBErrorResponseException {
        HttpHeaders amHeader = new HttpHeaders();

        UserRegistrationRequest userRegistrationRequest = UserRegistrationRequest.builder().input(
                UserRegistrationRequest.Input.builder()
                        .user(UserRegistrationRequest.User.builder()
                                .username(USER_PREFIX + UUID.randomUUID())
                                .userPassword(USER_DEFAULT_PASSWORD)
                                .build())
                        .build())
                .build();

        amHeader.add("Accept-API-Version", "protocol=1.0,resource=1.0");
        ResponseEntity responseEntity = amGateway.toAM(amOpenBankingConfiguration.registration, HttpMethod.POST,
                amHeader, new ParameterizedTypeReference<String>() {
        }, userRegistrationRequest);
        if (responseEntity.getStatusCode() != HttpStatus.OK) {
            return responseEntity;
        }
        return ResponseEntity.status(HttpStatus.CREATED).body(userRegistrationRequest.getInput().getUser());
    }

    @Override
    public ResponseEntity deleteUser(
            @RequestParam(name = "username") String username
    ) throws OBErrorResponseException {
        if (!username.startsWith(USER_PREFIX)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("User '" + username +  "' not created by the monitoring");
        }
        AMAuthentication.TokenResponse token = amAuthentication.authenticateAsAMAdmin();
        HttpHeaders headers = new HttpHeaders();
        headers.add("Accept-API-Version", "protocol=1.0,resource=1.0");
        headers.add("Cookie", "iPlanetDirectoryPro=" + token.getTokenId());
        return amGateway.toAM(amOpenBankingConfiguration.users + username, HttpMethod.DELETE,
                headers, new ParameterizedTypeReference<String>() {
                }, null);
    }
}
