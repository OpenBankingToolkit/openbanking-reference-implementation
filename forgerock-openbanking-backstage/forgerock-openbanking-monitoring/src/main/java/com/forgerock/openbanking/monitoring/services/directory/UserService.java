/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.monitoring.services.directory;

import com.forgerock.openbanking.monitoring.configuration.DirectoryConfiguration;
import com.forgerock.openbanking.monitoring.model.directory.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

/**
 * Access the Jwk MS services
 */
@Service
public class UserService {

    private DirectoryConfiguration directoryConfiguration;
    private RestTemplate restTemplate;

    @Autowired
    public UserService(DirectoryConfiguration directoryConfiguration, RestTemplate restTemplate) {
        this.directoryConfiguration = directoryConfiguration;
        this.restTemplate = restTemplate;
    }

    public User getUser() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        ParameterizedTypeReference<User> ptr = new ParameterizedTypeReference<User>() {};
        HttpEntity<String> request = new HttpEntity<>(headers);
        return restTemplate.exchange(directoryConfiguration.rootEndpoint + "/api/user/monitoring/",
                HttpMethod.GET, request, ptr).getBody();
    }
}
