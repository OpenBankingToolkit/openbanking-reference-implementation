/**
 * Copyright 2019 ForgeRock AS.
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
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
