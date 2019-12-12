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
package com.forgerock.openbanking.register.service;

import com.forgerock.openbanking.auth.services.UserProvider;
import com.forgerock.openbanking.model.UserContext;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.context.annotation.Primary;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

@Primary
@Service
public class RegisterUserProvider implements UserProvider {
    @Override
    public Object getUser(Authentication authentication) {
        UserContext principal = (UserContext) authentication.getPrincipal();
        return new RegisterUser(principal.getUsername(), principal.getAuthorities().stream().map(Objects::toString).collect(Collectors.toList()));
    }

    @Data
    @AllArgsConstructor
    private static class RegisterUser {
        private String username;
        private List<String> authorities;
    }
}
