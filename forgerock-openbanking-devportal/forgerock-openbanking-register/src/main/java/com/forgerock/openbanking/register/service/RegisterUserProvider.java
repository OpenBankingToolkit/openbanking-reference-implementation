/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
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
