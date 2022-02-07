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
package com.forgerock.openbanking.common;

import com.forgerock.openbanking.jwt.services.CryptoApiClient;
import com.forgerock.spring.security.multiauth.configurers.collectors.CustomCookieCollector;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWT;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;

@Slf4j
public class DecryptingJwtCookieCollector extends CustomCookieCollector<JWT> {

    @Builder
    public DecryptingJwtCookieCollector(String collectorName,
                                        CustomCookieCollector.AuthoritiesCollector<JWT> authoritiesCollector,
                                        String cookieName, CryptoApiClient cryptoApiClient) {
        super(
                collectorName,
                tokenSerialised -> {
                    try {
                        return cryptoApiClient.decryptJwe(tokenSerialised);
                    } catch (JOSEException e) {
                        throw new BadCredentialsException("Invalid cookie");
                    }
                },
                token -> {
                    String username = token.getJWTClaimsSet().getSubject();
                    if(username.isBlank()) username = "Anonymous";
                    log.info("getUserName() called on collector '{}' returning username '{}'", collectorName, username);
                    return username;
                },
                authoritiesCollector,
                cookieName
        );
    }
}
