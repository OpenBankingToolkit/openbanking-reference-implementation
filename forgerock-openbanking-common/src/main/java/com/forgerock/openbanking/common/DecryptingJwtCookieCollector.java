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
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWT;
import com.forgerock.spring.security.multiauth.configurers.collectors.CustomCookieCollector;
import lombok.Builder;
import org.springframework.security.authentication.BadCredentialsException;

public class DecryptingJwtCookieCollector extends CustomCookieCollector<JWT> {

    @Builder
    public DecryptingJwtCookieCollector(CustomCookieCollector.AuthoritiesCollector<JWT> authoritiesCollector, String cookieName, CryptoApiClient cryptoApiClient) {
        super(
                "jwt-cookie",
                tokenSerialised -> {
                    try {
                        return cryptoApiClient.decryptJwe(tokenSerialised);
                    } catch (JOSEException e) {
                        throw new BadCredentialsException("Invalid cookie");
                    }
                },
                token -> token.getJWTClaimsSet().getSubject(),
                authoritiesCollector,
                cookieName
        );
    }
}
