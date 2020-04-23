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
import dev.openbanking4.spring.security.multiauth.configurers.MultiAuthenticationCollectorConfigurer;
import dev.openbanking4.spring.security.multiauth.configurers.collectors.PSD2Collector;
import dev.openbanking4.spring.security.multiauth.configurers.collectors.StaticUserCollector;
import dev.openbanking4.spring.security.multiauth.model.CertificateHeaderFormat;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.Collections;

import static com.forgerock.openbanking.common.CertificateHelper.CLIENT_CERTIFICATE_HEADER_NAME;

/**
 * A utility class providing helper methods related to certificates.
 */
public class CookieHttpSecurityHelper {

    /**
     * Configures the instance of {@link HttpSecurity} with the internal and external OBRI certificates, but without the {@link DecryptingJwtCookieCollector}.
     *
     * @param httpSecurity the {@link HttpSecurity} to configure.
     * @param obriInternalCertificates the {@link OBRIInternalCertificates} to add as a collector.
     * @param obriExternalCertificates the {@link OBRIExternalCertificates} to add as a collector.
     */
    public static void configureHttpSecurity(HttpSecurity httpSecurity, OBRICertificates obriInternalCertificates, OBRICertificates obriExternalCertificates) throws Exception {
        httpSecurity(httpSecurity)
                .apply(collectors(obriInternalCertificates, obriExternalCertificates, null));
    }

    /**
     * Configures the instance of {@link HttpSecurity} with the internal and external OBRI certificates, plus the {@link DecryptingJwtCookieCollector}.
     *
     * @param httpSecurity the {@link HttpSecurity} to configure.
     * @param obriInternalCertificates the {@link OBRIInternalCertificates} to add as a collector.
     * @param obriExternalCertificates the {@link OBRIExternalCertificates} to add as a collector.
     * @param cryptoApiClient the {@link CryptoApiClient} for the {@link DecryptingJwtCookieCollector} collector.
     */
    public static void configureHttpSecurity(HttpSecurity httpSecurity, OBRICertificates obriInternalCertificates, OBRICertificates obriExternalCertificates, CryptoApiClient cryptoApiClient) throws Exception {
        httpSecurity(httpSecurity)
                .apply(collectors(obriInternalCertificates, obriExternalCertificates, cryptoApiClient));
    }

    private static HttpSecurity httpSecurity(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .csrf().disable()
                .authorizeRequests()
                .anyRequest()
                .permitAll()//.authenticated()
                .and()
                .authenticationProvider(new CustomAuthProvider());
    }

    private static MultiAuthenticationCollectorConfigurer<HttpSecurity> collectors(OBRICertificates obriInternalCertificates, OBRICertificates obriExternalCertificates, CryptoApiClient cryptoApiClient) {
        MultiAuthenticationCollectorConfigurer<HttpSecurity> configurer = new MultiAuthenticationCollectorConfigurer<>();
        configurer
                .collector(PSD2Collector.psd2Builder()
                        .collectFromHeader(CertificateHeaderFormat.JWK)
                        .headerName(CLIENT_CERTIFICATE_HEADER_NAME)
                        .usernameCollector(obriInternalCertificates)
                        .authoritiesCollector(obriInternalCertificates)
                        .build())
                .collector(PSD2Collector.psd2Builder()
                        .collectFromHeader(CertificateHeaderFormat.JWK)
                        .headerName(CLIENT_CERTIFICATE_HEADER_NAME)
                        .usernameCollector(obriExternalCertificates)
                        .authoritiesCollector(obriExternalCertificates)
                        .build())
                .collector(StaticUserCollector.builder()
                        .grantedAuthorities(Collections.emptySet())
                        .usernameCollector(() -> "Anonymous")
                        .build());

        if (cryptoApiClient != null) {
            JwtCookieAuthorityCollector jwtCookieAuthorityCollector = new JwtCookieAuthorityCollector();
            configurer.collector(DecryptingJwtCookieCollector.builder()
                    .cryptoApiClient(cryptoApiClient)
                    .cookieName("obri-session")
                    .authoritiesCollector(jwtCookieAuthorityCollector)
                    .build());
        }
        return configurer;
    }
}
