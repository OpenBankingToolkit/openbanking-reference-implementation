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
package com.forgerock.openbanking.register;

import com.forgerock.openbanking.common.CustomAuthProvider;
import com.forgerock.openbanking.common.OBRIExternalCertificates;
import com.forgerock.openbanking.common.OBRIInternalCertificates;
import com.forgerock.openbanking.common.services.store.tpp.TppStoreService;
import com.forgerock.openbanking.jwt.services.CryptoApiClient;
import com.forgerock.openbanking.model.OBRIRole;
import com.forgerock.openbanking.ssl.services.keystore.KeyStoreService;
import com.google.common.collect.Sets;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWT;
import dev.openbanking4.spring.security.multiauth.configurers.MultiAuthenticationCollectorConfigurer;
import dev.openbanking4.spring.security.multiauth.configurers.collectors.CustomJwtCookieCollector;
import dev.openbanking4.spring.security.multiauth.configurers.collectors.PSD2Collector;
import dev.openbanking4.spring.security.multiauth.configurers.collectors.StaticUserCollector;
import dev.openbanking4.spring.security.multiauth.model.CertificateHeaderFormat;
import lombok.Builder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;

import static com.forgerock.openbanking.common.CertificateHelper.CLIENT_CERTIFICATE_HEADER_NAME;

@Configuration
class RegisterApplicationSecurityConfiguration {

    @Configuration
    static class CookieWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

        @Value("${matls.forgerock-internal-ca-alias}")
        private String internalCaAlias;
        @Value("${matls.forgerock-external-ca-alias}")
        private String externalCaAlias;
        @Value("${openbankingdirectory.certificates.ob.root}")
        private Resource obRootCertificatePem;
        @Value("${openbankingdirectory.certificates.ob.issuing}")
        private Resource obIssuingCertificatePem;

        private final CryptoApiClient cryptoApiClient;
        private final KeyStoreService keyStoreService;
        private final TppStoreService tppStoreService;

        @Autowired
        CookieWebSecurityConfigurerAdapter(CryptoApiClient cryptoApiClient, KeyStoreService keyStoreService, TppStoreService tppStoreService) {
            this.cryptoApiClient = cryptoApiClient;
            this.keyStoreService = keyStoreService;
            this.tppStoreService = tppStoreService;
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            X509Certificate[] obCA = loadOBCertificates();
            X509Certificate internalCACertificate = (X509Certificate) keyStoreService.getKeyStore().getCertificate(internalCaAlias);
            X509Certificate externalCACertificate = (X509Certificate) keyStoreService.getKeyStore().getCertificate(externalCaAlias);

            OBRIInternalCertificates obriInternalCertificates = new OBRIInternalCertificates(internalCACertificate);
            OBRIExternalCertificates obriExternalCertificates = new OBRIExternalCertificates(externalCACertificate, tppStoreService, obCA);

            http
                    .csrf().disable()
                    .authorizeRequests()
                    .anyRequest()
                    .permitAll()//.authenticated()
                    .and()
                    .authenticationProvider(new CustomAuthProvider())
                    .apply(new MultiAuthenticationCollectorConfigurer<HttpSecurity>()
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
                            .collector(DecryptingJwtCookieCollector.jwtBuilder()
                                    .cryptoApiClient(cryptoApiClient)
                                    .cookieName("obri-session")
                                    .authoritiesCollector(t -> Sets.newHashSet(
                                            OBRIRole.ROLE_SOFTWARE_STATEMENT,
                                            OBRIRole.ROLE_USER,
                                            OBRIRole.ROLE_TPP)) // different implementation and additional TPP role to JwtCookieAuthorityCollector in common
                                    .build())
                            .collector(StaticUserCollector.builder()
                                    .grantedAuthorities(Collections.emptySet())
                                    .usernameCollector(() -> "Anonymous")
                                    .build())
                    );
        }

        private X509Certificate[] loadOBCertificates() throws CertificateException, IOException {
            CertificateFactory fact = CertificateFactory.getInstance("X.509");
            InputStream rootCertStream = null;
            InputStream issuingCertStream = null;
            try {
                rootCertStream = obRootCertificatePem.getURL().openStream();
                X509Certificate obRootCert = (X509Certificate) fact.generateCertificate(rootCertStream);

                issuingCertStream = obIssuingCertificatePem.getURL().openStream();
                X509Certificate obIssuingCert = (X509Certificate) fact.generateCertificate(issuingCertStream);
                X509Certificate[] obCA = new X509Certificate[2];
                obCA[0] = obIssuingCert;
                obCA[1] = obRootCert;
                return obCA;
            } finally {
                if (rootCertStream != null) {
                    rootCertStream.close();
                }
                if (issuingCertStream != null) {
                    issuingCertStream.close();
                }
            }
        }
    }

    // N.B. the common DecryptingJwtCookieCollector extends CustomCookieCollector
    static class DecryptingJwtCookieCollector extends CustomJwtCookieCollector {

        @Builder(builderMethodName = "jwtBuilder")
        public DecryptingJwtCookieCollector(CustomJwtCookieCollector.AuthoritiesCollector<JWT> authoritiesCollector, String cookieName, CryptoApiClient cryptoApiClient) {
            super(
                    "jwt-cookie",
                    tokenSerialised -> {
                        try {
                            return cryptoApiClient.decryptJwe(tokenSerialised);
                        } catch (JOSEException e) {
                            throw new BadCredentialsException("Invalid cookie");
                        }
                    },
                    authoritiesCollector,
                    cookieName
            );
        }

    }
}
