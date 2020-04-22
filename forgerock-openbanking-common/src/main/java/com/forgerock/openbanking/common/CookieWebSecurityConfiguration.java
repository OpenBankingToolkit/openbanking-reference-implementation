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

import com.forgerock.openbanking.common.services.store.tpp.TppStoreService;
import com.forgerock.openbanking.jwt.services.CryptoApiClient;
import com.forgerock.openbanking.ssl.services.keystore.KeyStoreService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.Resource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import java.security.cert.X509Certificate;

import static com.forgerock.openbanking.common.CertificateHelper.loadOBCertificates;
import static com.forgerock.openbanking.common.CookieHttpSecurityConfiguration.configureHttpSecurity;
import static org.springframework.core.Ordered.LOWEST_PRECEDENCE;

/**
 * A common implementation of {@link WebSecurityConfigurerAdapter} for applications that require internal and external OBRI certificates.
 */
@Configuration
@EnableWebSecurity
class CookieWebSecurityConfiguration {

    @Value("${matls.forgerock-internal-ca-alias}")
    private String internalCaAlias;
    @Value("${matls.forgerock-external-ca-alias}")
    private String externalCaAlias;
    @Value("${openbankingdirectory.certificates.ob.root}")
    private Resource obRootCertificatePem;
    @Value("${openbankingdirectory.certificates.ob.issuing}")
    private Resource obIssuingCertificatePem;

    private final KeyStoreService keyStoreService;
    private final TppStoreService tppStoreService;

    @Autowired
    CookieWebSecurityConfiguration(KeyStoreService keyStoreService, TppStoreService tppStoreService) {
        this.keyStoreService = keyStoreService;
        this.tppStoreService = tppStoreService;
    }

    @Bean
    @Qualifier("obriInternalCertificates")
    public OBRICertificates obriInternalCertificates() throws Exception {
        X509Certificate internalCACertificate = (X509Certificate) keyStoreService.getKeyStore().getCertificate(internalCaAlias);

        OBRIInternalCertificates obriInternalCertificates = new OBRIInternalCertificates(internalCACertificate);
        return obriInternalCertificates;
    }

    @Bean
    @Qualifier("obriExternalCertificates")
    public OBRICertificates obriExternalCertificates() throws Exception {
        X509Certificate externalCACertificate = (X509Certificate) keyStoreService.getKeyStore().getCertificate(externalCaAlias);

        X509Certificate[] obCA = loadOBCertificates(obRootCertificatePem, obIssuingCertificatePem);
        OBRIExternalCertificates obriExternalCertificates = new OBRIExternalCertificates(externalCACertificate, tppStoreService, obCA);
        return obriExternalCertificates;
    }

    @Configuration
    @Order(LOWEST_PRECEDENCE - 1)
    static class CookieWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

        private final OBRICertificates obriInternalCertificates;
        private final OBRICertificates obriExternalCertificates;
        private final CryptoApiClient cryptoApiClient;

        @Autowired
        CookieWebSecurityConfigurerAdapter(@Qualifier("obriInternalCertificates") OBRICertificates obriInternalCertificates,
                                           @Qualifier("obriExternalCertificates") OBRICertificates obriExternalCertificates,
                                           CryptoApiClient cryptoApiClient) {
            this.obriInternalCertificates = obriInternalCertificates;
            this.obriExternalCertificates = obriExternalCertificates;
            this.cryptoApiClient = cryptoApiClient;
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            configureHttpSecurity(http, obriInternalCertificates, obriExternalCertificates, cryptoApiClient);
        }
    }
}
