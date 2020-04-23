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
package com.forgerock.openbanking.jwkms;

import com.forgerock.openbanking.jwkms.service.application.ApplicationService;
import com.forgerock.openbanking.ssl.services.keystore.KeyStoreService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import java.security.cert.X509Certificate;

import static com.forgerock.openbanking.common.CookieHttpSecurityHelper.configureHttpSecurity;

@Configuration
class JwkMSApplicationSecurityConfiguration {

    @Configuration
    static class CookieWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

        @Value("${matls.forgerock-internal-ca-alias}")
        private String internalCaAlias;
        @Value("${matls.forgerock-external-ca-alias}")
        private String externalCaAlias;

        private final ApplicationService applicationService;
        private final KeyStoreService keyStoreService;

        @Autowired
        CookieWebSecurityConfigurerAdapter(ApplicationService applicationService, KeyStoreService keyStoreService) {
            this.applicationService = applicationService;
            this.keyStoreService = keyStoreService;
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            X509Certificate internalCACertificate = (X509Certificate) keyStoreService.getKeyStore().getCertificate(internalCaAlias);
            X509Certificate externalCACertificate = (X509Certificate) keyStoreService.getKeyStore().getCertificate(externalCaAlias);

            JwkMsOBRIInternalCertificates obriInternalCertificates = new JwkMsOBRIInternalCertificates(internalCACertificate, applicationService);
            JwkMsOBRIExternalCertificates obriExternalCertificates = new JwkMsOBRIExternalCertificates(externalCACertificate, applicationService);

            configureHttpSecurity(http, obriInternalCertificates, obriExternalCertificates);
        }
    }
}
