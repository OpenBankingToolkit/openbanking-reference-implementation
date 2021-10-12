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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import static com.forgerock.openbanking.common.CookieHttpSecurityHelper.configureHttpSecurity;
import static org.springframework.core.Ordered.LOWEST_PRECEDENCE;

/**
 * A common implementation of {@link WebSecurityConfigurerAdapter} for applications that require internal and external OBRI certificates.
 */
@Configuration
@EnableWebSecurity
@Order(LOWEST_PRECEDENCE - 1)
@Import(OBRICertificateConfiguration.class)
public class CookieWebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final OBRIInternalCertificates obriInternalCertificates;
    private final OBRIExternalCertificates obriExternalCertificates;
    private final CryptoApiClient cryptoApiClient;

    @Autowired
    CookieWebSecurityConfiguration(OBRIInternalCertificates obriInternalCertificates, OBRIExternalCertificates obriExternalCertificates, CryptoApiClient cryptoApiClient) {
        this.obriInternalCertificates = obriInternalCertificates;
        this.obriExternalCertificates = obriExternalCertificates;
        this.cryptoApiClient = cryptoApiClient;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        configureHttpSecurity(http, obriInternalCertificates, obriExternalCertificates, cryptoApiClient);
    }
}
