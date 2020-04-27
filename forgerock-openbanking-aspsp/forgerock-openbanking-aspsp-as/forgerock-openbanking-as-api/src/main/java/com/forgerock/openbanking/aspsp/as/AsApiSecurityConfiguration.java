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
package com.forgerock.openbanking.aspsp.as;

import com.forgerock.openbanking.common.ApiOBRIExternalCertificates;
import com.forgerock.openbanking.common.CookieWebSecurityConfiguration;
import com.forgerock.openbanking.common.OBRIExternalCertificates;
import com.forgerock.openbanking.common.services.store.tpp.TppStoreService;
import com.forgerock.openbanking.ssl.services.keystore.KeyStoreService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.Resource;

import java.security.cert.X509Certificate;

import static com.forgerock.openbanking.common.CertificateHelper.loadOBCertificates;

@Configuration
@Import(CookieWebSecurityConfiguration.class)
class AsApiSecurityConfiguration {

    @Value("${matls.forgerock-external-ca-alias}")
    private String externalCaAlias;
    @Value("${openbankingdirectory.certificates.ob.root}")
    private Resource obRootCertificatePem;
    @Value("${openbankingdirectory.certificates.ob.issuing}")
    private Resource obIssuingCertificatePem;

    private final KeyStoreService keyStoreService;
    private final TppStoreService tppStoreService;

    public AsApiSecurityConfiguration(KeyStoreService keyStoreService, TppStoreService tppStoreService) {
        this.keyStoreService = keyStoreService;
        this.tppStoreService = tppStoreService;
    }

    @Bean
    @Primary
    public OBRIExternalCertificates AsApiObriExternalCertificates() throws Exception {
        X509Certificate[] obCA = loadOBCertificates(obRootCertificatePem, obIssuingCertificatePem);
        X509Certificate externalCACertificate = (X509Certificate) keyStoreService.getKeyStore().getCertificate(externalCaAlias);
        return new ApiOBRIExternalCertificates(externalCACertificate, tppStoreService, obCA);
    }
}
