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

import com.forgerock.openbanking.common.EnableCookieWebSecurityConfiguration;
import com.forgerock.openbanking.common.EnableSslClientConfiguration;
import com.forgerock.openbanking.common.OBRICertificates;
import com.forgerock.openbanking.common.services.store.tpp.TppStoreService;
import com.forgerock.openbanking.ssl.services.keystore.KeyStoreService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.Resource;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;
import org.springframework.scheduling.annotation.EnableScheduling;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import java.security.cert.X509Certificate;

import static com.forgerock.openbanking.common.CertificateHelper.loadOBCertificates;

@SpringBootApplication
@EnableSwagger2
@EnableDiscoveryClient
@EnableScheduling
@ComponentScan(basePackages = {"com.forgerock"})
@EnableMongoRepositories(basePackages = "com.forgerock")
@EnableCookieWebSecurityConfiguration
@EnableSslClientConfiguration
public class ForgerockOpenbankingAsApiApplication {

    public static void main(String[] args) {
        new SpringApplication(ForgerockOpenbankingAsApiApplication.class).run(args);
    }

    @Value("${matls.forgerock-external-ca-alias}")
    private String externalCaAlias;
    @Value("${openbankingdirectory.certificates.ob.root}")
    private Resource obRootCertificatePem;
    @Value("${openbankingdirectory.certificates.ob.issuing}")
    private Resource obIssuingCertificatePem;

    private final KeyStoreService keyStoreService;
    private final TppStoreService tppStoreService;

    @Autowired
    public ForgerockOpenbankingAsApiApplication(KeyStoreService keyStoreService, TppStoreService tppStoreService) {
        this.keyStoreService = keyStoreService;
        this.tppStoreService = tppStoreService;
    }

    @Bean
    @Primary
    @Qualifier("obriExternalCertificates")
    public OBRICertificates obriExternalCertificates() throws Exception  {
        X509Certificate[] obCA = loadOBCertificates(obRootCertificatePem, obIssuingCertificatePem);
        X509Certificate externalCACertificate = (X509Certificate) keyStoreService.getKeyStore().getCertificate(externalCaAlias);

        AsApiOBRIExternalCertificates obriExternalCertificates = new AsApiOBRIExternalCertificates(externalCACertificate, tppStoreService, obCA);
        return obriExternalCertificates;
    }
}