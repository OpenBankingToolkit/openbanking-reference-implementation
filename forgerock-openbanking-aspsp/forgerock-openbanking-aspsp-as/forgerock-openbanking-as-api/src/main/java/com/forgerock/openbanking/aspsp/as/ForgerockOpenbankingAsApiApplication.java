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

import com.forgerock.openbanking.common.EnableSslClientConfiguration;
import com.forgerock.openbanking.common.OBRIInternalCertificates;
import com.forgerock.openbanking.common.services.store.tpp.TppStoreService;
import com.forgerock.openbanking.jwt.services.CryptoApiClient;
import com.forgerock.openbanking.ssl.services.keystore.KeyStoreService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.core.io.Resource;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static com.forgerock.openbanking.common.CookieHttpSecurityConfiguration.configureHttpSecurity;

@SpringBootApplication
@EnableSwagger2
@EnableDiscoveryClient
@EnableScheduling
@EnableWebSecurity
@ComponentScan(basePackages = {"com.forgerock"})
@EnableMongoRepositories(basePackages = "com.forgerock")
@EnableSslClientConfiguration
public class ForgerockOpenbankingAsApiApplication {

    public static void main(String[] args) {
        new SpringApplication(ForgerockOpenbankingAsApiApplication.class).run(args);
    }

    // TODO - this is the same as the common CookieWebSecurityConfiguration, except for the OBRI external certs - inject a different instance?
    static class CookieWebSecurityConfiguration extends WebSecurityConfigurerAdapter {

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
        private final CryptoApiClient cryptoApiClient;

        @Autowired
        CookieWebSecurityConfiguration(KeyStoreService keyStoreService, TppStoreService tppStoreService, CryptoApiClient cryptoApiClient) {
            this.keyStoreService = keyStoreService;
            this.tppStoreService = tppStoreService;
            this.cryptoApiClient = cryptoApiClient;
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            X509Certificate[] obCA = loadOBCertificates();
            X509Certificate internalCACertificate = (X509Certificate) keyStoreService.getKeyStore().getCertificate(internalCaAlias);
            X509Certificate externalCACertificate = (X509Certificate) keyStoreService.getKeyStore().getCertificate(externalCaAlias);

            OBRIInternalCertificates obriInternalCertificates = new OBRIInternalCertificates(internalCACertificate);
            AsApiOBRIExternalCertificates obriExternalCertificates = new AsApiOBRIExternalCertificates(externalCACertificate, tppStoreService, obCA);

            configureHttpSecurity(http, obriInternalCertificates, obriExternalCertificates, cryptoApiClient);
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
}
