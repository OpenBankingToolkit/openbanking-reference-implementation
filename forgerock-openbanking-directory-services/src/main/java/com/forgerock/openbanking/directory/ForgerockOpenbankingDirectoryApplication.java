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
package com.forgerock.openbanking.directory;

import brave.Tracer;
import com.forgerock.openbanking.common.CustomAuthProvider;
import com.forgerock.openbanking.common.DecryptingJwtCookieCollector;
import com.forgerock.openbanking.common.EnableSslClientConfiguration;
import com.forgerock.openbanking.common.OBRIInternalCertificates;
import com.forgerock.openbanking.directory.error.ErrorHandler;
import com.forgerock.openbanking.directory.security.FormValueSanitisationFilter;
import com.forgerock.openbanking.directory.security.JsonRequestSanitisiationFilter;
import com.forgerock.openbanking.directory.service.DirectoryUtilsService;
import com.forgerock.openbanking.jwt.services.CryptoApiClient;
import com.forgerock.openbanking.model.OBRIRole;
import com.forgerock.openbanking.ssl.services.keystore.KeyStoreService;
import com.google.common.collect.Sets;
import com.nimbusds.jwt.JWT;
import dev.openbanking4.spring.security.multiauth.configurers.MultiAuthenticationCollectorConfigurer;
import dev.openbanking4.spring.security.multiauth.configurers.collectors.CustomCookieCollector;
import dev.openbanking4.spring.security.multiauth.configurers.collectors.PSD2Collector;
import dev.openbanking4.spring.security.multiauth.configurers.collectors.StaticUserCollector;
import dev.openbanking4.spring.security.multiauth.model.CertificateHeaderFormat;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import javax.servlet.Filter;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static com.forgerock.openbanking.common.CertificateHelper.CLIENT_CERTIFICATE_HEADER_NAME;

@SpringBootApplication
@EnableSwagger2
@EnableDiscoveryClient
@EnableScheduling
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@ComponentScan(basePackages = {"com.forgerock"})
@EnableMongoRepositories(basePackages = "com.forgerock")
@EnableSslClientConfiguration
public class ForgerockOpenbankingDirectoryApplication {

    public static void main(String[] args) {
        SpringApplication.run(ForgerockOpenbankingDirectoryApplication.class, args);
    }

    @Configuration
    static class AuthWebSecurity extends WebSecurityConfigurerAdapter {

        @Value("${matls.forgerock-internal-ca-alias}")
        private String internalCaAlias;
        @Value("${matls.forgerock-external-ca-alias}")
        private String externalCaAlias;

        private final CryptoApiClient cryptoApiClient;
        private final DirectoryUtilsService directoryUtilsService;
        private final KeyStoreService keyStoreService;

        @Autowired
        AuthWebSecurity(CryptoApiClient cryptoApiClient, DirectoryUtilsService directoryUtilsService, KeyStoreService keyStoreService) {
            this.cryptoApiClient = cryptoApiClient;
            this.directoryUtilsService = directoryUtilsService;
            this.keyStoreService = keyStoreService;
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            X509Certificate internalCACertificate = (X509Certificate) keyStoreService.getKeyStore().getCertificate(internalCaAlias);
            X509Certificate externalCACertificate = (X509Certificate) keyStoreService.getKeyStore().getCertificate(externalCaAlias);

            JwtCookieAuthorityCollector jwtCookieAuthorityCollector = new JwtCookieAuthorityCollector();
            OBRIInternalCertificates obriInternalCertificates = new OBRIInternalCertificates(internalCACertificate);
            DirectoryORBIExternalCertificates obriExternalCertificates = new DirectoryORBIExternalCertificates(externalCACertificate, directoryUtilsService);
            http
                    .csrf().disable() // We don't need CSRF for JWT based authentication
                    .authorizeRequests()
                    .anyRequest()
                    .permitAll()//.authenticated()
                    .and()
                    .authenticationProvider(new CustomAuthProvider())
                    .apply(new MultiAuthenticationCollectorConfigurer<HttpSecurity>()
                            .collector(PSD2Collector.psd2Builder()
                                    .collectFromHeader(CertificateHeaderFormat.JWK)
                                    .headerName(CLIENT_CERTIFICATE_HEADER_NAME)
                                    .usernameCollector(obriExternalCertificates)
                                    .authoritiesCollector(obriExternalCertificates)
                                    .build())
                            .collector(DecryptingJwtCookieCollector.builder()
                                    .cryptoApiClient(cryptoApiClient)
                                    .cookieName("obri-session")
                                    .authoritiesCollector(jwtCookieAuthorityCollector)
                                    .build())
                            .collector(PSD2Collector.psd2Builder()
                                    .collectFromHeader(CertificateHeaderFormat.JWK)
                                    .headerName(CLIENT_CERTIFICATE_HEADER_NAME)
                                    .usernameCollector(obriInternalCertificates)
                                    .authoritiesCollector(obriInternalCertificates)
                                    .build())
                            .collector(StaticUserCollector.builder()
                                    .grantedAuthorities(Collections.emptySet())
                                    .usernameCollector(() -> "Anonymous")
                                    .build())
                    );
        }
    }


    /*
     * Adding the default authorities.
     * Adding the authorities coming from Forgerock AM JWT Cookie authentication if exist authorities.
     * FYI: Additional Authorities setted on Claim 'group' set in 'identity / MSISDN Number'.
     */
    @Slf4j
    @AllArgsConstructor
    static class JwtCookieAuthorityCollector implements CustomCookieCollector.AuthoritiesCollector<JWT> {

        @Override
        public Set<GrantedAuthority> getAuthorities(JWT token) throws ParseException {
            Set<GrantedAuthority> authorities = Sets.newHashSet(
                    OBRIRole.ROLE_SOFTWARE_STATEMENT,
                    OBRIRole.ROLE_USER);
            List<String> amGroups = token.getJWTClaimsSet().getStringListClaim("group");
            if (amGroups != null && !amGroups.isEmpty()) {
                log.trace("AM Authorities founds: {}", amGroups);
                for (String amGroup : amGroups) {
                    authorities.add(new SimpleGrantedAuthority(amGroup));
                }
            }
            return authorities;
        }
    }

    @Bean
    public Filter jsonSanitisationFilter(ErrorHandler errorHandler, Tracer tracer) {
        return new JsonRequestSanitisiationFilter(errorHandler, tracer);
    }

    @Bean
    public Filter formSanitisationFilter(ErrorHandler errorHandler, Tracer tracer) {
        return new FormValueSanitisationFilter(errorHandler, tracer);
    }

}
