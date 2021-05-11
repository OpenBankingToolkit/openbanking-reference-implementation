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
package com.forgerock.openbanking.analytics;

import com.forgerock.openbanking.analytics.MetricsOBRIInternalCertificates.AnalyticsAuthority;
import com.forgerock.openbanking.common.CustomAuthProvider;
import com.forgerock.openbanking.common.DecryptingJwtCookieCollector;
import com.forgerock.openbanking.common.EnableSslClient;
import com.forgerock.openbanking.jwt.services.CryptoApiClient;
import com.forgerock.openbanking.ssl.services.keystore.KeyStoreService;
import com.google.common.collect.Sets;
import com.nimbusds.jwt.JWT;
import com.forgerock.spring.security.multiauth.configurers.MultiAuthenticationCollectorConfigurer;
import com.forgerock.spring.security.multiauth.configurers.collectors.CustomCookieCollector;
import com.forgerock.spring.security.multiauth.configurers.collectors.PSD2Collector;
import com.forgerock.spring.security.multiauth.model.CertificateHeaderFormat;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static com.forgerock.openbanking.common.CertificateHelper.CLIENT_CERTIFICATE_HEADER_NAME;

@Configuration
@EnableSslClient
class MetricsApplicationSecurityConfiguration {

    @Configuration
    static class CookieWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

        @Value("${matls.forgerock-internal-ca-alias}")
        private String internalCaAlias;

        private final CryptoApiClient cryptoApiClient;
        private final KeyStoreService keyStoreService;

        @Autowired
        CookieWebSecurityConfigurerAdapter(CryptoApiClient cryptoApiClient, KeyStoreService keyStoreService) {
            this.cryptoApiClient = cryptoApiClient;
            this.keyStoreService = keyStoreService;
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            JwtCookieAuthorityCollector jwtCookieAuthorityCollector = new JwtCookieAuthorityCollector();
            X509Certificate internalCACertificate = (X509Certificate) keyStoreService.getKeyStore().getCertificate(internalCaAlias);

            MetricsOBRIInternalCertificates obriInternalCertificates = new MetricsOBRIInternalCertificates(internalCACertificate);

            http
                    .csrf().disable() // We don't need CSRF for JWT based authentication
                    .authorizeRequests()
                    .antMatchers(HttpMethod.POST, "/api/kpi/**").hasAuthority(AnalyticsAuthority.PUSH_KPI.getAuthority())
                    .antMatchers(HttpMethod.GET, "/api/kpi/**").hasAuthority(AnalyticsAuthority.READ_KPI.getAuthority())
                    .antMatchers(HttpMethod.GET, "/api/user/initiate-login").permitAll()
                    .antMatchers(HttpMethod.POST, "/api/user/login").permitAll()
                    .antMatchers(HttpMethod.GET, "/api/metrics/keys/jwk_uri").permitAll()
                    .antMatchers(HttpMethod.GET, "/actuator/health").permitAll()
                    .antMatchers(HttpMethod.GET, "/actuator/info").permitAll()
                    .anyRequest().authenticated()
                    .and()
                    .authenticationProvider(new CustomAuthProvider())
                    .apply(new MultiAuthenticationCollectorConfigurer<HttpSecurity>()
                            .collector(PSD2Collector.psd2Builder()
                                    .collectFromHeader(CertificateHeaderFormat.JWK)
                                    .headerName(CLIENT_CERTIFICATE_HEADER_NAME)
                                    .psd2UsernameCollector(obriInternalCertificates)
                                    .psd2AuthoritiesCollector(obriInternalCertificates)
                                    .build())
                            .collector(DecryptingJwtCookieCollector.builder()
                                    .cryptoApiClient(cryptoApiClient)
                                    .cookieName("obri-session")
                                    .authoritiesCollector(jwtCookieAuthorityCollector)
                                    .build())
                    );
        }
    }

    /*
     * User authority privilege permission is required to access the analytics app.
     * It is important for users/customers of the analytics app that the competitive information within is kept private.
     * And then only the users with the authority READ_KPI can access to analytics.
     * Adding the restricted authorities.
     * Adding the authorities coming from Forgerock AM JWT Cookie authentication if exist authorities.
     * FYI: Additional Authorities setted on Claim 'group' set in 'identity / MSISDN Number'.
     */
    @Slf4j
    @AllArgsConstructor
    public static class JwtCookieAuthorityCollector implements CustomCookieCollector.AuthoritiesCollector<JWT> {

        @Override
        public Set<GrantedAuthority> getAuthorities(JWT token) throws ParseException {

            Set<GrantedAuthority> authorities = Sets.newHashSet(Collections.EMPTY_SET);
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
}
