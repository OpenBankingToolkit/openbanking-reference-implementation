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

import com.forgerock.cert.Psd2CertInfo;
import com.forgerock.cert.psd2.RolesOfPsp;
import com.forgerock.openbanking.jwt.services.CryptoApiClient;
import com.forgerock.openbanking.model.OBRIRole;
import com.forgerock.openbanking.model.error.ClientResponseErrorHandler;
import com.forgerock.openbanking.ssl.config.SslConfiguration;
import com.forgerock.openbanking.ssl.exceptions.SslConfigurationFailure;
import com.forgerock.openbanking.ssl.services.keystore.KeyStoreService;
import com.google.common.collect.Sets;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWT;
import dev.openbanking4.spring.security.multiauth.configurers.MultiAuthenticationCollectorConfigurer;
import dev.openbanking4.spring.security.multiauth.configurers.collectors.CustomCookieCollector;
import dev.openbanking4.spring.security.multiauth.configurers.collectors.PSD2Collector;
import dev.openbanking4.spring.security.multiauth.configurers.collectors.X509Collector;
import dev.openbanking4.spring.security.multiauth.model.CertificateHeaderFormat;
import dev.openbanking4.spring.security.multiauth.model.granttypes.PSD2GrantType;
import io.netty.handler.ssl.SslContext;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jackson.Jackson2ObjectMapperBuilderCustomizer;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;


@SpringBootApplication
@EnableSwagger2
@EnableDiscoveryClient
@EnableScheduling
@Slf4j
@ComponentScan(basePackages = {"com.forgerock"})
@EnableMongoRepositories(basePackages = "com.forgerock")
public class ForgerockOpenbankingMetricsServicesApplication {

    public static void main(String[] args) throws Exception {
        new SpringApplication(ForgerockOpenbankingMetricsServicesApplication.class).run(args);
    }

    @Autowired
    private KeyStoreService keyStoreService;
    @Value("${matls.forgerock-internal-ca-alias}")
    private String internalCaAlias;
    @Value("${matls.forgerock-external-ca-alias}")
    private String externalCaAlias;
    @Autowired
    private SslConfiguration sslConfiguration;
    @Value("${server.ssl.client-certs-key-alias}")
    private String keyAlias;

    private static String getCn(X509Certificate x509Certificate) {
        try {
            X500Name x500name = new JcaX509CertificateHolder(x509Certificate).getSubject();
            RDN cn = x500name.getRDNs(BCStyle.CN)[0];
            return IETFUtils.valueToString(cn.getFirst().getValue());
        } catch (CertificateEncodingException e) {
            return null;
        }
    }

    @Configuration
    static class CookieWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {
        private static String CLIENT_CERTIFICATE_HEADER_NAME = "x-client-jwk";

        @Autowired
        private KeyStoreService keyStoreService;
        @Value("${matls.forgerock-internal-ca-alias}")
        private String internalCaAlias;
        @Value("${matls.forgerock-external-ca-alias}")
        private String externalCaAlias;
        @Autowired
        private CryptoApiClient cryptoApiClient;


        @Override
        protected void configure(HttpSecurity http) throws Exception {
            JwtCookieAuthorityCollector jwtCookieAuthorityCollector = new JwtCookieAuthorityCollector();
            X509Certificate internalCACertificate = (X509Certificate) keyStoreService.getKeyStore().getCertificate(internalCaAlias);

            OBRIInternalCertificates obriInternalCertificates = new OBRIInternalCertificates(internalCACertificate);

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
                                    .usernameCollector(obriInternalCertificates)
                                    .authoritiesCollector(obriInternalCertificates)
                                    .build())
                            .collector(DecryptingJwtCookieCollector.builder()
                                    .cryptoApiClient(cryptoApiClient)
                                    .cookieName("obri-session")
                                    .authoritiesCollector(jwtCookieAuthorityCollector)
                                    .build())
                    );
        }
    }

    public static class DecryptingJwtCookieCollector extends CustomCookieCollector<JWT> {

        @Builder
        public DecryptingJwtCookieCollector(CustomCookieCollector.AuthoritiesCollector<JWT> authoritiesCollector, String cookieName, CryptoApiClient cryptoApiClient) {
            super(
                    "JWTCookie",
                    tokenSerialised -> {
                        try {
                            return cryptoApiClient.decryptJwe(tokenSerialised);
                        } catch (JOSEException e) {
                            throw new RuntimeException(e);
                        }
                    },
                    token -> token.getJWTClaimsSet().getSubject(),
                    authoritiesCollector,
                    cookieName
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
    public static class JwtCookieAuthorityCollector implements CustomCookieCollector.AuthoritiesCollector<JWT> {

        @Override
        public Set<GrantedAuthority> getAuthorities(JWT token) throws ParseException {
            Set<GrantedAuthority> authorities = Sets.newHashSet(
                    AnalyticsAuthority.READ_KPI,
                    AnalyticsAuthority.PUSH_KPI);
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

    @Slf4j
    @AllArgsConstructor
    public static class OBRIInternalCertificates implements PSD2Collector.AuthoritiesCollector, X509Collector.UsernameCollector {

        private X509Certificate caCertificate;

        @Override
        public Set<GrantedAuthority> getAuthorities(X509Certificate[] certificatesChain, Psd2CertInfo psd2CertInfo, RolesOfPsp roles) {
            Set<GrantedAuthority> authorities = new HashSet<>();

            if (roles != null) {
                authorities.addAll(roles.getRolesOfPsp().stream().map(r -> new PSD2GrantType(r)).collect(Collectors.toSet()));
            }

            if (isCertificateIssuedByCA(certificatesChain)) {
                authorities.add(OBRIRole.ROLE_FORGEROCK_INTERNAL_APP);
                authorities.add(AnalyticsAuthority.PUSH_KPI);
                authorities.add(AnalyticsAuthority.READ_KPI);
            }
            return authorities;
        }

        @Override
        public String getUserName(X509Certificate[] certificatesChain) {
            if (!isCertificateIssuedByCA(certificatesChain)) {
                return null;
            }
            return getCn(certificatesChain[0]);
        }

        private boolean isCertificateIssuedByCA(X509Certificate[] certificatesChain) {
            return (certificatesChain.length > 1 && caCertificate.equals(certificatesChain[1]))
                    || (certificatesChain.length == 1 && caCertificate.getSubjectX500Principal().equals(certificatesChain[0].getIssuerX500Principal()));
        }
    }

    public static class CustomAuthProvider implements AuthenticationProvider {
        @Override
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            //You can load more GrantedAuthority based on the user subject, like loading the TPP details from the software ID
            return authentication;
        }

        @Override
        public boolean supports(Class<?> aClass) {
            return true;
        }
    }

    @Bean
    public RestTemplate restTemplate(@Qualifier("mappingJacksonHttpMessageConverter")
                                             MappingJackson2HttpMessageConverter converter) throws SslConfigurationFailure {
        RestTemplate restTemplate = new RestTemplate(sslConfiguration.factory(keyAlias, true));
        customiseRestTemplate(converter, restTemplate);
        return restTemplate;
    }

    @Bean
    public WebClient webClient() throws Exception {

        SslContext sslContext = sslConfiguration.getSslContextForReactor(keyAlias);
        HttpClient httpClient = HttpClient.create()
                .secure(sslContextSpec -> sslContextSpec.sslContext(sslContext));
        ReactorClientHttpConnector connector = new ReactorClientHttpConnector(httpClient);
        return WebClient.builder().clientConnector(connector).build();
    }

    private void customiseRestTemplate(@Qualifier("mappingJacksonHttpMessageConverter") MappingJackson2HttpMessageConverter converter, RestTemplate restTemplate) {
        List<HttpMessageConverter<?>> messageConverters = restTemplate.getMessageConverters();
        messageConverters.removeIf(c -> c instanceof MappingJackson2HttpMessageConverter);
        messageConverters.add(converter);
        restTemplate.setErrorHandler(new ClientResponseErrorHandler());
    }

    @Bean
    public MappingJackson2HttpMessageConverter mappingJacksonHttpMessageConverter(@Qualifier("objectMapperBuilderCustomizer") Jackson2ObjectMapperBuilderCustomizer objectMapperBuilderCustomizer) {
        MappingJackson2HttpMessageConverter converter = new MappingJackson2HttpMessageConverter();
        Jackson2ObjectMapperBuilder objectMapperBuilder = new Jackson2ObjectMapperBuilder();
        objectMapperBuilderCustomizer.customize(objectMapperBuilder);
        converter.setObjectMapper(objectMapperBuilder.build());
        return converter;
    }

    public enum AnalyticsAuthority implements GrantedAuthority {
        PUSH_KPI,
        READ_KPI;

        @Override
        public String getAuthority() {
            return name();
        }
    }
}
