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
package com.forgerock.openbanking.monitoring;

import com.forgerock.cert.Psd2CertInfo;
import com.forgerock.cert.psd2.RolesOfPsp;

import com.forgerock.openbanking.model.OBRIRole;
import com.forgerock.openbanking.model.error.ClientResponseErrorHandler;
import com.forgerock.openbanking.ssl.config.SslConfiguration;
import com.forgerock.openbanking.ssl.exceptions.SslConfigurationFailure;
import com.forgerock.openbanking.ssl.services.keystore.KeyStoreService;
import com.google.common.cache.CacheBuilder;
import dev.openbanking4.spring.security.multiauth.configurers.MultiAuthenticationCollectorConfigurer;
import dev.openbanking4.spring.security.multiauth.configurers.collectors.PSD2Collector;
import dev.openbanking4.spring.security.multiauth.configurers.collectors.X509Collector;
import dev.openbanking4.spring.security.multiauth.model.CertificateHeaderFormat;
import dev.openbanking4.spring.security.multiauth.model.granttypes.PSD2GrantType;
import io.netty.handler.ssl.SslContext;
import lombok.AllArgsConstructor;
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
import org.springframework.cache.Cache;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@SpringBootApplication
@EnableSwagger2
@EnableDiscoveryClient
@EnableScheduling
@EnableWebSecurity
@EnableCaching
@ComponentScan(basePackages = {"com.forgerock"})
@EnableMongoRepositories(basePackages = "com.forgerock")
public class ForgerockOpenbankingMonitoringApplication {

    public static final String MONITORING_CERTIFICATE_CACHE = "monitoringCertificate";

    public static void main(String[] args) {
        new SpringApplication(ForgerockOpenbankingMonitoringApplication.class).run(args);
    }

    @Bean
    public Cache cache() {
        return new ConcurrentMapCache(MONITORING_CERTIFICATE_CACHE,
                CacheBuilder.newBuilder().expireAfterWrite(30, TimeUnit.MINUTES).maximumSize(100).build().asMap(), false);
    }

    @Autowired
    private SslConfiguration sslConfiguration;
    @Value("${server.ssl.client-certs-key-alias}")
    private String keyAlias;
    @Bean
    public WebClient webClient() throws Exception {

        SslContext sslContext = sslConfiguration.getSslContextForReactor(keyAlias);
        HttpClient httpClient = HttpClient.create()
                .secure(sslContextSpec -> sslContextSpec.sslContext(sslContext));
        ReactorClientHttpConnector connector = new ReactorClientHttpConnector(httpClient);
        return WebClient.builder().clientConnector(connector).build();
    }


    @Bean
    public RestTemplate restTemplate(@Qualifier("mappingJacksonHttpMessageConverter")
                                             MappingJackson2HttpMessageConverter converter) throws SslConfigurationFailure {
        RestTemplate restTemplate = new RestTemplate(sslConfiguration.factory(keyAlias, true));
        customiseRestTemplate(converter, restTemplate);
        return restTemplate;
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

    @Bean
    public AuthenticationProvider authProvider() {
        return new CustomAuthProvider();
    }

    @Configuration
    static class AuthWebSecurity extends WebSecurityConfigurerAdapter {

        private static String CLIENT_CERTIFICATE_HEADER_NAME = "x-client-jwk";

        @Autowired
        private KeyStoreService keyStoreService;

        @Value("${matls.forgerock-internal-ca-alias}")
        private String internalCaAlias;
        @Autowired
        private AuthenticationProvider authProvider;

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            X509Certificate internalCACertificate = (X509Certificate) keyStoreService.getKeyStore().getCertificate(internalCaAlias);

            OBRIInternalCertificates obriInternalCertificates = new OBRIInternalCertificates(internalCACertificate);
            http

                    .csrf().disable() // We don't need CSRF for JWT based authentication
                    .authorizeRequests()
                    .anyRequest()
                    .permitAll()//.authenticated()
                    .and()
                    .authenticationProvider(authProvider)
                    .apply(new MultiAuthenticationCollectorConfigurer<HttpSecurity>()
                            .collector(PSD2Collector.psd2Builder()
                                    .collectFromHeader(CertificateHeaderFormat.JWK)
                                    .headerName(CLIENT_CERTIFICATE_HEADER_NAME)
                                    .usernameCollector(obriInternalCertificates)
                                    .authoritiesCollector(obriInternalCertificates)
                                    .build())
                    );
        }

        @Slf4j
        @AllArgsConstructor
        public static class OBRIInternalCertificates implements PSD2Collector.AuthoritiesCollector, X509Collector.UsernameCollector {

            private X509Certificate caCertificate;

            @Override
            public Set<GrantedAuthority> getAuthorities(X509Certificate[] certificatesChain, Psd2CertInfo psd2CertInfo, RolesOfPsp roles) {
                Set<GrantedAuthority> authorities = new HashSet<>();

                if (roles != null) {
                    authorities.addAll(roles.getRolesOfPsp().stream().map(PSD2GrantType::new).collect(Collectors.toSet()));
                }

                if (isCertificateIssuedByCA(certificatesChain)) {
                    authorities.add(OBRIRole.ROLE_FORGEROCK_INTERNAL_APP);
                }
                return authorities;
            }

            @Override
            public String getUserName(X509Certificate[] certificatesChain) {
                if (!isCertificateIssuedByCA(certificatesChain)) {
                    return null;
                }

                try {
                    X500Name x500name = new JcaX509CertificateHolder(certificatesChain[0]).getSubject();
                    RDN cn = x500name.getRDNs(BCStyle.CN)[0];
                    return IETFUtils.valueToString(cn.getFirst().getValue());
                } catch (CertificateEncodingException e) {
                    return null;
                }
            }

            private boolean isCertificateIssuedByCA(X509Certificate[] certificatesChain) {
                return (certificatesChain.length > 1 && caCertificate.equals(certificatesChain[1]))
                        || (certificatesChain.length == 1 && caCertificate.getSubjectX500Principal().equals(certificatesChain[0].getIssuerX500Principal()));
            }

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
}
