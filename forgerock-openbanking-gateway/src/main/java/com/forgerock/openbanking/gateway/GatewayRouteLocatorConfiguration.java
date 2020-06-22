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
package com.forgerock.openbanking.gateway;

import com.forgerock.openbanking.gateway.filters.AddCertificateHeaderGatewayFilter;
import com.forgerock.openbanking.gateway.filters.AddInteractionIdHeaderGatewayFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.BooleanSpec;
import org.springframework.cloud.gateway.route.builder.PredicateSpec;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.cloud.gateway.support.ipresolver.RemoteAddressResolver;
import org.springframework.cloud.gateway.support.ipresolver.XForwardedRemoteAddressResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;

import java.util.function.Function;

@Configuration
class GatewayRouteLocatorConfiguration {

    private static final String X_FORWARDED_HOST = "X-Forwarded-Host";
    private static final String X_FORWARDED_PROTO = "X-Forwarded-Proto";

    private static final RemoteAddressResolver xForwardedRemoteAddressResolver = XForwardedRemoteAddressResolver.maxTrustedIndex(1);

    private final AddCertificateHeaderGatewayFilter addCertificateHeaderGatewayFilter;
    private final AddInteractionIdHeaderGatewayFilter addInteractionIdHeaderGatewayFilter;

    @Value("${am.internal-route}")
    private String amRoute;
    @Value("${am.hostname}")
    private String amHostname;
    @Value("${am.matls-hostname}")
    private String amMatlsHostname;
    @Value("${rs-api.internal-port}")
    private String rsApiPort;
    @Value("${jwkms.internal-port}")
    private String jwkmsPort;
    @Value("${directory.internal-port}")
    private String directoryServicePort;
    @Value("${metrics.internal-port}")
    private String metricsServicePort;
    @Value("${rcs.internal-port}")
    private String rcsPort;
    @Value("${tpp.internal-port}")
    private String tppCorePort;
    @Value("${shop.internal-port}")
    private String shopUiPort;
    @Value("${account.internal-port}")
    private String accountUIPort;
    @Value("${rs-ui.internal-port}")
    private String rsUiPort;
    @Value("${register.internal-port}")
    private String registerPort;
    @Value("${spring.boot.admin.client.internal-port}")
    private String adminPort;
    @Value("${doc.internal-port}")
    private String docsPort;
    @Value("${as-api.internal-port}")
    private String asApiPort;
    @Value("${monitoring.internal-port}")
    private String monitoringPort;
    @Value("${rs-simulator.internal-port}")
    private String rsSimulatorPort;
    @Value("${config.internal-port}")
    private String configPort;
    @Value("#{'${forgerock.whitelist:0.0.0.0/0}'.split('\\s*,\\s*')}")
    private String[] forgerockWhitelist;
    @Value("${dynamic-registration.enable}")
    private boolean isDynamicRegistrationEnable;
    @Value("${dns.hosts.root}")
    private String dnsHostRoot;

    @Autowired
    GatewayRouteLocatorConfiguration(AddCertificateHeaderGatewayFilter addCertificateHeaderGatewayFilter,
                                     AddInteractionIdHeaderGatewayFilter addInteractionIdHeaderGatewayFilter) {
        this.addCertificateHeaderGatewayFilter = addCertificateHeaderGatewayFilter;
        this.addInteractionIdHeaderGatewayFilter = addInteractionIdHeaderGatewayFilter;
    }

    @Bean
    public RouteLocator routeLocator(RouteLocatorBuilder builder) {
        String[] dynamicRegWhitelist = isDynamicRegistrationEnable ? new String[]{"0.0.0.0/0"} : forgerockWhitelist;
        return builder.routes()
                .route(rewriteExternalActuatorToInternal("jwkms." + dnsHostRoot + "**", "https://jwkms:" + jwkmsPort))
                .route(rewriteExternalActuatorToInternal("matls.rs.aspsp." + dnsHostRoot + "**", "https://rs-api:" + rsApiPort))
                .route(rewriteExternalActuatorToInternal("rs.aspsp." + dnsHostRoot + "**", "https://rs-api:" + rsApiPort))
                .route(rewriteExternalActuatorToInternal("as.aspsp." + dnsHostRoot + "**", "https://as-api:" + asApiPort))
                .route(rewriteExternalActuatorToInternal("service.directory." + dnsHostRoot + "**", "https://directory-services:" + directoryServicePort))
                .route(rewriteExternalActuatorToInternal("matls.service.directory." + dnsHostRoot + "**", "https://directory-services:" + directoryServicePort))
                .route(rewriteExternalActuatorToInternal("service.metrics." + dnsHostRoot + "**", "https://metrics-services:" + metricsServicePort))
                .route(rewriteExternalActuatorToInternal("rcs.aspsp." + dnsHostRoot + "**", "https://rs-rcs:" + rcsPort))
                .route(rewriteExternalActuatorToInternal("tpp-core." + dnsHostRoot + "**", "https://tpp-core:" + tppCorePort))
                .route(rewriteExternalActuatorToInternal("shop." + dnsHostRoot + "**", "https://shop:" + shopUiPort))
                .route(rewriteExternalActuatorToInternal("account." + dnsHostRoot + "**", "https://account:" + accountUIPort))
                .route(rewriteExternalActuatorToInternal("service.bank." + dnsHostRoot + "**", "https://rs-ui:" + rsUiPort))
                .route(rewriteExternalActuatorToInternal("matls.service.bank." + dnsHostRoot + "**", "https://rs-ui:" + rsUiPort))
                .route(rewriteExternalActuatorToInternal("docs." + dnsHostRoot + "**", "https://docs:" + docsPort))
                .route(rewriteExternalActuatorToInternal("admin." + dnsHostRoot + "**", "https://admin:" + adminPort))
                .route(rewriteExternalActuatorToInternal("config." + dnsHostRoot + "**", "http://config:" + configPort))
                .route(rewriteExternalActuatorToInternal("monitoring." + dnsHostRoot + "**", "https://monitoring:" + monitoringPort))
                .route(rewriteExternalActuatorToInternal("service.register." + dnsHostRoot + "**", "https://register:" + registerPort))
                .route(rewriteExternalActuatorToInternal("rs-simulator.aspsp." + dnsHostRoot + "**", "https://rs-simulator:" + rsSimulatorPort))
                .route(r ->
                        r
                                .host("am." + dnsHostRoot + "**")

                                .filters(f -> f
                                        .filter(addInteractionIdHeaderGatewayFilter, 0)
                                        .filter(addCertificateHeaderGatewayFilter)
                                        .addRequestHeader("host", amMatlsHostname)

                                )
                                .uri(amRoute)
                )
                .route(r ->
                        r
                                .host("as.aspsp." + dnsHostRoot + "**")
                                .and()
                                .path("/api/jwk/jwk_uri")
                                .or()
                                .path("/oauth2/realms/root/realms/openbanking/connect/jwk_uri")
                                .filters(f -> f
                                        .filter(addInteractionIdHeaderGatewayFilter, 0)
                                        .rewritePath("/oauth2/realms/root/realms/openbanking/connect/jwk_uri", "/api/jwk/jwk_uri")

                                )
                                .uri("https://as-api:" + asApiPort)
                )
                .route(r ->
                        r
                                .host("matls.as.aspsp." + dnsHostRoot + "**")
                                .and()
                                .path("/oauth2/access_token")
                                .or()
                                .path("/oauth2/realms/root/realms/openbanking/access_token")
                                .and()
                                .method(HttpMethod.POST)
                                .filters(f -> f
                                        .filter(addInteractionIdHeaderGatewayFilter, 0)
                                        .filter(addCertificateHeaderGatewayFilter)
                                        .rewritePath("/oauth2/realms/root/realms/openbanking/(?<segment>.*)", "/oauth2/${segment}")
                                )
                                .uri("https://as-api:" + asApiPort)
                ).route(r ->
                        r
                                .path("/oauth2/authorize")
                                .or()
                                .path("/oauth2/realms/root/realms/openbanking/authorize")
                                .and()
                                .host("matls.as.aspsp." + dnsHostRoot + "**")
                                .filters(f -> f
                                        .filter(addInteractionIdHeaderGatewayFilter, 0)
                                        .filter(addCertificateHeaderGatewayFilter)
                                        .rewritePath("/oauth2/realms/root/realms/openbanking/(?<segment>.*)", "/oauth2/${segment}")
                                )
                                .uri("https://as-api:" + asApiPort)
                ).route(r ->                        r
                        .path("/oauth2/authorize")
                        .or()
                        .path("/oauth2/rest/authorize")
                        .or()
                        .path("/oauth2/realms/root/realms/openbanking/authorize")
                        .and()
                        .host("as.aspsp." + dnsHostRoot + "**")
                        .filters(f -> f
                                .filter(addInteractionIdHeaderGatewayFilter, 0)
                                .filter(addCertificateHeaderGatewayFilter)
                                .rewritePath("/oauth2/realms/root/realms/openbanking/(?<segment>.*)", "/oauth2/${segment}")
                        )
                        .uri("https://as-api:" + asApiPort)
                )
                .route(r ->                        r
                        .path("/oauth2/access_token")
                        .or()
                        .path("/oauth2/realms/root/realms/openbanking/access_token")
                        .and()
                        .host("as.aspsp." + dnsHostRoot + "**")
                        .filters(f -> f
                                .filter(addInteractionIdHeaderGatewayFilter, 0)
                                .filter(addCertificateHeaderGatewayFilter)
                                .rewritePath("/oauth2/realms/root/realms/openbanking/(?<segment>.*)", "/oauth2/${segment}")
                        )
                        .uri("https://as-api:" + asApiPort)
                ).route(r ->
                        r
                                .path("/open-banking/register").negate()
                                .and()
                                .host("matls.as.aspsp." + dnsHostRoot + "**")
                                .or()
                                .host("as.aspsp." + dnsHostRoot + "**")
                                .and()
                                .path("/open-banking/**")
                                .or()
                                .path("/oauth2/.well-known/openid-configuration")
                                .filters(f -> f
                                        .filter(addInteractionIdHeaderGatewayFilter, 0)
                                        .filter(addCertificateHeaderGatewayFilter)
                                        .preserveHostHeader()
                                )
                                .uri("https://as-api:" + asApiPort)
                ).route(r ->
                        r
                                .remoteAddr(xForwardedRemoteAddressResolver, dynamicRegWhitelist)
                                .and()
                                .host("matls.as.aspsp." + dnsHostRoot + "**")
                                .and()
                                .path("/open-banking/register")
                                .filters(f -> f
                                        .filter(addInteractionIdHeaderGatewayFilter, 0)
                                        .filter(addCertificateHeaderGatewayFilter)
                                        .preserveHostHeader()
                                )
                                .uri("https://as-api:" + asApiPort)
                ).route(r ->
                        r
                                .path("/open-banking/register")
                                .negate()
                                .and()
                                .host("matls.as.aspsp." + dnsHostRoot + "**")
                                .filters(f -> f
                                        .removeRequestHeader(X_FORWARDED_HOST)
                                        .removeRequestHeader(X_FORWARDED_PROTO)
                                        .setRequestHeader(X_FORWARDED_PROTO, "https")
                                        .setRequestHeader(X_FORWARDED_HOST, amMatlsHostname)
                                        .addRequestHeader("host", amMatlsHostname)
                                        .preserveHostHeader())
                                .uri(amRoute)
                ).route(r ->
                        r
                                .host("as.aspsp." + dnsHostRoot + "**")
                                .and()
                                .path("/oauth2/.well-known/openid-configuration")
                                .filters(f -> f
                                        .filter(addInteractionIdHeaderGatewayFilter, 0)
                                )
                                .uri("https://as-api:" + asApiPort)
                ).route(r ->
                        r
                                .host("as.aspsp." + dnsHostRoot + "**")
                                .filters(f -> f
                                        .filter(addInteractionIdHeaderGatewayFilter, 0)
                                        .removeRequestHeader(X_FORWARDED_HOST)
                                        .removeRequestHeader(X_FORWARDED_PROTO)
                                        .setRequestHeader(X_FORWARDED_PROTO, "https")
                                        .setRequestHeader(X_FORWARDED_HOST, amMatlsHostname)
                                        .addRequestHeader("host", amHostname)
                                        .preserveHostHeader()
                                )
                                .uri(amRoute)
                ).route(r -> {
                            BooleanSpec booleanSpec = r
                                    .host("rs.aspsp." + dnsHostRoot + "**")
                                    .and()
                                    .path("/open-banking/**");

                            booleanSpec.filters(f -> f
                                    .filter(addInteractionIdHeaderGatewayFilter, 0)
                                    .filter(addCertificateHeaderGatewayFilter)
                                    .preserveHostHeader()
                            );
                            return booleanSpec.uri("https://rs-api:" + rsApiPort);
                        }
                ).route(r -> {
                            BooleanSpec booleanSpec = r
                                    .host("rs.aspsp." + dnsHostRoot + "**")
                                    .and()
                                    .path("/**");

                            booleanSpec.filters(f -> f
                                    .filter(addInteractionIdHeaderGatewayFilter)
                                    .preserveHostHeader()
                            );
                            ;
                            return booleanSpec.uri("https://rs-api:" + rsApiPort);
                        }
                ).route(r -> {
                            BooleanSpec booleanSpec = r
                                    .host("matls.rs.aspsp." + dnsHostRoot + "**")
                                    .and()
                                    .path("/open-banking/**");

                            booleanSpec.filters(f -> f
                                    .filter(addInteractionIdHeaderGatewayFilter, 0)
                                    .filter(addCertificateHeaderGatewayFilter)
                                    .preserveHostHeader()
                            );
                            return booleanSpec.uri("https://rs-api:" + rsApiPort);
                        }
                ).route(r -> {
                            BooleanSpec booleanSpec = r
                                    .host("matls.rs.aspsp." + dnsHostRoot + "**")
                                    .and()
                                    .path("/**");

                            booleanSpec.filters(f -> f
                                    .filter(addInteractionIdHeaderGatewayFilter)
                                    .preserveHostHeader()
                            );
                            ;
                            return booleanSpec.uri("https://rs-api:" + rsApiPort);
                        }
                ).route(r ->
                        r
                                .host("jwkms." + dnsHostRoot + "**")
                                .and()
                                .path("/**")
                                .filters(f -> f
                                        .filter(addInteractionIdHeaderGatewayFilter, 0)
                                        .filter(addCertificateHeaderGatewayFilter))
                                .uri("https://jwkms:" + jwkmsPort)
                ).route(r ->
                        r
                                .host("service.directory." + dnsHostRoot + "**")
                                .or()
                                .host("matls.service.directory." + dnsHostRoot + "**")
                                .filters(f -> f
                                        .filter(addInteractionIdHeaderGatewayFilter)
                                        .filter(addCertificateHeaderGatewayFilter))
                                .uri("https://directory-services:" + directoryServicePort)
                ).route(r ->
                        r
                                .host("service.metrics." + dnsHostRoot + "**")
                                .and()
                                .path("/**")
                                .filters(f -> f
                                        .filter(addInteractionIdHeaderGatewayFilter)
                                )
                                .uri("https://metrics-services:" + metricsServicePort)
                ).route(r ->
                        r
                                .host("rcs.aspsp." + dnsHostRoot + "**")
                                .and()
                                .path("/**")
                                .filters(f -> f
                                        .filter(addInteractionIdHeaderGatewayFilter)
                                )
                                .uri("https://rs-rcs:" + rcsPort)
                ).route(r ->
                        r
                                .host("tpp-core." + dnsHostRoot + "**")
                                .and()
                                .path("/**")
                                .filters(f -> f
                                        .filter(addInteractionIdHeaderGatewayFilter)
                                )
                                .uri("https://tpp-core:" + tppCorePort)
                ).route(r ->
                        r
                                .host("shop." + dnsHostRoot + "**")
                                .and()
                                .path("/**")
                                .filters(f -> f
                                        .filter(addInteractionIdHeaderGatewayFilter)
                                )
                                .uri("https://shop:" + shopUiPort)
                ).route(r ->
                        r
                                .host("account." + dnsHostRoot + "**")
                                .and()
                                .path("/**")
                                .filters(f -> f
                                        .filter(addInteractionIdHeaderGatewayFilter)
                                )
                                .uri("https://account:" + accountUIPort)
                ).route(r ->
                        r
                                .host("service.bank." + dnsHostRoot + "**")
                                .and()
                                .path("/**")
                                .filters(f -> f
                                        .filter(addInteractionIdHeaderGatewayFilter, 0)
                                        .filter(addCertificateHeaderGatewayFilter)
                                )
                                .uri("https://rs-ui:" + rsUiPort)
                ).route(r ->
                        r
                                .host("admin." + dnsHostRoot + "**")
                                .and()
                                .path("/**")
                                .filters(f -> f
                                        .filter(addInteractionIdHeaderGatewayFilter, 0)
                                )
                                .uri("https://admin:" + adminPort)
                ).route(r ->
                        r
                                .host("docs." + dnsHostRoot + "**")
                                .and()
                                .path("/**")
                                .filters(f -> f
                                        .filter(addInteractionIdHeaderGatewayFilter, 0)
                                )
                                .uri("https://docs:" + docsPort)
                ).route(r ->
                        r
                                .host("monitoring." + dnsHostRoot + "**")
                                .and()
                                .path("/**")
                                .filters(f -> f
                                        .filter(addInteractionIdHeaderGatewayFilter, 0)
                                )
                                .uri("https://monitoring:" + monitoringPort)
                ).route(r ->
                        r
                                .host("matls.service.bank." + dnsHostRoot + "**")
                                .and()
                                .path("/**")
                                .filters(f -> f
                                        .filter(addInteractionIdHeaderGatewayFilter, 0)
                                        .filter(addCertificateHeaderGatewayFilter)
                                )
                                .uri("https://rs-ui:" + rsUiPort)
                ).route(r ->
                        r
                                .host("service.register." + dnsHostRoot + "**")
                                .and()
                                .path("/**")
                                .filters(f -> f
                                        .filter(addInteractionIdHeaderGatewayFilter, 0)
                                        .filter(addCertificateHeaderGatewayFilter)
                                )
                                .uri("https://register:" + registerPort)
                )
                .build();
    }

    private Function<PredicateSpec, Route.AsyncBuilder> rewriteExternalActuatorToInternal(String externalHost, String internalHost) {
        return r -> r
                .path("/external/actuator/health")
                .or()
                .path("/external/actuator/info")
                .and()
                .host(externalHost)
                .filters(
                        f -> f
                                .rewritePath("external/actuator", "actuator")

                )
                .uri(internalHost);
    }
}
