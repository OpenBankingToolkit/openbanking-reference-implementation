/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.gateway.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.cors.reactive.CorsUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.net.URI;

@Configuration
@Slf4j
public class CorsConfiguration {

    private static final String ALLOWED_HEADERS = "accept-api-version, x-requested-with, authorization, Content-Type, Authorization, credential, X-XSRF-TOKEN, Id-Token";
    private static final String ALLOWED_METHODS = "GET, PUT, POST, DELETE, OPTIONS";
    private static final String ALLOWED_ORIGIN = "*";
    private static final Boolean ALLOWED_CREDENTIAL = true;
    private static final String MAX_AGE = "3600";

    @Value("${dns.hosts.root}")
    private String hostRoot;
    @Bean
    public WebFilter corsFilter() {
        return (ServerWebExchange ctx, WebFilterChain chain) -> {
            ServerHttpRequest request = ctx.getRequest();
            if (CorsUtils.isCorsRequest(request)) {
                ServerHttpResponse response = ctx.getResponse();
                HttpHeaders headers = response.getHeaders();

                URI uri = URI.create(request.getHeaders().getFirst("Origin"));
                if (!uri.getHost().endsWith(hostRoot)) {
                    log.warn("Host from origin header {} is not matching the expected host root {}", uri.getHost(), hostRoot);
                    response.setStatusCode(HttpStatus.UNAUTHORIZED);
                    return Mono.empty();
                }

                headers.add("Access-Control-Allow-Origin", request.getHeaders().getFirst("Origin"));
                headers.add("Access-Control-Allow-Methods", ALLOWED_METHODS);
                headers.add("Access-Control-Max-Age", MAX_AGE);
                headers.add("Access-Control-Allow-Headers",ALLOWED_HEADERS);
                headers.add("Access-Control-Allow-Credentials", ALLOWED_CREDENTIAL.toString());
                if (request.getMethod() == HttpMethod.OPTIONS) {
                    response.setStatusCode(HttpStatus.OK);
                    return Mono.empty();
                }
            }
            return chain.filter(ctx);
        };
    }

}