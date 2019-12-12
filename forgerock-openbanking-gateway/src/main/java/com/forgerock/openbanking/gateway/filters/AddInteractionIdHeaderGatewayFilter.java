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
package com.forgerock.openbanking.gateway.filters;


import brave.Tracer;
import brave.propagation.ExtraFieldPropagation;
import lombok.extern.slf4j.Slf4j;
import org.codehaus.groovy.runtime.dgmimpl.arrays.FloatArrayPutAtMetaMethod;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Service
@Slf4j
public class AddInteractionIdHeaderGatewayFilter implements GatewayFilter {

    public final static String X_FAPI_INTERACTION_ID_HEADER_NAME = "x-fapi-interaction-id";
    private final static String ANALYTICS_ENABLED_HEADER_NAME = "x-obri-analytics-enabled";

    @Autowired
    private Tracer tracer;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String xFapiInteractionId = request.getHeaders().getFirst(X_FAPI_INTERACTION_ID_HEADER_NAME);
        if (StringUtils.isEmpty(xFapiInteractionId)) {
            log.debug("Interaction ID is missing, generate ID '{}'", xFapiInteractionId);
            xFapiInteractionId = UUID.randomUUID().toString();
        }
        try{
            UUID.fromString(xFapiInteractionId);
        } catch (IllegalArgumentException exception){
            log.warn("User submitted an invalid interaction id '{}: {}'", X_FAPI_INTERACTION_ID_HEADER_NAME, xFapiInteractionId);
            return Mono.error(new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid header: "+X_FAPI_INTERACTION_ID_HEADER_NAME+". This header must be a RFC4122 UID"));
        }

        exchange = exchange.mutate().request(
                exchange.getRequest().mutate().header(X_FAPI_INTERACTION_ID_HEADER_NAME, xFapiInteractionId).build()).build();

        addAnalyticsEnabledTag(request);
        addFapiInteractionTag(xFapiInteractionId);

        log.debug("InteractionID:{}", xFapiInteractionId);
        exchange.getResponse().getHeaders().add(X_FAPI_INTERACTION_ID_HEADER_NAME, xFapiInteractionId);
        return chain.filter(exchange);
    }

    private void addFapiInteractionTag(String xFapiInteractionId) {
        ExtraFieldPropagation.set(tracer.currentSpan().context(), X_FAPI_INTERACTION_ID_HEADER_NAME, xFapiInteractionId);
    }


    private void addAnalyticsEnabledTag(ServerHttpRequest request) {
        //Filter for analytics

        String isAnalyticsEnabled = request.getHeaders().getFirst(ANALYTICS_ENABLED_HEADER_NAME);
        if (isAnalyticsEnabled == null) {
            isAnalyticsEnabled = "true";
        }
        ExtraFieldPropagation.set(tracer.currentSpan().context(), ANALYTICS_ENABLED_HEADER_NAME, isAnalyticsEnabled);
    }
}
