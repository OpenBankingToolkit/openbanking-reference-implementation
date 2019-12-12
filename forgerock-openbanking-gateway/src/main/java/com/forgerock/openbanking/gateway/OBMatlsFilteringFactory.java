/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.gateway;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.GatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

@Component
public class OBMatlsFilteringFactory implements GatewayFilterFactory {
    private static final Logger LOGGER = LoggerFactory.getLogger(OBMatlsFilteringFactory.class);

    @Override
    public GatewayFilter apply(Object config) {
        return (exchange, chain) -> {

            LOGGER.debug("Coucou!");

            ServerHttpRequest request = exchange.getRequest().mutate()
                    .build();

            return chain.filter(exchange.mutate().request(request).build());
        };
    }
}
