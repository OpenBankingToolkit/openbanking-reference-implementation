/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.gateway.filters;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.cloud.gateway.filter.factory.SetStatusGatewayFilterFactory;
import org.springframework.cloud.gateway.support.HttpStatusHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

@Component
@Slf4j
public class AbortWithStatusGatewayFilterFactory extends AbstractGatewayFilterFactory<SetStatusGatewayFilterFactory.Config> {

    public AbortWithStatusGatewayFilterFactory() {
        super(SetStatusGatewayFilterFactory.Config.class);
    }

    @Override
    public GatewayFilter apply(SetStatusGatewayFilterFactory.Config config) {
        HttpStatusHolder statusHolder = HttpStatusHolder.parse(config.getStatus());
        return (exchange, chain) -> {
            log.info("Aborting request [{}] with status [{}]", exchange.getRequest().getPath(), statusHolder.getHttpStatus().value());
            return Mono.error(new ResponseStatusException(statusHolder.getHttpStatus()));
        };
    }

    @Override
    public String name() {
        return "Abort";
    }

}
