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
