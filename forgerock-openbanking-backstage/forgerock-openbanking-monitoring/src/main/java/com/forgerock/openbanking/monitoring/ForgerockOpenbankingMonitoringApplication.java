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

import com.forgerock.openbanking.common.AuthWebSecurityConfiguration;
import com.forgerock.openbanking.common.EnableSslClient;
import com.google.common.cache.CacheBuilder;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.Cache;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;
import org.springframework.scheduling.annotation.EnableScheduling;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import java.util.concurrent.TimeUnit;

@SpringBootApplication(scanBasePackages = "com.forgerock.openbanking")
@EnableSwagger2
@EnableDiscoveryClient
@EnableScheduling
@EnableCaching
@EnableMongoRepositories
@EnableSslClient
@Import(AuthWebSecurityConfiguration.class)
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
}
