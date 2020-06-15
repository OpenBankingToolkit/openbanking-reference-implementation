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
package com.forgerock.openbanking.directory;

import brave.Tracer;
import com.forgerock.openbanking.common.EnableSslClient;
import com.forgerock.openbanking.directory.error.ErrorHandler;
import com.forgerock.openbanking.directory.security.FormValueSanitisationFilter;
import com.forgerock.openbanking.directory.security.JsonRequestSanitisiationFilter;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.FilterType;
import org.springframework.context.annotation.Import;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import javax.servlet.Filter;

@SpringBootApplication
@ComponentScan(
        basePackages = "com.forgerock.openbanking",
        // beans under com.forgerock.openbanking.common (such as AspspApiClientImpl) clash with equivalent ones in com.forgerock.openbanking.directory
        excludeFilters = @ComponentScan.Filter(type= FilterType.REGEX, pattern="com\\.forgerock\\.openbanking\\.common\\..*"))
@EnableMongoRepositories
@EnableSwagger2
@EnableDiscoveryClient
@EnableScheduling
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@EnableSslClient
@Import(DirectoryApplicationSecurityConfiguration.class)
public class ForgerockOpenbankingDirectoryApplication {

    public static void main(String[] args) {
        SpringApplication.run(ForgerockOpenbankingDirectoryApplication.class, args);
    }

    @Bean
    public Filter jsonSanitisationFilter(ErrorHandler errorHandler, Tracer tracer) {
        return new JsonRequestSanitisiationFilter(errorHandler, tracer);
    }

    @Bean
    public Filter formSanitisationFilter(ErrorHandler errorHandler, Tracer tracer) {
        return new FormValueSanitisationFilter(errorHandler, tracer);
    }

}
