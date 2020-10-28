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
package com.forgerock.openbanking.aspsp.rs.store;

import com.forgerock.openbanking.aspsp.rs.store.repository.ManualRegistrationApplicationRepository;
import com.forgerock.openbanking.repositories.TppRepository;
import com.forgerock.openbanking.common.CookieWebSecurityConfiguration;
import com.forgerock.openbanking.common.EnableSslClient;
import com.forgerock.openbanking.common.model.onboarding.ManualRegistrationApplication;
import com.forgerock.openbanking.model.Tpp;
import com.github.mongobee.Mongobee;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.data.mongodb.config.EnableMongoAuditing;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;
import org.springframework.data.rest.core.config.RepositoryRestConfiguration;
import org.springframework.data.rest.webmvc.config.RepositoryRestConfigurer;
import org.springframework.data.rest.webmvc.config.RepositoryRestConfigurerAdapter;

@SpringBootApplication(scanBasePackages = "com.forgerock.openbanking")
@EnableMongoRepositories
@EnableMongoAuditing
@EnableDiscoveryClient
@EnableSslClient
@Import(CookieWebSecurityConfiguration.class)
public class ForgerockOpenbankingRsStoreApplication{

    public static void main(String[] args) {
        SpringApplication.run(ForgerockOpenbankingRsStoreApplication.class, args);
    }

    @Bean
    public RepositoryRestConfigurer repositoryRestConfigurer() {

        return new RepositoryRestConfigurerAdapter() {
            @Override
            public void configureRepositoryRestConfiguration(
                    RepositoryRestConfiguration config) {
                config.exposeIdsFor(TppRepository.class, Tpp.class);
                config.exposeIdsFor(ManualRegistrationApplicationRepository.class, ManualRegistrationApplication.class);
            }
        };
    }

    @Bean
    @ConditionalOnProperty(prefix = "rs", name = "mongo-migration.enabled", havingValue = "true")
    public Mongobee mongobee(@Value("${spring.data.mongodb.uri}") String mongoDbUrl, MongoTemplate mongoTemplate){
        Mongobee mongobee = new Mongobee(mongoDbUrl);
        mongobee.setChangeLogsScanPackage("com.forgerock.openbanking.aspsp.rs.store.repository");
        mongobee.setMongoTemplate(mongoTemplate);
        return mongobee;
    }

}
