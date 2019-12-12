/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.monitoring.configuration;

import com.forgerock.openbanking.config.ApplicationConfiguration;
import com.nimbusds.jose.jwk.JWKSet;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class DirectoryConfiguration implements ApplicationConfiguration {

    @Value("${directory.endpoints.authenticate}")
    public String authenticateEndpoint;
    @Value("${directory.endpoints.root}")
    public String rootEndpoint;
    @Value("${directory.endpoints.external.root}")
    public String externalRootEndpoint;
    @Override
    public String getIssuerID() {
        return "directory";
    }

    @Override
    public JWKSet getJwkSet() {
        return null;
    }
}
