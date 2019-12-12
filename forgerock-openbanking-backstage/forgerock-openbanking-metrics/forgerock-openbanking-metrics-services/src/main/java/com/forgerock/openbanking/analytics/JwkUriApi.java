/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.analytics;

import com.forgerock.openbanking.core.services.ApplicationApiClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JwkUriApi {
    @Autowired
    private ApplicationApiClient applicationApiClient;

    @RequestMapping(value = "/api/metrics/keys/jwk_uri", method = RequestMethod.GET)
    public ResponseEntity<String> getJwkUri() {
        return ResponseEntity.ok(applicationApiClient.signingEncryptionKeysJwkUri("CURRENT"));
    }
}
