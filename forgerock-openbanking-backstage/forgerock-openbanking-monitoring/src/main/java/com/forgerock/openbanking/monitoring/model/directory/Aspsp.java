/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.monitoring.model.directory;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Data
@Document
public class Aspsp {
    @Id
    private String id;
    @JsonProperty("name")
    private String name;
    @JsonProperty("logo_uri")
    private String logoUri;
    @JsonProperty("financial_id")
    private String financialId;
    @JsonProperty("as_discovery_endpoint")
    private String asDiscoveryEndpoint;
    @JsonProperty("rs_discovery_endpoint")
    private String rsDiscoveryEndpoint;
    @JsonProperty("test_mtls_endpoint")
    private String testMtlsEndpoint;
    @JsonProperty("transport_keys")
    private String transportKeys;
}
