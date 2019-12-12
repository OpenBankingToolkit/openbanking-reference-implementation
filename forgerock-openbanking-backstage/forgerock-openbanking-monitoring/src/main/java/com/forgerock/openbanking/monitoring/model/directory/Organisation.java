/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.monitoring.model.directory;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Data
@AllArgsConstructor
@Builder
@Document
public class Organisation {

    @Id
    private String id;
    private String name;
    private List<Contact> contacts;
    private Status status;
    private String description;
    private String jwkUri;
    private String revokedJwkUri;
    private List<String> softwareStatementIds;

    @CreatedDate
    public Date created;
    @LastModifiedDate
    public Date updated;

    public enum Status {
        ACTIVE, REVOKED, WITHDRAWN
    }

    public Organisation() {
        status = Status.ACTIVE;
        contacts = new ArrayList<>();
        softwareStatementIds = new ArrayList<>();
    }
}
