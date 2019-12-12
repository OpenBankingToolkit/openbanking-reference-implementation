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
