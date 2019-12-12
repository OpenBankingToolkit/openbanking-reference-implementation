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
package com.forgerock.openbanking.gateway.model;


import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ApplicationIdentity {

    private String id;
    private List<String> roles = new ArrayList<>();
    private DirectorySrc directorySrc;

    public ApplicationIdentity() {}

    public ApplicationIdentity(String id, List<String> roles) {
       this(id, roles, DirectorySrc.FORGEROCK);
    }

    public ApplicationIdentity(String id, List<String> roles, DirectorySrc directorySrc) {
        this.id = id;
        this.roles = roles;
        this.directorySrc = directorySrc;
    }

    public ApplicationIdentity(String id, String role, DirectorySrc directorySrc) {
        this(id, Arrays.asList(role), DirectorySrc.FORGEROCK);
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void addRole(String role) {
        this.roles.add(role);
    }
    public void setRoles(List<String> roles) {
        this.roles = roles;
    }

    public DirectorySrc getDirectorySrc() {
        return directorySrc;
    }

    public void setDirectorySrc(DirectorySrc directorySrc) {
        this.directorySrc = directorySrc;
    }

    public enum DirectorySrc {
        FORGEROCK, OPEN_BANKING
    }

    @Override
    public String toString() {
        return "ApplicationIdentity{" +
                "id='" + id + '\'' +
                ", roles=" + roles +
                ", directorySrc=" + directorySrc +
                '}';
    }
}
