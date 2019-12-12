/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.gateway.model;

import com.nimbusds.jwt.JWTClaimsSet;

import java.text.ParseException;
import java.util.HashSet;
import java.util.Set;

public class Tpp {
    public String id;
    public String directoryId;
    public String name;
    public String officialName;
    private String certificateCn;
    private String clientId;
    private String ssa;
    private String tppRequest;

    private Set<Type> types = new HashSet<>();

    public enum Type {
        AISP, PISP
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getOfficialName() {
        return officialName;
    }

    public void setOfficialName(String officialName) {
        this.officialName = officialName;
    }

    public String getCertificateCn() {
        return certificateCn;
    }

    public void setCertificateCn(String certificateCn) {
        this.certificateCn = certificateCn;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public Set<Type> getTypes() {
        return types;
    }

    public void setTypes(Set<Type> type) {
        this.types = type;
    }

    public void addType(Type type) {
        types.add(type);
    }

    public String getSsa() {
        return ssa;
    }

    public JWTClaimsSet getSsaClaim() throws ParseException {
        return JWTClaimsSet.parse(ssa);
    }

    public void setSsa(String ssa) {
        this.ssa = ssa;
    }

    public String getTppRequest() {
        return tppRequest;
    }

    public void setTppRequest(String tppRequest) {
        this.tppRequest = tppRequest;
    }

    public String getDirectoryId() {
        return directoryId;
    }

    public void setDirectoryId(String directoryId) {
        this.directoryId = directoryId;
    }

    @Override
    public String toString() {
        return "Tpp{" +
                "id='" + id + '\'' +
                ", name='" + name + '\'' +
                ", certificateCn='" + certificateCn + '\'' +
                ", officialName='" + officialName + '\'' +
                ", clientId='" + clientId + '\'' +
                ", ssa='" + ssa + '\'' +
                ", tppRequest='" + tppRequest + '\'' +
                ", types=" + types +
                '}';
    }
}
