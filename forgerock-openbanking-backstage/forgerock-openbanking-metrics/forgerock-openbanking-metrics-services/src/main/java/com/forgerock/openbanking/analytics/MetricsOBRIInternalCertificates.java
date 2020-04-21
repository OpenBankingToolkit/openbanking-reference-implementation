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
package com.forgerock.openbanking.analytics;

import com.forgerock.cert.Psd2CertInfo;
import com.forgerock.cert.psd2.RolesOfPsp;
import com.forgerock.openbanking.common.OBRICertificates;
import com.forgerock.openbanking.model.OBRIRole;
import dev.openbanking4.spring.security.multiauth.model.granttypes.PSD2GrantType;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;

import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import static com.forgerock.openbanking.common.CertificateHelper.getCn;
import static com.forgerock.openbanking.common.CertificateHelper.isCertificateIssuedByCA;

/**
 * A specific variation of {@link com.forgerock.openbanking.common.OBRIInternalCertificates} for the metrics-application-services.
 */
@Slf4j
@AllArgsConstructor
class MetricsOBRIInternalCertificates implements OBRICertificates {

    private X509Certificate caCertificate;

    @Override
    public Set<GrantedAuthority> getAuthorities(X509Certificate[] certificatesChain, Psd2CertInfo psd2CertInfo, RolesOfPsp roles) {
        Set<GrantedAuthority> authorities = new HashSet<>();

        if (roles != null) {
            authorities.addAll(roles.getRolesOfPsp().stream().map(r -> new PSD2GrantType(r)).collect(Collectors.toSet()));
        }

        if (isCertificateIssuedByCA(caCertificate, certificatesChain)) {
            authorities.add(OBRIRole.ROLE_FORGEROCK_INTERNAL_APP);
            authorities.add(AnalyticsAuthority.PUSH_KPI);
            authorities.add(AnalyticsAuthority.READ_KPI);
        }
        return authorities;
    }

    @Override
    public String getUserName(X509Certificate[] certificatesChain) {
        if (!isCertificateIssuedByCA(caCertificate, certificatesChain)) {
            return null;
        }
        return getCn(certificatesChain[0]);
    }

    enum AnalyticsAuthority implements GrantedAuthority {
        PUSH_KPI,
        READ_KPI;

        @Override
        public String getAuthority() {
            return name();
        }
    }
}