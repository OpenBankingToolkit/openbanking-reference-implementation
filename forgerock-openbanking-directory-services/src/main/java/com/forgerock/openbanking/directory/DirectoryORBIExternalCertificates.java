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

import com.forgerock.cert.Psd2CertInfo;
import com.forgerock.cert.psd2.RolesOfPsp;
import com.forgerock.openbanking.common.OBRIExternalCertificates;
import com.forgerock.openbanking.directory.service.DirectoryUtilsService;
import com.forgerock.openbanking.model.ApplicationIdentity;
import com.forgerock.openbanking.model.OBRIRole;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import dev.openbanking4.spring.security.multiauth.model.granttypes.PSD2GrantType;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.springframework.security.core.GrantedAuthority;

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import static com.forgerock.openbanking.common.CertificateHelper.isCertificateIssuedByCA;

@Slf4j
public class DirectoryORBIExternalCertificates extends OBRIExternalCertificates {

    private final X509Certificate caCertificate;
    private final DirectoryUtilsService directoryUtilsService;

    public DirectoryORBIExternalCertificates(X509Certificate caCertificate, DirectoryUtilsService directoryUtilsService) {
        super(caCertificate, null, null);
        this.caCertificate = caCertificate;
        this.directoryUtilsService = directoryUtilsService;
    }

    @Override
    public Set<GrantedAuthority> getAuthorities(X509Certificate[] certificatesChain, Psd2CertInfo psd2CertInfo, RolesOfPsp roles) {
        Set<GrantedAuthority> authorities = new HashSet<>();

        if (roles != null) {
            authorities.addAll(roles.getRolesOfPsp().stream().map(PSD2GrantType::new).collect(Collectors.toSet()));
        }

        if (isCertificateIssuedByCA(caCertificate, certificatesChain)) {
            authorities.add(OBRIRole.ROLE_FORGEROCK_EXTERNAL_APP);
        }
        try {
            ApplicationIdentity authenticate = directoryUtilsService.authenticate(JWK.parse(certificatesChain[0]));
            authorities.addAll(authenticate.getRoles());
        } catch (JOSEException | CertificateException e) {
            log.info("Could not parse certificate", e);
        }
        return authorities;
    }

    @Override
    public String getUserName(X509Certificate[] certificatesChain) {
        if (!isCertificateIssuedByCA(caCertificate, certificatesChain)) {
            return null;
        }

        try {
            X500Name x500name = new JcaX509CertificateHolder(certificatesChain[0]).getSubject();
            RDN cn = x500name.getRDNs(BCStyle.CN)[0];
            return IETFUtils.valueToString(cn.getFirst().getValue());
        } catch (CertificateEncodingException e) {
            log.warn("Failed to parse certificate", e);
            return null;
        }
    }
}
