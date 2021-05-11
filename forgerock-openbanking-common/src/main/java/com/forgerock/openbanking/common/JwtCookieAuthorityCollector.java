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
package com.forgerock.openbanking.common;

import com.forgerock.openbanking.model.OBRIRole;
import com.google.common.collect.Sets;
import com.nimbusds.jwt.JWT;
import com.forgerock.spring.security.multiauth.configurers.collectors.CustomCookieCollector;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.text.ParseException;
import java.util.List;
import java.util.Set;

/*
 * Adding the default authorities.
 * Adding the authorities coming from Forgerock AM JWT Cookie authentication if exist authorities.
 * FYI: Additional Authorities setted on Claim 'group' set in 'identity / MSISDN Number'.
 */
@Slf4j
public class JwtCookieAuthorityCollector implements CustomCookieCollector.AuthoritiesCollector<JWT> {

    @Override
    public Set<GrantedAuthority> getAuthorities(JWT token) throws ParseException {
        Set<GrantedAuthority> authorities = Sets.newHashSet(
                OBRIRole.ROLE_SOFTWARE_STATEMENT,
                OBRIRole.ROLE_USER);
        List<String> amGroups = token.getJWTClaimsSet().getStringListClaim("group");
        if (amGroups != null && !amGroups.isEmpty()) {
            log.trace("AM Authorities founds: {}", amGroups);
            for (String amGroup : amGroups) {
                authorities.add(new SimpleGrantedAuthority(amGroup));
            }
        }
        return authorities;
    }
}
