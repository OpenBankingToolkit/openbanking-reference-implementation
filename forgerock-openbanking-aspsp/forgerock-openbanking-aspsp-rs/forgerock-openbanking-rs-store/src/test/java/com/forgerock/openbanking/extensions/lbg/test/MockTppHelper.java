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
package com.forgerock.openbanking.extensions.lbg.test;

import com.forgerock.openbanking.repositories.TppRepository;
import com.forgerock.openbanking.model.Tpp;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

public class MockTppHelper {

    public static final String MOCK_CLIENT_ID = "pispId123";
    public static final String MOCK_PISP_NAME = "testPisp";
    public static final String MOCK_PISP_ID = "55555";

    public static void setupMockTpp(TppRepository tppRepository) {
        Tpp tpp = new Tpp();
        tpp.officialName = MOCK_PISP_NAME;
        tpp.id = MOCK_PISP_ID;
        when(tppRepository.findByClientId(eq(MOCK_CLIENT_ID))).thenReturn(tpp);
    }
}
