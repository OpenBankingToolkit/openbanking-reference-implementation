/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.monitoring.api.test;

import com.forgerock.openbanking.exceptions.OBErrorResponseException;
import io.swagger.annotations.Api;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

@Api(tags = "Test-users")
@RequestMapping(
        value = "/api/test/user"
)
public interface UserForTestApi {

    @RequestMapping(
            value = "/",
            method = RequestMethod.POST
    )
    ResponseEntity createUser() throws OBErrorResponseException;

    @RequestMapping(
            value = "/",
            method = RequestMethod.DELETE
    )
    ResponseEntity deleteUser(
            @RequestParam(name = "username") String username
    ) throws OBErrorResponseException;
}
