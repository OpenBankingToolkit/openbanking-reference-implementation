/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.docs.web;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/*")
public class HomeHtmlEndpoints {

    private final String obriDomain;

    public HomeHtmlEndpoints(@Value("${dns.hosts.root}") String obriDomain) {
        this.obriDomain = obriDomain;
    }

    @GetMapping("/")
    public String home(
            Model model) {
        model.addAttribute("obriDomain", obriDomain);
        return "api-guide";
    }

    @GetMapping("/errors")
    public String errors(
            Model model) {

        return "errors";
    }
}
