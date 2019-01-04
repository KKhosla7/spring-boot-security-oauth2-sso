package com.kkhosla.springbootsecurityoauth2sso.web.service;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class UserController {
    @GetMapping(value = {"/user", "/me"})
    public Principal user(Principal user) {
        return user;
    }
}
