package com.kkhosla.springbootsecurityoauth2sso;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;

@SpringBootApplication
@EnableOAuth2Sso
public class SpringBootSecurityOauth2SsoApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringBootSecurityOauth2SsoApplication.class, args);
    }

}

