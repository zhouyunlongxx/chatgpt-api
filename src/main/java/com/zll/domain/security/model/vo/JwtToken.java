package com.zll.domain.security.model.vo;

import lombok.Getter;
import lombok.Setter;
import org.apache.shiro.authc.AuthenticationToken;

@Getter
@Setter
public class JwtToken implements AuthenticationToken {
    private static final long serialVersionUID = 1L;

    // JSON WEB TOKEN
    private String jwt;

    public JwtToken(String jwt) {
        this.jwt = jwt;
    }

    @Override
    public Object getPrincipal() {
        return jwt;
    }

    @Override
    public Object getCredentials() {
        return jwt;
    }
}

