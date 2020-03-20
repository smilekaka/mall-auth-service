package com.yeyoo.mall.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;

/**
 * @program: mall-auth-service
 * @description: 自定义的认证令牌类
 * @author: Jin Chun Liang
 * @create: 2020-03-20 14:31
 **/
public class CustomAuthenticationToken extends AbstractAuthenticationToken {

    private CustomUserDetails userDetails;

    public CustomAuthenticationToken(CustomUserDetails userDetails) {
        super(null);
        this.userDetails = userDetails;
        super.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return this.userDetails.getPassword();
    }

    @Override
    public Object getPrincipal() {
        return this.userDetails;
    }
}
