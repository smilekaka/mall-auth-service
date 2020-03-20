package com.yeyoo.mall.security;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

/**
 * @program: mall-auth-service
 * @description: 自定义用户详情信息类
 * @author: Jin Chun Liang
 * @create: 2020-03-20 13:35
 **/
public class CustomUserDetails implements UserDetails {

    @Setter
    private String username;

    @Setter
    private String password;

    private boolean enabled = true;

    @Setter
    @Getter
    private String userId;
    @Setter
    @Getter
    private String clientId;

    @Setter
    private Collection<? extends GrantedAuthority> authorities;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    public static class CustomUserDetailsBuilder {
        private CustomUserDetails userDetails = new CustomUserDetails();

        public CustomUserDetailsBuilder withUsername(String username) {
            userDetails.setUsername(username);
            userDetails.setAuthorities(null);
            return this;
        }

        public CustomUserDetailsBuilder withPassword(String password) {
            userDetails.setPassword(password);
            return this;
        }

        public CustomUserDetailsBuilder withClientId(String clientId) {
            userDetails.setClientId(clientId);
            return this;
        }

        public CustomUserDetailsBuilder withUserId(String userId) {
            userDetails.setUserId(userId);
            return this;
        }

        public CustomUserDetails build() {
            return userDetails;
        }
    }
}
