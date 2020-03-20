package com.yeyoo.mall.security;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

/**
 * @program: mall-auth-service
 * @description: 自定义访问令牌增强器
 * @author: Jin Chun Liang
 * @create: 2020-03-20 13:32
 **/
public class CustomTokenEnhancer extends JwtAccessTokenConverter implements Serializable {
    private static final String TOKEN_SEG_USER_ID = "X-KAKA-UserId";
    private static final String TOKEN_SEG_CLIENT = "X-KAKA-ClientId";

    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        authentication.getUserAuthentication().getPrincipal();
        Map<String, Object> info = new HashMap();
        info.put(TOKEN_SEG_USER_ID, userDetails.getUserId());

        DefaultOAuth2AccessToken customAccessToken = new DefaultOAuth2AccessToken(accessToken);
        customAccessToken.setAdditionalInformation(info);

        OAuth2AccessToken enhancedToken = super.enhance(customAccessToken, authentication);
        enhancedToken.getAdditionalInformation().put(TOKEN_SEG_CLIENT, userDetails.getClientId());
        return enhancedToken;
    }
}
