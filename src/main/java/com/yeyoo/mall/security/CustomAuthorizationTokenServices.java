package com.yeyoo.mall.security;

import lombok.Setter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.*;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.Set;
import java.util.UUID;

/**
 * @program: mall-auth-service
 * @description: 自定义的授权令牌服务类
 * @author: Jin Chun Liang
 * @create: 2020-03-20 12:57
 **/
public class CustomAuthorizationTokenServices implements AuthorizationServerTokenServices, ConsumerTokenServices {
    /**
     * default 30 days. （刷新令牌默认有效期一个月）
     */
    private int refreshTokenValiditySeconds = 60 * 60 * 24 * 30;

    /**
     * default 12 hours.
     */
    private int accessTokenValiditySeconds = 60 * 60 * 12;

    @Setter
    private boolean supportRefreshToken;

    @Setter
    private boolean reuseRefreshToken = true;

    @Setter
    private TokenStore tokenStore;

    @Setter
    private ClientDetailsService clientDetailsService;

    @Setter
    private TokenEnhancer accessTokenEnhancer;

    private AuthenticationManager authenticationManager;

    /**
    * @description 创建访问令牌
    *
    * @param authentication
    * @return org.springframework.security.oauth2.common.OAuth2AccessToken
    * @author Jin Chun Liang
    * @date 2020/3/20
    */
    @Override
    @Transactional
    public OAuth2AccessToken createAccessToken(OAuth2Authentication authentication) throws AuthenticationException {
        // 通过TokenStore，获取现存的accessToken
        OAuth2AccessToken existingAccessToken = tokenStore.getAccessToken(authentication);
        OAuth2RefreshToken refreshToken;
        // 移除已有的accessToken和refreshToken
        if (existingAccessToken != null) {
            if (existingAccessToken.getRefreshToken() != null) {
                refreshToken = existingAccessToken.getRefreshToken();
                tokenStore.removeRefreshToken(refreshToken);
            }
            tokenStore.removeAccessToken(existingAccessToken);
        }
        //recreate a refreshToken
        refreshToken = createRefreshToken(authentication);

        OAuth2AccessToken accessToken = this.createAccessToken(authentication, refreshToken);
        if (accessToken != null) {
            tokenStore.storeAccessToken(accessToken, authentication);
        }
        refreshToken = accessToken.getRefreshToken();
        if (refreshToken != null) {
            tokenStore.storeRefreshToken(refreshToken, authentication);
        }
        return accessToken;
    }

    /**
    * @description 刷新访问令牌
    *
    * @param refreshTokenValue
    * @param tokenRequest
    * @return org.springframework.security.oauth2.common.OAuth2AccessToken
    * @author Jin Chun Liang
    * @date 2020/3/20
    */
    @Override
    @Transactional(noRollbackFor = {InvalidTokenException.class, InvalidGrantException.class})
    public OAuth2AccessToken refreshAccessToken(String refreshTokenValue, TokenRequest tokenRequest) throws AuthenticationException {
        if (!supportRefreshToken) {
            throw new InvalidGrantException("Invalid refresh token: " + refreshTokenValue);
        }

        OAuth2RefreshToken refreshToken = tokenStore.readRefreshToken(refreshTokenValue);
        if (refreshToken == null) {
            throw new InvalidGrantException("Invalid refresh token: " + refreshTokenValue);
        }

        OAuth2Authentication authentication = tokenStore.readAuthenticationForRefreshToken(refreshToken);
        if (this.authenticationManager != null && !authentication.isClientOnly()) {
            Authentication user = new PreAuthenticatedAuthenticationToken(authentication.getUserAuthentication(), "", authentication.getAuthorities());

            // Overrides this section, because he followed std's oAuth2 refresh token mechanism to skip the scope of use check.changes
            //user = authenticationManager.authenticate(user);
            Object details = authentication.getDetails();
            authentication = new OAuth2Authentication(authentication.getOAuth2Request(), user);
            authentication.setDetails(details);
        }
        String clientId = authentication.getOAuth2Request().getClientId();
        if (clientId == null || !clientId.equals(tokenRequest.getClientId())) {
            throw new InvalidGrantException("Wrong client for this refresh token: " + refreshTokenValue);
        }

        // clear out any access tokens already associated with the refresh
        // token.
        tokenStore.removeAccessTokenUsingRefreshToken(refreshToken);

        if (isExpired(refreshToken)) {
            tokenStore.removeRefreshToken(refreshToken);
            throw new InvalidTokenException("Invalid refresh token (expired): " + refreshToken);
        }

        authentication = this.createRefreshedAuthentication(authentication, tokenRequest);

        if (!reuseRefreshToken) {
            tokenStore.removeRefreshToken(refreshToken);
            refreshToken = createRefreshToken(authentication);
        }

        OAuth2AccessToken accessToken = createAccessToken(authentication, refreshToken);
        tokenStore.storeAccessToken(accessToken, authentication);
        if (!reuseRefreshToken) {
            tokenStore.storeRefreshToken(accessToken.getRefreshToken(), authentication);
        }
        return accessToken;
    }

    @Override
    public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
        return tokenStore.getAccessToken(authentication);
    }

    @Override
    public boolean revokeToken(String tokenValue) {
        OAuth2AccessToken accessToken = tokenStore.readAccessToken(tokenValue);
        if (accessToken == null) {
            return false;
        }
        if (accessToken.getRefreshToken() != null) {
            tokenStore.removeRefreshToken(accessToken.getRefreshToken());
        }
        tokenStore.removeAccessToken(accessToken);
        return true;
    }

    /**
    * @description 创建访问令牌
    *
    * @param authentication
    * @param refreshToken
    * @return org.springframework.security.oauth2.common.OAuth2AccessToken
    * @author Jin Chun Liang
    * @date 2020/3/20
    */
    private OAuth2AccessToken createAccessToken(OAuth2Authentication authentication, OAuth2RefreshToken refreshToken) {
        DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken(UUID.randomUUID().toString());
        int validitySeconds = getAccessTokenValiditySeconds(authentication.getOAuth2Request());
        if (validitySeconds > 0) {
            token.setExpiration(new Date(System.currentTimeMillis() + (validitySeconds * 1000L)));
        }
        token.setRefreshToken(refreshToken);
        token.setScope(authentication.getOAuth2Request().getScope());

        return accessTokenEnhancer != null ? accessTokenEnhancer.enhance(token, authentication) : token;
    }

    /**
    * @description 创建刷新令牌
    *
    * @param authentication
    * @return org.springframework.security.oauth2.common.OAuth2RefreshToken
    * @author Jin Chun Liang
    * @date 2020/3/20
    */
    private OAuth2RefreshToken createRefreshToken(OAuth2Authentication authentication) {
        if (!isSupportRefreshToken(authentication.getOAuth2Request())) {
            return null;
        }
        int validitySeconds = getRefreshTokenValiditySeconds(authentication.getOAuth2Request());
        String value = UUID.randomUUID().toString();
        if (validitySeconds > 0) {
            return new DefaultExpiringOAuth2RefreshToken(value, new Date(System.currentTimeMillis()
                    + (validitySeconds * 1000L)));
        }
        return new DefaultOAuth2RefreshToken(value);
    }

    /**
    * @description 校验是否支持刷新令牌
    *
    * @param clientAuth
    * @return boolean
    * @author Jin Chun Liang
    * @date 2020/3/20
    */
    protected boolean isSupportRefreshToken(OAuth2Request clientAuth) {
        if (clientDetailsService != null) {
            ClientDetails client = clientDetailsService.loadClientByClientId(clientAuth.getClientId());
            return client.getAuthorizedGrantTypes().contains("refresh_token");
        }
        return this.supportRefreshToken;
    }

    /**
    * @description 获取访问令牌的有效秒数（校验访问令牌有效性）
    *
    * @param clientAuth
    * @return int
    * @author Jin Chun Liang
    * @date 2020/3/20
    */
    protected int getAccessTokenValiditySeconds(OAuth2Request clientAuth) {
        if (clientDetailsService != null) {
            ClientDetails client = clientDetailsService.loadClientByClientId(clientAuth.getClientId());
            Integer validity = client.getAccessTokenValiditySeconds();
            if (validity != null) {
                return validity;
            }
        }
        return accessTokenValiditySeconds;
    }

    /**
    * @description 获取刷新令牌的有效秒数（校验访问令牌有效性）
    *
    * @param clientAuth
    * @return int
    * @author Jin Chun Liang
    * @date 2020/3/20
    */
    protected int getRefreshTokenValiditySeconds(OAuth2Request clientAuth) {
        if (clientDetailsService != null) {
            ClientDetails client = clientDetailsService.loadClientByClientId(clientAuth.getClientId());
            Integer validity = client.getRefreshTokenValiditySeconds();
            if (validity != null) {
                return validity;
            }
        }
        return refreshTokenValiditySeconds;
    }

    /**
    * @description 校验刷新令牌是否有效
    *
    * @param refreshToken
    * @return boolean
    * @author Jin Chun Liang
    * @date 2020/3/20
    */
    protected boolean isExpired(OAuth2RefreshToken refreshToken) {
        if (refreshToken instanceof ExpiringOAuth2RefreshToken) {
            ExpiringOAuth2RefreshToken expiringToken = (ExpiringOAuth2RefreshToken) refreshToken;
            return expiringToken.getExpiration() == null || System.currentTimeMillis() > expiringToken.getExpiration().getTime();
        }
        return false;
    }

    /**
    * @description
    *
    * @param authentication
    * @param request
    * @return org.springframework.security.oauth2.provider.OAuth2Authentication
    * @author Jin Chun Liang
    * @date 2020/3/20
    */
    private OAuth2Authentication createRefreshedAuthentication(OAuth2Authentication authentication, TokenRequest request) {
        OAuth2Authentication narrowed = authentication;
        Set<String> scope = request.getScope();
        OAuth2Request clientAuth = authentication.getOAuth2Request().refresh(request);
        if (scope != null && !scope.isEmpty()) {
            Set<String> originalScope = clientAuth.getScope();
            if (originalScope == null || !originalScope.containsAll(scope)) {
                throw new InvalidScopeException("Unable to narrow the scope of the client authentication to " + scope
                        + ".", originalScope);
            } else {
                clientAuth = clientAuth.narrowScope(scope);
            }
        }
        narrowed = new OAuth2Authentication(clientAuth, authentication.getUserAuthentication());
        return narrowed;
    }
}
