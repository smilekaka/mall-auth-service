package com.yeyoo.mall.config;

import com.yeyoo.mall.security.CustomAuthorizationTokenServices;
import com.yeyoo.mall.security.CustomRedisTokenStore;
import com.yeyoo.mall.security.CustomTokenEnhancer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import javax.sql.DataSource;

/**
 * @program: mall-auth-service
 * @description: 认证授权服务器配置类
 * @author: Jin Chun Liang
 * @create: 2020-03-20 08:49
 **/
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private AuthenticationManager authenticationManager;

//    @Autowired
//    private WebResponseExceptionTranslator webResponseExceptionTranslator;

    /**
     * 数据源
     */
    @Autowired
    private DataSource dataSource;

    /**
     * Redis连接工厂
     */
    @Autowired
    private RedisConnectionFactory redisConnectionFactory;

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        // 3 配置身份认证器
        endpoints.authenticationManager(authenticationManager)
                // 配置Token存储方式
                .tokenStore(tokenStore(redisConnectionFactory))
                // 令牌服务
                .tokenServices(authorizationServerTokenServices())
                // 访问Token转换器
                .accessTokenConverter(accessTokenConverter())
                // 允许 GET、POST 请求获取 token，即访问端点：oauth/token
                .allowedTokenEndpointRequestMethods(HttpMethod.GET, HttpMethod.POST);
                // 异常翻译器
//                .exceptionTranslator(webResponseExceptionTranslator);
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        // 4 配置客户端认证方式（数据库方式）
        clients.withClientDetails(clientDetailsService());
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        //允许表单认证
        security.allowFormAuthenticationForClients()
                .tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()");
    }

    @Bean
    public JdbcClientDetailsService clientDetailsService() {
        // 1 创建数据库服务
        return new JdbcClientDetailsService(dataSource);
    }

    @Bean
    public TokenStore tokenStore(RedisConnectionFactory redisConnectionFactory) {
        // 2 自定义令牌存储方式
        return new CustomRedisTokenStore(redisConnectionFactory);
    }

    @Bean
    public AuthorizationServerTokenServices authorizationServerTokenServices() {
        CustomAuthorizationTokenServices customTokenServices = new CustomAuthorizationTokenServices();
        customTokenServices.setTokenStore(tokenStore(redisConnectionFactory));
        customTokenServices.setSupportRefreshToken(true);
        customTokenServices.setReuseRefreshToken(false);
        customTokenServices.setClientDetailsService(clientDetailsService());
        customTokenServices.setAccessTokenEnhancer(accessTokenConverter());
        return customTokenServices;
    }

    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter converter = new CustomTokenEnhancer();
        converter.setSigningKey("secret");
        return converter;
    }

}
