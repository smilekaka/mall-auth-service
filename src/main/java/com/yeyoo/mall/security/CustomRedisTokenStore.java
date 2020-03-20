package com.yeyoo.mall.security;

import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.DefaultAuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.JdkSerializationStrategy;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStoreSerializationStrategy;

import java.util.*;

/**
 * @program: mall-auth-service
 * @description: 自定义的Redis方式存储Token
 * @author: Jin Chun Liang
 * @create: 2020-03-20 09:34
 **/
public class CustomRedisTokenStore implements TokenStore {
    private static final String ACCESS = "access:";
    private static final String AUTH = "auth:";
    private static final String AUTH_TO_ACCESS = "auth_to_access:";
    private static final String REFRESH = "refresh:";
    private static final String REFRESH_AUTH = "refresh_auth:";
    private static final String REFRESH_TO_ACCESS = "refresh_to_access:";
    private static final String CLIENT_ID_TO_ACCESS = "client_id_to_access:";
    private static final String USERNAME_TO_ACCESS = "username_to_access:";

    private final RedisConnectionFactory connectionFactory;

    /**
     * 认证key生成器
     */
    private AuthenticationKeyGenerator authenticationKeyGenerator = new DefaultAuthenticationKeyGenerator();

    /**
     * 序列化策略
     */
    private RedisTokenStoreSerializationStrategy serializationStrategy = new JdkSerializationStrategy();

    private String prefix = "";

    public CustomRedisTokenStore(RedisConnectionFactory connectionFactory) {
        this.connectionFactory = connectionFactory;
    }

    /**
     * @param token
     * @return org.springframework.security.oauth2.provider.OAuth2Authentication
     * @description 读取认证信息
     * @author Jin Chun Liang
     * @date 2020/3/20
     */
    @Override
    public OAuth2Authentication readAuthentication(OAuth2AccessToken token) {
        return readAuthentication(token.getValue());
    }

    /**
     * @param tokenValue
     * @return org.springframework.security.oauth2.provider.OAuth2Authentication
     * @description 读取认证信息
     * @author Jin Chun Liang
     * @date 2020/3/20
     */
    @Override
    public OAuth2Authentication readAuthentication(String tokenValue) {
        byte[] bytes = null;
        RedisConnection conn = this.getConnection();
        try {
            bytes = conn.get(this.serializeKey(AUTH + tokenValue));
        } finally {
            conn.close();
        }
        OAuth2Authentication auth = this.deserializeAuthentication(bytes);
        return auth;
    }

    /**
    * @description 存储访问令牌
    *
    * @param token
    * @param authentication
    * @return void
    * @author Jin Chun Liang
    * @date 2020/3/20
    */
    @Override
    public void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
        byte[] serializedAccessToken = serialize(token);
        byte[] serializedAuth = serialize(authentication);
        byte[] accessKey = serializeKey(ACCESS + token.getValue());
        byte[] authKey = serializeKey(AUTH + token.getValue());
        byte[] authToAccessKey = serializeKey(AUTH_TO_ACCESS + authenticationKeyGenerator.extractKey(authentication));
//        byte[] approvalKey = serializeKey(UNAME_TO_ACCESS + getApprovalKey(authentication));
//        byte[] clientId = serializeKey(CLIENT_ID_TO_ACCESS + authentication.getOAuth2Request().getClientId());

        RedisConnection conn = getConnection();
        try {
            conn.openPipeline();
            conn.stringCommands().set(accessKey, serializedAccessToken);
            conn.stringCommands().set(authKey, serializedAuth);
            conn.stringCommands().set(authToAccessKey, serializedAccessToken);
//            if (!authentication.isClientOnly()) {
//                conn.rPush(approvalKey, serializedAccessToken);
//            }
//            conn.rPush(clientId, serializedAccessToken);
            if (token.getExpiration() != null) {
                int seconds = token.getExpiresIn();
                conn.expire(accessKey, seconds);
                conn.expire(authKey, seconds);
                conn.expire(authToAccessKey, seconds);
//                conn.expire(clientId, seconds);
//                conn.expire(approvalKey, seconds);
            }
            OAuth2RefreshToken refreshToken = token.getRefreshToken();
            if (refreshToken != null && refreshToken.getValue() != null) {
//                byte[] refresh = serialize(token.getRefreshToken().getValue());
                byte[] auth = serialize(token.getValue());
                byte[] refreshToAccessKey = serializeKey(REFRESH_TO_ACCESS + token.getRefreshToken().getValue());
                conn.stringCommands().set(refreshToAccessKey, auth);
//                byte[] accessToRefreshKey = serializeKey(ACCESS_TO_REFRESH + token.getValue());
//                conn.stringCommands().set(accessToRefreshKey, refresh);
                if (refreshToken instanceof ExpiringOAuth2RefreshToken) {
                    ExpiringOAuth2RefreshToken expiringRefreshToken = (ExpiringOAuth2RefreshToken) refreshToken;
                    Date expiration = expiringRefreshToken.getExpiration();
                    if (expiration != null) {
                        int seconds = Long.valueOf((expiration.getTime() - System.currentTimeMillis()) / 1000L)
                                .intValue();
                        conn.expire(refreshToAccessKey, seconds);
//                        conn.expire(accessToRefreshKey, seconds);
                    }
                }
            }
            conn.closePipeline();
        } finally {
            conn.close();
        }
    }

    /**
    * @description 读取访问令牌
    *
    * @param tokenValue
    * @return org.springframework.security.oauth2.common.OAuth2AccessToken
    * @author Jin Chun Liang
    * @date 2020/3/20
    */
    @Override
    public OAuth2AccessToken readAccessToken(String tokenValue) {
        byte[] key = serializeKey(ACCESS + tokenValue);
        byte[] bytes = null;
        RedisConnection conn = getConnection();
        try {
            bytes = conn.get(key);
        } finally {
            conn.close();
        }
        OAuth2AccessToken accessToken = deserializeAccessToken(bytes);
        return accessToken;
    }

    /**
    * @description 获取访问令牌
    *
    * @param authentication
    * @return org.springframework.security.oauth2.common.OAuth2AccessToken
    * @author Jin Chun Liang
    * @date 2020/3/20
    */
    @Override
    public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
        String key = authenticationKeyGenerator.extractKey(authentication);
        byte[] serializedKey = serializeKey(AUTH_TO_ACCESS + key);
        byte[] bytes = this.getBytesFromRedis(serializedKey);
        OAuth2AccessToken accessToken = deserializeAccessToken(bytes);
        if (accessToken != null) {
            OAuth2Authentication storedAuthentication = this.readAuthentication(accessToken.getValue());
            if ((storedAuthentication == null || !key.equals(authenticationKeyGenerator.extractKey(storedAuthentication)))) {
                // Keep the stores consistent (maybe the same user is
                // represented by this authentication but the details have
                // changed)
                storeAccessToken(accessToken, authentication);
            }

        }
        return accessToken;
    }

    /**
    * @description 删除访问令牌
    *
    * @param token
    * @return void
    * @author Jin Chun Liang
    * @date 2020/3/20
    */
    @Override
    public void removeAccessToken(OAuth2AccessToken token) {
        removeAccessToken(token.getValue());
    }

    /**
    * @description 存储刷新令牌
    *
    * @param refreshToken
    * @param authentication
    * @return void
    * @author Jin Chun Liang
    * @date 2020/3/20
    */
    @Override
    public void storeRefreshToken(OAuth2RefreshToken refreshToken, OAuth2Authentication authentication) {
        byte[] refreshKey = serializeKey(REFRESH + refreshToken.getValue());
        byte[] refreshAuthKey = serializeKey(REFRESH_AUTH + refreshToken.getValue());
        byte[] serializedRefreshToken = serialize(refreshToken);
        RedisConnection conn = getConnection();
        try {
            conn.openPipeline();
            conn.stringCommands().set(refreshKey, serializedRefreshToken);
            conn.stringCommands().set(refreshAuthKey, serialize(authentication));
            if (refreshToken instanceof ExpiringOAuth2RefreshToken) {
                ExpiringOAuth2RefreshToken expiringRefreshToken = (ExpiringOAuth2RefreshToken) refreshToken;
                Date expiration = expiringRefreshToken.getExpiration();
                if (expiration != null) {
                    int seconds = Long.valueOf((expiration.getTime() - System.currentTimeMillis()) / 1000L)
                            .intValue();
                    conn.expire(refreshKey, seconds);
                    conn.expire(refreshAuthKey, seconds);
                }
            }
            conn.closePipeline();
        } finally {
            conn.close();
        }
    }

    /**
    * @description 读取刷新令牌
    *
    * @param tokenValue
    * @return org.springframework.security.oauth2.common.OAuth2RefreshToken
    * @author Jin Chun Liang
    * @date 2020/3/20
    */
    @Override
    public OAuth2RefreshToken readRefreshToken(String tokenValue) {
        byte[] key = this.serializeKey(REFRESH + tokenValue);
        byte[] bytes = this.getBytesFromRedis(key);
        OAuth2RefreshToken refreshToken = deserializeRefreshToken(bytes);
        return refreshToken;
    }

    /**
    * @description 删除刷新令牌
    *
    * @param refreshToken
    * @return void
    * @author Jin Chun Liang
    * @date 2020/3/20
    */
    @Override
    public void removeRefreshToken(OAuth2RefreshToken refreshToken) {
        this.removeRefreshToken(refreshToken.getValue());
    }

    /**
    * @description 读取关于刷新令牌的认证信息
    *
    * @param refreshToken
    * @return org.springframework.security.oauth2.provider.OAuth2Authentication
    * @author Jin Chun Liang
    * @date 2020/3/20
    */
    @Override
    public OAuth2Authentication readAuthenticationForRefreshToken(OAuth2RefreshToken refreshToken) {
        return this.readAuthenticationForRefreshToken(refreshToken.getValue());
    }

    /**
    * @description 根据刷新令牌删除访问令牌
    *
    * @param refreshToken
    * @return void
    * @author Jin Chun Liang
    * @date 2020/3/20
    */
    @Override
    public void removeAccessTokenUsingRefreshToken(OAuth2RefreshToken refreshToken) {
        this.removeAccessTokenUsingRefreshToken(refreshToken.getValue());
    }

    /**
    * @description 根据客户端ID查询令牌集合信息
    *
    * @param clientId 客户端ID
    * @return java.util.Collection<org.springframework.security.oauth2.common.OAuth2AccessToken>
    * @author Jin Chun Liang
    * @date 2020/3/20
    */
    @Override
    public Collection<OAuth2AccessToken> findTokensByClientId(String clientId) {
        byte[] key = this.serializeKey(CLIENT_ID_TO_ACCESS + clientId);
        return this.getTokensByKeyBytes(key);
    }

    /**
    * @description 根据客户端ID和用户名查询令牌集合信息
    *
    * @param clientId
    * @param userName
    * @return java.util.Collection<org.springframework.security.oauth2.common.OAuth2AccessToken>
    * @author Jin Chun Liang
    * @date 2020/3/20
    */
    @Override
    public Collection<OAuth2AccessToken> findTokensByClientIdAndUserName(String clientId, String userName) {
        byte[] approvalKey = this.serializeKey(USERNAME_TO_ACCESS + getApprovalKey(clientId, userName));
        return this.getTokensByKeyBytes(approvalKey);
    }

    /**
    * @description 获取Redis连接
    *
    * @param
    * @return org.springframework.data.redis.connection.RedisConnection
    * @author Jin Chun Liang
    * @date 2020/3/20
    */
    private RedisConnection getConnection() {
        return connectionFactory.getConnection();
    }

    /**
    * @description 序列化key
    *
    * @param key
    * @return byte[]
    * @author Jin Chun Liang
    * @date 2020/3/20
    */
    private byte[] serializeKey(String key) {
        return serialize(prefix + key);
    }

    /**
    * @description 序列化对象
    *
    * @param object
    * @return byte[]
    * @author Jin Chun Liang
    * @date 2020/3/20
    */
    private byte[] serialize(Object object) {
        return serializationStrategy.serialize(object);
    }

    /**
    * @description 序列化字符串
    *
    * @param string
    * @return byte[]
    * @author Jin Chun Liang
    * @date 2020/3/20
    */
    private byte[] serialize(String string) {
        return serializationStrategy.serialize(string);
    }

    /**
    * @description 反序列化字符串
    *
    * @param bytes
    * @return java.lang.String
    * @author Jin Chun Liang
    * @date 2020/3/20
    */
    private String deserializeString(byte[] bytes) {
        return serializationStrategy.deserializeString(bytes);
    }

    /**
    * @description 反序列化字节数组为访问令牌
    *
    * @param bytes
    * @return org.springframework.security.oauth2.common.OAuth2AccessToken
    * @author Jin Chun Liang
    * @date 2020/3/20
    */
    private OAuth2AccessToken deserializeAccessToken(byte[] bytes) {
        return serializationStrategy.deserialize(bytes, OAuth2AccessToken.class);
    }

    /**
    * @description 反序列化字节数组为刷新令牌
    *
    * @param bytes
    * @return org.springframework.security.oauth2.common.OAuth2RefreshToken
    * @author Jin Chun Liang
    * @date 2020/3/20
    */
    private OAuth2RefreshToken deserializeRefreshToken(byte[] bytes) {
        return serializationStrategy.deserialize(bytes, OAuth2RefreshToken.class);
    }

    /**
    * @description 反序列化字节数组为认证信息
    *
    * @param bytes
    * @return org.springframework.security.oauth2.provider.OAuth2Authentication
    * @author Jin Chun Liang
    * @date 2020/3/20
    */
    private OAuth2Authentication deserializeAuthentication(byte[] bytes) {
        return serializationStrategy.deserialize(bytes, OAuth2Authentication.class);
    }

    /**
     * @description 删除访问令牌
     *
     * @param tokenValue
     * @return void
     * @author Jin Chun Liang
     * @date 2020/3/20
     */
    private void removeAccessToken(String tokenValue) {
        byte[] accessKey = serializeKey(ACCESS + tokenValue);
        byte[] authKey = serializeKey(AUTH + tokenValue);
//        byte[] accessToRefreshKey = serializeKey(ACCESS_TO_REFRESH + tokenValue);
        RedisConnection conn = getConnection();
        try {
            conn.openPipeline();
            conn.get(accessKey);
            conn.get(authKey);
            conn.del(accessKey);
//            conn.del(accessToRefreshKey);
            // Don't remove the refresh token - it's up to the caller to do that
            conn.del(authKey);
            List<Object> results = conn.closePipeline();
//            byte[] access = (byte[]) results.get(0);
            byte[] auth = (byte[]) results.get(1);

            OAuth2Authentication authentication = deserializeAuthentication(auth);
            if (authentication != null) {
                String key = authenticationKeyGenerator.extractKey(authentication);
                byte[] authToAccessKey = serializeKey(AUTH_TO_ACCESS + key);
//                byte[] unameKey = serializeKey(UNAME_TO_ACCESS + getApprovalKey(authentication));
//                byte[] clientId = serializeKey(CLIENT_ID_TO_ACCESS + authentication.getOAuth2Request().getClientId());
                conn.openPipeline();
                conn.del(authToAccessKey);
//                conn.lRem(unameKey, 1, access);
//                conn.lRem(clientId, 1, access);
                conn.del(serialize(ACCESS + key));
                conn.closePipeline();
            }
        } finally {
            conn.close();
        }
    }

    /**
    * @description 删除刷新令牌
    *
    * @param tokenValue
    * @return void
    * @author Jin Chun Liang
    * @date 2020/3/20
    */
    private void removeRefreshToken(String tokenValue) {
        byte[] refreshKey = serializeKey(REFRESH + tokenValue);
        byte[] refreshAuthKey = serializeKey(REFRESH_AUTH + tokenValue);
        byte[] refresh2AccessKey = serializeKey(REFRESH_TO_ACCESS + tokenValue);
//        byte[] access2RefreshKey = serializeKey(ACCESS_TO_REFRESH + tokenValue);
        RedisConnection conn = getConnection();
        try {
            conn.openPipeline();
            conn.del(refreshKey);
            conn.del(refreshAuthKey);
            conn.del(refresh2AccessKey);
//            conn.del(access2RefreshKey);
            conn.closePipeline();
        } finally {
            conn.close();
        }
    }

    /**
    * @description 根据刷新令牌删除访问令牌信息
    *
    * @param refreshToken
    * @return void
    * @author Jin Chun Liang
    * @date 2020/3/20
    */
    private void removeAccessTokenUsingRefreshToken(String refreshToken) {
        byte[] key = serializeKey(REFRESH_TO_ACCESS + refreshToken);
        List<Object> results = null;
        RedisConnection conn = getConnection();
        try {
            conn.openPipeline();
            conn.get(key);
            conn.del(key);
            results = conn.closePipeline();
        } finally {
            conn.close();
        }
        if (results == null) {
            return;
        }
        byte[] bytes = (byte[]) results.get(0);
        String accessToken = this.deserializeString(bytes);
        if (accessToken != null) {
            removeAccessToken(accessToken);
        }
    }

    /**
    * @description 读取关于刷新令牌的认证信息
    *
    * @param token
    * @return org.springframework.security.oauth2.provider.OAuth2Authentication
    * @author Jin Chun Liang
    * @date 2020/3/20
    */
    private OAuth2Authentication readAuthenticationForRefreshToken(String token) {
        RedisConnection conn = this.getConnection();
        try {
            byte[] bytes = conn.get(this.serializeKey(REFRESH_AUTH + token));
            return this.deserializeAuthentication(bytes);
        } finally {
            conn.close();
        }
    }

    /**
    * @description
    *
    * @param clientId
    * @param userName
    * @return java.lang.String
    * @author Jin Chun Liang
    * @date 2020/3/20
    */
    private static String getApprovalKey(String clientId, String userName) {
        return clientId + (userName == null ? "" : ":" + userName);
    }

    /**
     * @description 从Redis中获取字节数组
     *
     * @param serializedKey
     * @return byte[]
     * @author Jin Chun Liang
     * @date 2020/3/20
     */
    private byte[] getBytesFromRedis(byte[] serializedKey){
        byte[] bytes = null;
        RedisConnection conn = this.getConnection();
        try {
            bytes = conn.get(serializedKey);
        } finally {
            conn.close();
        }
        return bytes;
    }

    /**
     * @description 从Redis中获取字节列表
     *
     * @param key
     * @return java.util.List<byte[]>
     * @author Jin Chun Liang
     * @date 2020/3/20
     */
    private List<byte[]> getByteListFromRedis(byte[] key){
        List<byte[]> byteList = null;
        RedisConnection conn = getConnection();
        try {
            byteList = conn.lRange(key, 0, -1);
        } finally {
            conn.close();
        }
        return byteList;
    }

    /**
    * @description 根据字节数组获取访问令牌信息集合
    *
    * @param key
    * @return java.util.Collection<org.springframework.security.oauth2.common.OAuth2AccessToken>
    * @author Jin Chun Liang
    * @date 2020/3/20
    */
    private Collection<OAuth2AccessToken> getTokensByKeyBytes(byte[] key){
        List<byte[]> byteList = this.getByteListFromRedis(key);
        if (byteList == null || byteList.size() == 0) {
            return Collections.emptySet();
        }
        List<OAuth2AccessToken> accessTokens = new ArrayList<OAuth2AccessToken>(byteList.size());
        for (byte[] bytes : byteList) {
            OAuth2AccessToken accessToken = deserializeAccessToken(bytes);
            accessTokens.add(accessToken);
        }
        return Collections.unmodifiableCollection(accessTokens);
    }

}
