package com.yeyoo.mall.security;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * @program: mall-auth-service
 * @description: 授权码方式提供商
 * @author: Jin Chun Liang
 * @create: 2020-03-20 14:23
 **/
@Component
public class CodeAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = (String) authentication.getCredentials();
        //如果你是调用user服务，这边不用注掉
        //map = userClient.checkUsernameAndPassword(getUserServicePostObject(username, password, type));
        Map map = this.checkUsernameAndPassword(this.getUserServicePostObject(username, password));

        String userId = (String) map.get("userId");
        if (StringUtils.isBlank(userId)) {
            String errorCode = (String) map.get("code");
            throw new BadCredentialsException(errorCode);
        }
        CustomUserDetails customUserDetails = this.buildCustomUserDetails(username, password, userId);
        return new CustomAuthenticationToken(customUserDetails);
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return true;
    }

    /**
     * 模拟调用user服务的方法
     *
     * @param map
     * @return
     */
    private Map checkUsernameAndPassword(Map map) {
        //checkUsernameAndPassword
        Map ret = new HashMap(16);
        ret.put("userId", UUID.randomUUID().toString());
        return ret;
    }

    /**
    * @description 获取用户服务请求对象
    *
    * @param username
    * @param password
    * @return java.util.Map<java.lang.String,java.lang.String>
    * @author Jin Chun Liang
    * @date 2020/3/20
    */
    private Map<String, String> getUserServicePostObject(String username, String password) {
        Map<String, String> requestParam = new HashMap(16);
        requestParam.put("userName", username);
        requestParam.put("password", password);
        return requestParam;
    }

    /**
    * @description 创建自定义的用户详情信息对象
    *
    * @param username
    * @param password
    * @param userId
    * @return com.yeyoo.mall.security.CustomUserDetails
    * @author Jin Chun Liang
    * @date 2020/3/20
    */
    private CustomUserDetails buildCustomUserDetails(String username, String password, String userId) {
        CustomUserDetails customUserDetails = new CustomUserDetails.CustomUserDetailsBuilder()
                .withUserId(userId)
                .withPassword(password)
                .withUsername(username)
                .withClientId("frontend")
                .build();
        return customUserDetails;
    }

}
