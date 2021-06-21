package com.ruoyi.auth.service;

import com.ruoyi.common.security.service.TokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.cas.authentication.CasAssertionAuthenticationToken;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.HashSet;

/**
 * 用于加载用户信息 实现UserDetailsService接口，或者实现AuthenticationUserDetailsService接口
 *
 * @author xu
 */
public class CustomUserDetailsService implements AuthenticationUserDetailsService<CasAssertionAuthenticationToken> {

    private static final Logger log = LoggerFactory.getLogger(CustomUserDetailsService.class);

    @Autowired
    private SysLoginService sysLoginService;

    @Autowired
    private TokenService tokenService;

    /**
     * 加载登录用户的信息
     *
     * @param token
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserDetails(CasAssertionAuthenticationToken token) throws UsernameNotFoundException {
        System.out.println("当前的用户名是：" + token.getName());
        String username = token.getName();
        return new User(username,"",new HashSet<>());
    }

}