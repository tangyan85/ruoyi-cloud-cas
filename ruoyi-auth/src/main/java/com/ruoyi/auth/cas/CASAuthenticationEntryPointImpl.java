package com.ruoyi.auth.cas;

import com.alibaba.fastjson.JSON;
import com.ruoyi.common.core.constant.HttpStatus;
import com.ruoyi.common.core.web.domain.AjaxResult;
import com.ruoyi.common.core.utils.ServletUtils;
import com.ruoyi.common.core.utils.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Serializable;

/**
 * 认证失败处理类 返回未授权
 *
 * @author xu
 */
@Component
public class CASAuthenticationEntryPointImpl implements AuthenticationEntryPoint, Serializable
{
    private static final long serialVersionUID = -8970718410437077606L;

    @Autowired
    private CasProperties casProperties;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e)
            throws IOException
    {
        StringBuffer requestURL = request.getRequestURL();
        System.out.println("requestURL=>"+requestURL);
        int code = HttpStatus.UNAUTHORIZED;
        String msg = StringUtils.format("请求访问：{}，认证失败，无法访问系统资源", request.getRequestURI());
        AjaxResult error = AjaxResult.error(code, msg);
        error.put("loginUrl",casProperties.getCasServerLoginUrl()+"?service="+casProperties.getAppServerUrl() + casProperties.getAppLoginUrl());
        ServletUtils.renderString(response, JSON.toJSONString(error));
    }
}