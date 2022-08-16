package com.cos.jwt.filter;


import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("필터3");
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;

        if (httpServletRequest.getMethod().equalsIgnoreCase("post")) {
            String headerAuth = httpServletRequest.getHeader("Authorization");
            System.out.println("headerAuth = " + headerAuth);
            if (headerAuth.equals("cos")) {
                chain.doFilter(httpServletRequest, httpServletResponse);
            } else {
                PrintWriter outPrintWriter = httpServletResponse.getWriter();
                outPrintWriter.println("인증안됨");
            }
        }
    }
}
