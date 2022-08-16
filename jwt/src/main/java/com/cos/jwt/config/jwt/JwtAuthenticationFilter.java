package com.cos.jwt.config.jwt;

import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// 스프링 시큐리티에 UsernamePasswordAuthenticationFilter 가 있음
// /login 요청해서 username, password 를 전송하면 (post)
// UsernamePasswordAuthenticationFilter 필터가 동작하는데 지금 formLogin.disable() 을 해놨기 때문에 동작하지 않음
// 따라서 SecurityConfig 에서 addFilter 로 등록해줘야 한다.
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    
    // login 요청을 하면 로그인 시도를 위해 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter.attemptAuthentication");
        
        // username, password 를 받아서 정상인지 로그인 시도를 해보는 것
        // authenticationManager 로 로그인 시도를 하면 PrincipalDetailsService 의 loadUserByUsername 이 실행된다.
        // PrincipalDetails 를 세션에 담고(권한관리가 필요해서, 아니라면 굳이 안해도 됨)
        // jwt 토큰을 만들어서 응답
        return super.attemptAuthentication(request, response);
    }
}
