package com.cos.jwt.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CorsFilter corsFilter;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션 사용 X, stateless 서버
                .and()
                .addFilter(corsFilter) // 이렇게 등록까지 하면 모든 ip 를 다 허용하게 해놨으므로 cross origin 요청이 와도 허용한다.
                .formLogin().disable() // jwt 서버니까 폼 로그인 X
                .httpBasic().disable() // Authorization 에 ID 랑 PW 를 담아서 요청하는 것(httpBasic)을 disable.
                                        // 여기서 구현할 것은 Authorization 에 token 을 담는 Bearer 방식
                .authorizeRequests()
                // 유저쪽으로는 USER, MANAGER, ADMIN 가능
                .antMatchers("/api/v1/user/**").access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                // 매니저쪽으로는 MANAGER, ADMIN 가능
                .antMatchers("/api/v1/manager/**").access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                // 어드민쪽으로는 ADMIN 가능
                .antMatchers("/api/v1/admin/**").access("hasRole('ROLE_ADMIN')")
                // 다른 것들은 허용
                .anyRequest().permitAll();
    }
}
