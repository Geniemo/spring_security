package com.cos.jwt.config;

import com.cos.jwt.filter.MyFilter1;
import com.cos.jwt.filter.MyFilter3;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CorsFilter corsFilter;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 특정 필터가 어디에 들어갈지는 필터 체인을 확인해보고 원하는 위치에 넣으면 된다.
        // FilterConfig 에서 등록한 필터들은 기본적으로 스프링 시큐리티 필터 체인 이후에 들어간다.
        // 토큰 인증 필터를 거의 제일 앞에 있는 UsernamePasswordAuthenticationFilter 앞에서 실행되게 한다.
        // 토큰: cos(지금은 임시로 설정해놓은 것) 이걸 만들어줘야 한다. id, pw 가 정상적으로 들어와서 로그인이 완료되면 토큰을 만들어주고 그걸 응답해준다.
        // 요청할 때마다 header 에 Authorization 에 value 값으로 토큰을 가지고 온다.
        // 토큰이 넘어오면 이 토큰이 내가 만든 토큰이 맞는지만 검증하면 된다. (RSA, HS256)
        http.addFilterBefore(new MyFilter3(), UsernamePasswordAuthenticationFilter.class);
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
