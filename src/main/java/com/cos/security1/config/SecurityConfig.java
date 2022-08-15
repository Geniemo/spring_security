package com.cos.security1.config;

import com.cos.security1.oauth.PrincipalOauth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록이 된다.
// @Secured 활성화, @preAuthorize 와 @postAuthorize 활성화
// 예전에는 @preAuthorize 썼었는데 @Secured 가 새로 나와서 얘를 많이 씀
// 특정 하나에다가 걸고 싶다면 @Secured 쓰면 되고 그게 아니라면 configure 메서드에서 글로벌로 걸면 된다.
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final PrincipalOauth2UserService principalOauth2UserService;

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests()
                .antMatchers("/user/**").authenticated()
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll()
                .and()
                .formLogin()
                .loginPage("/loginForm") // 권한 없으면 /loginForm 으로 이동하도록
                .loginProcessingUrl("/login") // login 주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인을 진행해준다.
                .defaultSuccessUrl("/") // a 페이지를 요청하다가 권한이 없어서 로그인 페이지로 왔으면 로그인 시 a 페이지로 이동시켜줌
                .and()
                .oauth2Login()
                .loginPage("/loginForm") // 인증이 필요할 때 로그인 페이지를 지정해놓은 것
                // 구글 로그인이 완료된 후의 후처리가 아직 필요
                // =>   1. 코드 받기(인증)
                //      2. 액세스 토큰(권한)
                //      3. 사용자 프로필 정보 가져오기
                //      4-1. 그 정보를 토대로 회원가입을 자동으로 진행시키기도 함
                //      4-2. 추가적인 정보가 필요하다면 정보 입력을 위한 다른 페이지에서 회원가입을 마저 진행시키기도 한다.
                // Tip. OAuth client 의 기능으로 코드를 받지 않고 액세스 토큰과 사용자 프로필 정보를 한 번에 받을 수 있다.
                .userInfoEndpoint()
                .userService(principalOauth2UserService);
    }
}
