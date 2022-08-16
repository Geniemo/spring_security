package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

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
        try {
            // 원시적인 방법으로는 아래처럼 할 수도 있긴 하다.
//            BufferedReader br = request.getReader();
//
//            String input = null;
//            while ((input = br.readLine()) != null) {
//                System.out.println("input = " + input);
//            }
            ObjectMapper objectMapper = new ObjectMapper(); // json 데이터 파싱 용 클래스
            User user = objectMapper.readValue(request.getInputStream(), User.class);
            System.out.println("user = " + user);

            // 이렇게 만든 토큰으로 로그인 시도
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
            // 이 때 PrincipalDetailsService 의 loadUserByUsername() 이 실행
            // 실행 후 정상(DB 에 있는 username 과 password 랑 비교해봤을 때 일치)이면 authentication 이 리턴된다.
            Authentication authentication = authenticationManager.authenticate(authenticationToken);
            System.out.println("=============================");
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            // 아래 값이 정상적으로 나왔다면 인증이 정상적으로 됐다는 것
            // 로그인이 되었다는 것이다.
            System.out.println("principalDetails.getUser().getUsername() = " + principalDetails.getUser().getUsername());
            // authentication 객체가 session 영역에 저장, 리턴의 이유는 security 가 권한 관리를 대신 해주기 때문에 편하려고
            // 굳이 jwt 토큰을 사용하며 세션을 만들 이유가 없지만 단지 권한 처리 때문에 session 에 넣는다.
            return authentication;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        // authenticationManager 로 로그인 시도를 하면 PrincipalDetailsService 의 loadUserByUsername 이 실행된다.
        // PrincipalDetails 를 세션에 담고(권한관리가 필요해서, 아니라면 굳이 안해도 됨)
        // jwt 토큰을 만들어서 응답
//        return super.attemptAuthentication(request, response);
    }

    // attemptAuthentication 실행 후 인증이 정상적으로 되었다면 successfulAuthentication 이 실행
    // jwt 토큰을 여기서 만들어서 response 해주면 된다.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("JwtAuthenticationFilter.successfulAuthentication 실행, 인증 완료라는 뜻");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        // RSA 방식이 아니고 Hash 암호 방식, 이 방식은 서버만 알고 있는 시크릿 키를 가지고 있어야 한다.
        String jwtToken = JWT.create()
                .withSubject("cos 토큰") // 토큰 이름
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000 * 10)))
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUsername())
                .sign(Algorithm.HMAC512("cos"));

        response.addHeader("Authorization", "Bearer " + jwtToken);
    }
}
