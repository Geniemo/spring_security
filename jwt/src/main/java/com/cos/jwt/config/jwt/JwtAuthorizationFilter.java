package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// 시큐리티가 필터를 가지고 있는데 그 중 BasicAuthenticationFilter 라는 것이 있다.
// 권한이나 인증이 필요한 특정 주소를 요청했을 때 위 필터를 무조건 타게 되어 있다.
// 만약 권한이나 인증이 필요한 주소가 아니라면 이 필터를 안탄다.
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    // 인증이나 권한이 필요한 주소 요청이 있을 때 해당 필터를 타게 된다.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("인증이나 권한이 필요한 주소 요청");

        String jwtHeader = request.getHeader("Authorization");
        System.out.println("jwtHeader = " + jwtHeader);

        // header 가 있는지 확인
        if (jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
            chain.doFilter(request, response);
            return;
        }

        // jwt 토큰 검증 해서 정상적 사용자인지 확인
        String jwtToken = jwtHeader.replace("Bearer ", "");
        System.out.println("jwtToken = " + jwtToken);
        String username = JWT.require(Algorithm.HMAC512("cos")).build().verify(jwtToken).getClaim("username").asString();
        // 서명이 제대로 됐는지 검사
        if (username != null) {
            User userEntity = userRepository.findByUsername(username);
            System.out.println("userEntity = " + userEntity);
            System.out.println("userEntity.getRoleList() = " + userEntity.getRoleList());
            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
            System.out.println("principalDetails = " + principalDetails);
            System.out.println("principalDetails.getAuthorities() = " + principalDetails.getAuthorities());
            // jwt 토큰 서명을 통해 서명이 정상이면 Authentication 객체 생성
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    principalDetails, // 나중에 컨트롤러에서 DI 해서 쓸 때 편하다.
                    null, // 패스워드는 모르니까 null 처리, 어차피 지금 인증하는 게 아니니까
                    principalDetails.getAuthorities());
            // 강제로 시큐리티 세션에 접근해 Authentication 객체 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);
            chain.doFilter(request, response);
        }
    }
}
