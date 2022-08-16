package com.cos.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true); // 내 서버가 응답을 할 때 json 을 자바스크립트에서 처리할 수 있게 할지 설정
        config.addAllowedOrigin("*"); // 모든 곳에서의 요청을 다 받아들인다.
        config.addAllowedHeader("*"); // 모든 헤더를 다 받는다.
        config.addAllowedMethod("*"); // 모든 메서드를 다 허용한다.
        source.registerCorsConfiguration("/api/**", config); // /api/** 로 오는 요청은 모두 이 필터를 거치도록 한다.
        return new CorsFilter(source);
    }
}
