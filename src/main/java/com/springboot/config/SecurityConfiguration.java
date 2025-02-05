package com.springboot.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
public class SecurityConfiguration {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
//                inmemory 사용일때만 필요합니다.frameOptions()
                .headers().frameOptions().sameOrigin()
                .and()
                .csrf().disable()
//                기본설정을 따라갈게요. 기본설정을 위한 정보는 우리가 만들어야 합니다. default 메서드를 따라간다.
                .cors(Customizer.withDefaults())
//                formLogin 페이지 안쓸게요 세션방식 X
                .formLogin().disable()
//                id,패스워드를 헤더에 담는 방식 안쓸게요 (옛날방식이다.)
                .httpBasic().disable()
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().permitAll());

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
//     .cors(Customizer.withDefaults()) 얘를 따라간다.
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
//        어떤 origin이든 cors 발생 안시킬게요
        configuration.setAllowedOrigins(Arrays.asList("*"));
//        origin이 다를 떄는 GET","POST","PATCH","DELETE 이 네개의 요청만 받을게요
        configuration.setAllowedMethods(List.of("GET","POST","PATCH","DELETE"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//        소스에 등록
        source.registerCorsConfiguration("/**",configuration);
        return source;
    }
}
