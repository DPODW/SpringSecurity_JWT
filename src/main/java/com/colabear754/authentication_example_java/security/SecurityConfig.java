package com.colabear754.authentication_example_java.security;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@RequiredArgsConstructor
@Configuration
@EnableMethodSecurity
public class SecurityConfig {
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final String[] allowedUrls = {"/", "/swagger-ui/**", "/v3/**", "/sign-up", "/sign-in"};

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws  Exception{
        return http
                .csrf().disable()
                .headers(headers -> headers.frameOptions().sameOrigin())
                .authorizeHttpRequests(requests ->
                        requests.requestMatchers(allowedUrls).permitAll()	// requestMatchers의 인자로 전달된 url은 모두에게 허용
                                .requestMatchers(PathRequest.toH2Console()).permitAll()	// H2 콘솔 접속은 모두에게 허용
                                .anyRequest().authenticated()	// 그 외의 모든 요청은 인증 필요
                )
                .sessionManagement(sessionManagement ->
                        sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )	// 세션을 사용하지 않으므로 STATELESS 설정
                .addFilterBefore(jwtAuthenticationFilter, BasicAuthenticationFilter.class)
                .build();
    }
}
/** code 해석 (filterChain)
 * 1. csrf 공격 방지 사용 X
 *
 * 2. X-Frame-Options 의 헤더값을 sameOrigin 으로 설정.
 *    ㄴ> 동일한 출처를 가진 프레임만 해당 페이지가 로드될수록 허용한다는 의미
 *    * X-Frame-Options :  웹 페이지가 다른 웹 페이지의 <frame>, <iframe>, <object> 요소 내에서 로드되는 것을 제어하기 위한 HTTP 응답 헤더
 *
 * 3. HTTP 요청에 대한 인가 규칙을 설정하는 부분
 * ( ~~ ) 내부 경로에 대한 요청은 모든 사용자에게 허용된다. (배열로 설정)
 * (H2~~) H2 콘솔에 대한 요청은 모든 사용자에게 허용된다.
 *
 * 4. SESSION 관리 설정 코드로, SESSION 을 STATELESS 로 설정하여 세션 생성을 하지 않는다.
 *
 * 5. 메소드 시큐리티 활성화 (커스텀 시큐리티로 추정)
 * */