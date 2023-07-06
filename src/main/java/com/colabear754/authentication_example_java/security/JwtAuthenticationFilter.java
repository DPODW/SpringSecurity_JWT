package com.colabear754.authentication_example_java.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;


import java.io.IOException;
import java.util.List;
import java.util.Optional;

@Order(0) //필터의 우선순위를 지정한다. 낮을수록 높다 (현재 필터의 우선순위는 무조건)
@RequiredArgsConstructor
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    //OncePerRequestFilter: 요청 당 한 번의 실행을 보장하는 필터 -> 불필요하게 필터를 거치지 않게 하기 위함
    //인증 같은건 한번만 필터링 되어도 충분하니까
    private final TokenProvider tokenProvider;


    @Override //OncePerRequestFilter 사용시 꼭 재정의 해야하는 doFilterInternal 메소드
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String token = parseBearerToken(request);
        User user = parseUserSpecification(token);
        AbstractAuthenticationToken authenticated = UsernamePasswordAuthenticationToken.authenticated(user, token, user.getAuthorities());
        authenticated.setDetails(new WebAuthenticationDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authenticated);

        filterChain.doFilter(request, response);
    }
/**
 * bearer -> 토큰을 사용하는 방식 (어떻게 토큰을 사용할 것인지)
 * jwt -> 실질적인 토큰
 * */

    //bearer 토큰 방식으로 받은 jwt 를 필요한 부분만 추출하는 메소드 (일반적으로 jwt 는 bearer 안에서 사용된다)
    //토큰에서 실질적인 토큰 값을 추출하기 위한 기능
    private String parseBearerToken(HttpServletRequest request) {
        return Optional.ofNullable(request.getHeader(HttpHeaders.AUTHORIZATION))
                .filter(token -> token.substring(0, 7).equalsIgnoreCase("Bearer "))
                .map(token -> token.substring(7))
                .orElse(null);
    }
    /**
     * Optional.ofNullable 를 사용하여서 AUTHORIZATION 헤더 값이 null 인지 확인한다.
     * filter 를 사용하여서 헤더 값의 첫 7개의 문자가 "Bearer" 과 일치하는지 확인한다.
     * map 을 사용하여서 "Bearer" 를 제외한 나머지 토큰값(실질적인 토큰값) 을 반환한다.
     *
     * Bearer 토큰이 없거나 조건에 맞지 않는 경우에는 null 을 반환
     * */

    // 주어진 토큰을 해석하여 사용자 정보를 생성하여 반환하는 메서드이다.
    private User parseUserSpecification(String token) {
        String[] split = Optional.ofNullable(token)
                .filter(subject -> subject.length() >= 10)
                .map(tokenProvider::validateTokenAndGetSubject)
                .orElse("anonymous:anonymous")
                .split(":");
        return new User(split[0], "", List.of(new SimpleGrantedAuthority(split[1])));
    }
    /**
     *  Optional.ofNullable(token) 을 통하여 토큰이 null 인지 확인, null 이 아닌 경우에만 다음 작업을 진행한다.
     *  filter 기능을 사용하여서 토큰의 길이가 10 이상인지 확인, 토큰의 길이가 충분히 길어야 유효한 토큰으로 간주한다.
     *  ㄴ > 즉, 토큰이 null 아니면서 너무 짧지 않아야 유효한 것이다.
     *
     *  위의 조건을 만족하면, .map(tokenProvider::validateTokenAndGetSubject) 를 통하여 토큰 복호화를 진행한다. **추가 공부 필요
     *  만약 위의 조건에 만족하지 않는다면, 익명 사용자 (익명 user 객체) 를 생성한다.
     *
     *  split(":")를 사용하여 토큰을 ":"으로 분리하여 배열로 반환 -> 첫번재 요소는 사용자 이름, 두번째 요소는 권한이다.
     *
     *  최종적으로 User의 사용자 이름에는 배열의 첫번째(0) 이름을 넣고, 비밀번호는 공백, 권한에는 split[1]을 단일 요소로 갖는 리스트로 설정한다. **권한 추가 공부 필요
     *
     *  결과적으로, parseUserSpecification 메서드는 주어진 토큰을 해석하여 사용자 정보를 생성하고, 생성된 User 객체를 반환
     *
     * */
}
