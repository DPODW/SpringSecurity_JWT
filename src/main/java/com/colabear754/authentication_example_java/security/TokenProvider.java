package com.colabear754.authentication_example_java.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.el.parser.Token;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Service;

import javax.crypto.spec.SecretKeySpec;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Date;

@PropertySource("classpath:jwt.yml") //프로퍼티 값을 받아올 파일 지정 (yml)
@Service
public class TokenProvider {
    private final String secretKey;
    private final long expirationHours;
    private final String issuer;

    public TokenProvider(
            //프로퍼티 값 (jwt 값) 을 jwt 변수에 삽입
            @Value("${secret-key}") String secretKey,
            @Value("${expiration-hours}") long expirationHours,
            @Value("${issuer}") String issuer
    ){
        //생성자
        this.secretKey = secretKey;
        this.expirationHours = expirationHours;
        this.issuer = issuer;
    }

    public String createToken(String userSpecification) {
        return Jwts.builder()
                .signWith(new SecretKeySpec(secretKey.getBytes(), SignatureAlgorithm.HS512.getJcaName()))   // HS512 알고리즘을 사용하여 secretKey를 이용해 서명
                .setSubject(userSpecification)  // JWT 토큰 제목 (주로 토큰에 포함될 사용자 정보를 지정)
                .setIssuer(issuer)  // JWT 토큰 발급자
                .setIssuedAt(Timestamp.valueOf(LocalDateTime.now()))    // JWT 토큰 발급 시간 (현재 시간)
                .setExpiration(Date.from(Instant.now().plus(expirationHours, ChronoUnit.HOURS)))    // JWT 토큰 만료 시간
                .compact(); // JWT 토큰 생성
    }

    public String validateTokenAndGetSubject(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey.getBytes())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    /**
     * validateTokenAndGetSubject()는 비밀키를 토대로 createToken()에서 토큰에 담은 Subject 를 복호화하여 문자열 형태로 반환하는 메소드이다.
     *
     * 그리고 이 Subject 에는 SignService 의 singIn()에서 토큰을 생성할 때 인자로 넘긴 "{회원 ID}:{회원타입}"이 담겨있다.
     * => 결론적으로 jwt 를 해독하여, 실질적 값을 리턴하는 놈. (추후, 이 정보로 필터링을 할 것)
     * */
}
