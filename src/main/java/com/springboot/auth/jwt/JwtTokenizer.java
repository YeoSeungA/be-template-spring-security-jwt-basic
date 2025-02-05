package com.springboot.auth.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;

@Component
public class JwtTokenizer {
    // secretKey는 민감해서 제대로 숨기자!
    @Getter
    @Value("${jwt.key}")
    private String secretKey;
//    만료시간도 숨긴다. 외부에 노출 X
    @Getter
    @Value("${jwt.access-token-expiration-minutes}")
    private int accessTokenExpirationMinutes;
    @Getter
    @Value("${jwt.refresh-token-expiration-minutes}")
    private int refreshTokenExpirationMinutes;

    public String encodeBase64SecretKey(String secretKey) {
        return Encoders.BASE64.encode(secretKey.getBytes(StandardCharsets.UTF_8));
    }

    public String generateAccessToken(Map<String, Object> claims,
                                      String subject,
                                      Date expiration,
                                      String base64EncodedSecretKey) {
        Key key = getKeyFromBase64EncodedKey(base64EncodedSecretKey);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(Calendar.getInstance().getTime())
                .setExpiration(expiration)
                .signWith(key)
                .compact();
    }
    public String generateRefreshToken(String subject, Date expiration, String base64EncodedSecretKey) {
        Key key = getKeyFromBase64EncodedKey(base64EncodedSecretKey);

        return Jwts.builder()
                .setSubject(subject)
                .setIssuedAt(Calendar.getInstance().getTime())
                .setExpiration(expiration)
                .signWith(key)
                .compact();
    }

    public Key getKeyFromBase64EncodedKey(String base64EncodedSecretKey) {
        byte[] keyBytes = Decoders.BASE64.decode(base64EncodedSecretKey);

        return Keys.hmacShaKeyFor(keyBytes);
    }
// 유저의 정보 가져오기 + 튕겨내기도 한다.
    public Jws<Claims> getClaims(String jws, String base64EncodedSecretKey) {
        Key key = getKeyFromBase64EncodedKey(base64EncodedSecretKey);

        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
//                검증. 안맞으면 터진다.
                .parseClaimsJws(jws);
    }
//     검증만 한다. 반환, 저장도 안함.
    public void verifySignature(String jws, String base64EncodedSecretKey) {
        Key key = getKeyFromBase64EncodedKey(base64EncodedSecretKey);

         Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
//                검증. 안맞으면 터진다.
                .parseClaimsJws(jws);
    }
//    만료시간 만드는 메서드
    public Date getTokenExpirations(int expiration) {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MINUTE, expiration);
//        .getTime() 라는 메서드는 시간을 Date 객체로 바꾼다.
        return calendar.getTime();
    }

}
