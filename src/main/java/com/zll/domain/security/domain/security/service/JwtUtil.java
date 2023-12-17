package com.zll.domain.security.domain.security.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
public class JwtUtil {
    private static final String defaultBase64EncodedSigningKey = "B*B^";
    private static final SignatureAlgorithm defaultSignatureAlgorithm = SignatureAlgorithm.HS256;

    private final String base64EncodedSecretKey;
    private final SignatureAlgorithm signatureAlgorithm;

    public JwtUtil() {
        this(defaultBase64EncodedSigningKey, defaultSignatureAlgorithm);
    }

    public JwtUtil(String secretKey, SignatureAlgorithm signatureAlgorithm) {
        this.base64EncodedSecretKey = Base64.encodeBase64String(secretKey.getBytes());
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public String encode(String issuer, long ttlMillis, Map<String, Object> claims) {
        return doEncode(issuer, ttlMillis, claims);
    }

    /**
     * 这里就是产生jwt字符串的地方
     * jwt字符串包括三个部分
     *  1. header
     *      -当前字符串的类型，一般都是“JWT”
     *      -哪种算法加密，“HS256”或者其他的加密算法
     *      所以一般都是固定的，没有什么变化
     *  2. payload
     *      一般有四个最常见的标准字段（下面有）
     *      iat：签发时间，也就是这个jwt什么时候生成的
     *      jti：JWT的唯一标识
     *      iss：签发人，一般都是username或者userId
     *      exp：过期时间
     * */
    private String doEncode(String issuer, long ttlMillis, Map<String, Object> claims) {
        if (null == claims) {
            claims = new HashMap<>();
        }

        // 签发时间(iat): 荷载部分的标准字段之一
        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);

        // 签发操作
        JwtBuilder builder = Jwts.builder()
                // 这个是JWT的唯一标识，一般设置成唯一的，这个方法可以生成唯一标识
                .setId(UUID.randomUUID().toString())
                // 荷载部分
                .setClaims(claims)
                // 签发时间
                .setIssuedAt(now)
                // 签发人
                .setSubject(issuer)
                // 生成签名的算法和密钥
                .signWith(signatureAlgorithm, base64EncodedSecretKey);

        if (ttlMillis >= 0) {
            long expireMillis = nowMillis + ttlMillis;
            // 过期时间：代表这个JWT的有效期
            Date expireDate = new Date(expireMillis);
            builder.setExpiration(expireDate);
        }

        return builder.compact();
    }

    public Claims decode(String token) {
        return doDecode(token);
    }

    // 相当于encode的方向，传入jwtToken生成对应的username和password等字段。Claim就是一个map
    // 也就是拿到荷载部分所有的键值对
    private Claims doDecode(String token) {
        return Jwts.parser()
                // 设置签名的密钥
                .setSigningKey(base64EncodedSecretKey)
                // 设置需要解析的jwt
                .parseClaimsJws(token)
                .getBody();
    }

    // 判断jwtToken是否合法
    public boolean isVerify(String token) {
        Algorithm algorithm;
        if (Objects.requireNonNull(signatureAlgorithm) == SignatureAlgorithm.HS256) {
            algorithm = Algorithm.HMAC256(Base64.decodeBase64(base64EncodedSecretKey));
        } else {
            throw new RuntimeException("不支持该算法");
        }
        JWTVerifier verifier = JWT.require(algorithm).build();
        verifier.verify(token);
        // 校验不通过会抛出异常
        // 判断合法的标准：1. 头部和荷载部分没有篡改过。2. 没有过期
        return true;
    }
}
