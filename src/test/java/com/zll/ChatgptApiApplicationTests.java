package com.zll;

import com.zll.domain.security.domain.security.service.JwtUtil;
import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

//@SpringBootTest
//@RunWith(SpringRunner.class)
public class ChatgptApiApplicationTests {

    @Test
    public void contextLoads() {
    }

    @Test
    public void testJwt() {
        JwtUtil jwtUtil = new JwtUtil("zyl", SignatureAlgorithm.HS256);
        Map<String, Object> map = new HashMap<>();
        map.put("name", "zyl");
        map.put("password", "123");
        map.put("age", "21");
        String token = jwtUtil.encode("zyl", 30000, map);
        jwtUtil.decode(token).forEach((key, value) -> System.out.println(key + ": " + value));

    }

}
