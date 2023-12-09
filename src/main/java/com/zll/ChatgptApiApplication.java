package com.zll;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
public class ChatgptApiApplication {

    public static void main(String[] args) {
        SpringApplication.run(ChatgptApiApplication.class, args);
    }

    @GetMapping(value = "/verify")
    public ResponseEntity<String> verify(String token) {
        if ("success".equals(token)) {
            return ResponseEntity.status(HttpStatus.OK).build();
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }

    @GetMapping("/success")
    public String success() {
        return "test success by zll";
    }

}
