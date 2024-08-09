package es.animal.hogar.controllers;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Key;
import java.util.Date;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final String SECRET_KEY = "WJyp6f9QXsTyL2b3N4QlmVoZhc6B7VgHr5Zp2lMjOkf4qHnT3Cz5ZMxk6X7Jz8N2";

    @GetMapping("/token")
    public String generateToken() {
        Key key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes());

        String jwt = Jwts.builder()
                .setSubject("admin") 
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 86400000))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        return jwt;
    }
}
