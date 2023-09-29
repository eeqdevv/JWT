package com.example.jwt.security.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.jwt.services.UserDetailsImpl;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.*;

import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);



    private static final int  TOKEN_EXPIRE=30000;
    private static final String SECRET = "qwert0987654321rewq";
    private static final Algorithm algorithm=  Algorithm.HMAC256(SECRET);


    public   String generateJwtToken(Authentication authentication) {

        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();
        Instant expirationTime = Instant.now().plusSeconds(TOKEN_EXPIRE);
        JWTCreator.Builder builder = JWT.create();
        builder.withSubject(userPrincipal.getUsername());
//        payload.forEach(builder::withClaim);
        return builder
                .withExpiresAt(expirationTime)
                .sign(algorithm);
    }


    public boolean  validateJwtToken(String token) {
   try{
       DecodedJWT verify = JWT.require(algorithm).build().verify(token);
       return  true;
    } catch (MalformedJwtException e) {
        logger.error("Invalid JWT token: {}", e.getMessage());
    } catch (ExpiredJwtException e) {
        logger.error("JWT token is expired: {}", e.getMessage());
    } catch (UnsupportedJwtException e) {
        logger.error("JWT token is unsupported: {}", e.getMessage());
    } catch (IllegalArgumentException e) {
        logger.error("JWT claims string is empty: {}", e.getMessage());
    }
   return false;
    }


    public String getUserNameFromJwtToken (String token ){
        DecodedJWT verify = JWT.require(algorithm).build().verify(token);
        Claim userName = verify.getClaim("userName");
        return userName.asString();
    }

//    private String getToken(String uid,String userName){
//        Map<String, String> map=new HashMap<>();
//        map.put("uid",uid);
//        map.put("userName",userName);
//        return generateJwtToken(map);
//    }

//
//    @Value("${bezkoder.app.jwtSecret}")
//    private String jwtSecret;
//
//    @Value("${bezkoder.app.jwtExpirationMs}")
//    private int jwtExpirationMs;
//
//    public String generateJwtToken(Authentication authentication) {
//
//        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();
//
//        return Jwts.builder()
//                .setSubject((userPrincipal.getUsername()))
//                .setIssuedAt(new Date())
//                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
//                .signWith(key(), SignatureAlgorithm.HS256)
//                .compact();
//    }
//
//    private Key key() {
//        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
//    }
//
//    public String getUserNameFromJwtToken(String token) {
//        return Jwts.parserBuilder().setSigningKey(key()).build()
//                .parseClaimsJws(token).getBody().getSubject();
//    }
//
//    public boolean validateJwtToken(String authToken) {
//        try {
//            Jwts.parserBuilder().setSigningKey(key()).build().parse(authToken);
//            return true;
//        } catch (MalformedJwtException e) {
//            logger.error("Invalid JWT token: {}", e.getMessage());
//        } catch (ExpiredJwtException e) {
//            logger.error("JWT token is expired: {}", e.getMessage());
//        } catch (UnsupportedJwtException e) {
//            logger.error("JWT token is unsupported: {}", e.getMessage());
//        } catch (IllegalArgumentException e) {
//            logger.error("JWT claims string is empty: {}", e.getMessage());
//        }
//
//        return false;
//    }

}
