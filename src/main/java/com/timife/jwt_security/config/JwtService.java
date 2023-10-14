package com.timife.jwt_security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

//This service is a helper class to extract claims from tokens.
@Service
public class JwtService {
    private static final String SECRET_KEY =
            "uyO2pwe68XshBBM1auM4jHcqknnBoky4Faita1stqK1/s2O8aoeNU8JzJj/549OBaBEQOVyCyrdTCtf9SVAzSD8Y9D01z2Mi1" +
                    "YZhyS+iQr50MuvSaBwI3opgNtpmjN9InV4tIVoN/OpSK4nbNxAb+f67h0KH3J9gbdVTTHZNaGUClXWRripLng4h73r" +
                    "J8YBpXXNbAI/G+bU7KqXezfDug6pJwdQUx3+piPkypHnacvC0vUO8Ue4M/r+zIedLYCGE6vNXJ+rMcqWIWGKlcPIHTB" +
                    "sTtD/GDv+R3kV+bm7ZLGAUeMeNqA2pKfqMA8xTi0f2FwOO6mVsSIZTpdjccC4Hx/aZO+Y9ZJh4w7T9qt4Mr24=";

    public String extractUsername(String token){
        return extractClaim(token, Claims::getSubject);
    }

    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ){
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);
    }

    public boolean isTokenValid(String token, UserDetails userDetails){ //checks if the token belongs to the userDetails and if the token is still valid, not expired.
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token){
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey()) //handles the signature part of the jwt and verifies the client is legit
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] bytes = Decoders.BASE64.decode(SECRET_KEY);

        return Keys.hmacShaKeyFor(bytes);
    }
}

