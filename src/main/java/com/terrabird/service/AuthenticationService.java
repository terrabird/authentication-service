package com.terrabird.service;

import com.terrabird.dao.AuthDAO;
import com.terrabird.persistence.TBUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.DigestUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import io.jsonwebtoken.*;
import java.util.Date; 
import io.jsonwebtoken.impl.crypto.MacProvider;
import sun.misc.BASE64Decoder;
import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author rakesh mishra
 */
@Service
public class AuthenticationService {

    private final Logger log = LoggerFactory.getLogger(this.getClass());
    
    @Autowired
    private AuthDAO authDAO;

    private long sessionTimeout =  600000;
    
    public TBUser getUserById(String userid) {            
       return authDAO.findUserById(userid);
    }
       
    public boolean isPasswordValid(TBUser tbUser, String password) {
    	password = getEncryptedPassword(password);
    	return tbUser.getPassword().equals(password);
    }

    private String getEncryptedPassword(String password) {
        StringBuffer hexString = new StringBuffer();
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedHash = digest.digest(
                    password.getBytes(StandardCharsets.UTF_8));
            for (int i = 0; i < encodedHash.length; i++) {
                String hex = Integer.toHexString(0xff & encodedHash[i]);
                if(hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
        } catch(NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        }
        return hexString.toString();
    }
    
    /* --- method to generate and return a new session token ---*/   
    public String getToken(String userid)    {
    	String provider = "Terrabird";
    	String subject = "Authenticate";    	
    	long timeMilli = sessionTimeout;
    	return createJWT(userid,provider,subject,timeMilli);
    	
    }
    
  /* --- method to construct a JWT ---*/    
  private String createJWT(String id, String issuer, String subject, long ttlMillis) {
   
      //The JWT signature algorithm we will be using to sign the token
      SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
      String str = "15+06x18y=";
   
      long nowMillis = System.currentTimeMillis();
      Date now = new Date(nowMillis);      
      
      //We will sign our JWT with our ApiKey secret
      str = DatatypeConverter.printBase64Binary(str.getBytes());
      //input = DatatypeConverter.printHexBinary(input.getBytes());

      String temp = DatatypeConverter.printBase64Binary(str.getBytes());
      //temp = DatatypeConverter.parseBase64Binary(str.getBytes());      
      //byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(str);
      
      byte[] apiKeySecretBytes = temp.getBytes();
      Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());
         
      JwtBuilder builder = Jwts.builder().setId(id)
                                  .setIssuedAt(now)
                                  .setSubject(subject)
                                  .setIssuer(issuer)
                                  .signWith(signatureAlgorithm, signingKey);
   
      if (ttlMillis >= 0) {
	      long expMillis = nowMillis + ttlMillis;
	          Date exp = new Date(expMillis);
	          builder.setExpiration(exp);
	      }
   
      return builder.compact();
  }
  
  
  /* --- method to check if token is valid ---*/
  public boolean ValidateToken( String token) {
	  
	  String str = "15+06x18y="; //TODO make sign key a private and class member
	  log.info("auth token passed : " + token);
     
      str = DatatypeConverter.printBase64Binary(str.getBytes());
      String temp = DatatypeConverter.printBase64Binary(str.getBytes());
      SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
      
      byte[] apiKeySecretBytes = temp.getBytes();
      //byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(str);
      Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());

      Claims claims = Jwts.parser().setSigningKey(signingKey).parseClaimsJws(token).getBody();
      
      log.info("Claims Id : " + claims.getId());
      log.info("Claims Subject : " + claims.getSubject());
      log.info("Claims Issuer:" + claims.getIssuer());
      log.info("Claims Expiration:" + claims.getExpiration());
	  
	  long nowMillis = System.currentTimeMillis();
	  //log.info("current time : " + nowMillis);
	  long expInMil = claims.getExpiration().getTime();
	  //log.info("Claims time : " + expInMil);
	  //log.info("Session Timeout : " + sessionTimeout);
	  
	  //TODO: Currently validating only the timeout set, need to validate other parameters of the session token
	  if (nowMillis <= expInMil + sessionTimeout)
	  {
		  log.info("Valid Session Token ");		  
		  return true; 
	  }		 
	  else
	  {
		  log.info("Invalid Session Token or expired ");
		  return false;
	  }	  
	  
  }
  
}
