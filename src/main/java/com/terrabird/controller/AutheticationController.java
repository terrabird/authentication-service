package com.terrabird.controller;

import com.terrabird.persistence.ServiceType;
import com.terrabird.persistence.TBUser;
import com.terrabird.service.AuthenticationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * @author rakesh mishra
 */

@RestController
public class AutheticationController {

    private final Logger log = LoggerFactory.getLogger(this.getClass());

    @Autowired
    private AuthenticationService authService;
    
    /* -- method to check if the user name and password is valid 
     * if the user is invalid throws error message
     * if the password is returns invalid password message
     * if login successful returns a session token 
     * 
     * Sample input: http://<hostname:port>/validateLogin?userid=<userid>&password=<paswd>
     * */

    @RequestMapping(value = "/validateLogin",
    		method = RequestMethod.GET)
    public String validateLogin(@RequestParam("userid") String userid, @RequestParam("password") String password ) {
    	
    	TBUser tbUser = authService.getUserById(userid) ;
    	if (tbUser == null) {
    		throw new RuntimeException("User with this Id " + userid + " does NOT exist");
    	}
    	boolean isValid = authService.isPasswordValid(tbUser, password);
    	log.info("Is valid user: " + isValid);    	
    	if (isValid) {
    		log.info("Sucessfuly logged In with passwd : " + password);
    		//generate new sessiontoken in case of logged login
    		String authtoken = authService.getToken(userid);
    		log.info("Authtoken : " + authtoken);
    		return authtoken;//return a session token in case of valid login    		
    	}
    	else
    	{	
    		log.info("Login failed");
    		return "Login Failed, Invalid Password" + password;
    	}
    }
    
    /* -- method to check if the token is valid 
     * sample input :http://<hostname:port>/IsValidToken?token=<token>
     * 
     * */
    
    @RequestMapping(value = "/IsValidToken",
    		method = RequestMethod.GET)
    public boolean IsValidToken(@RequestParam("token") String token ) {
    	
    	if (authService.ValidateToken(token))
    		return true;
    	else
    		return false;
    }    
    
}
