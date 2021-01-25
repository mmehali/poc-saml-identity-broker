package org.concept.security;

import org.keycloak.KeycloakSecurityContext;
import org.keycloak.representations.AccessToken;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.Principal;

import javax.servlet.http.HttpServletRequest;

@Controller
public class WebController {

    @GetMapping(path = "/")
    public String index() {
        return "external";
    }

    @PreAuthorize("hasRole('company')")
    @GetMapping(path = "/intranet")
    public String intranet(HttpServletRequest req, Principal principal, Model model) {
        model.addAttribute("option", "dummy");
        model.addAttribute("username", principal.getName());
        
        KeycloakSecurityContext session = (KeycloakSecurityContext) req.getAttribute(KeycloakSecurityContext.class.getName());
		
		String accessToken = session.getTokenString() ;
		
		String idToken = session.getIdTokenString() ;
		if (idToken==null) idToken = "Token vide";
		if (accessToken==null) accessToken="token vide";
		AccessToken token = session.getToken() ;
		String username = token.getPreferredUsername() ;
		
		model.addAttribute("accessToken",accessToken) ;
		model.addAttribute("idToken", idToken) ;
		model.addAttribute("username", username) ;
		
	        
        return "intranet";
    }

    @PreAuthorize("hasRole('caseworker')")
    @GetMapping(path = "/cases")
    public String cases() {
        return "cases";
    }

}