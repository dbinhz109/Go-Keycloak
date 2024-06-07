package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/coreos/go-oidc"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

var (
	clientID     = "test"
	clientSecret = "pp4C7gRKvLYWQxRdNTo9KJF8yEG65Ipp"
	issuer       = "https://id.lab.linksafe.vn/realms/binh"
	redirectURL  = "http://localhost:8080/callback"
	logoutURL    = "https://id.lab.linksafe.vn/realms/binh/protocol/openid-connect/logout"
	oidcProvider *oidc.Provider
	oauth2Config oauth2.Config
	verifier     *oidc.IDTokenVerifier
	userInfoURL  string
)

func main() {
	// Initialize OIDC provider
	var err error
	oidcProvider, err = oidc.NewProvider(context.Background(), issuer)
	if err != nil {
		panic(err)
	}

	// Get the userinfo endpoint from the OIDC provider
	var wellKnown map[string]interface{}
	if err := oidcProvider.Claims(&wellKnown); err != nil {
		panic(err)
	}
	userInfoURL, _ = wellKnown["userinfo_endpoint"].(string)

	// Initialize OAuth2 config
	oauth2Config = oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     oidcProvider.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	// Initialize ID Token verifier
	verifier = oidcProvider.Verifier(&oidc.Config{ClientID: clientID})

	// Initialize Gin router
	router := gin.Default()

	// Define routes
	router.GET("/", homeHandler)
	router.GET("/login", loginHandler)
	router.GET("/callback", callbackHandler)
	router.GET("/logout", logoutHandler)
	router.GET("/protected", authMiddleware("allowed"), protectedHandler)

	// Start server
	router.Run(":8080")
}

func homeHandler(c *gin.Context) {
	c.String(http.StatusOK, "Welcome to the home page!")
}

func loginHandler(c *gin.Context) {
	url := oauth2Config.AuthCodeURL("state", oauth2.AccessTypeOffline)
	c.Redirect(http.StatusFound, url)
}

func callbackHandler(c *gin.Context) {
	code := c.Query("code")

	// Exchange code for token
	token, err := oauth2Config.Exchange(context.Background(), code)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to exchange token: %v", err)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		c.String(http.StatusInternalServerError, "No id_token in token response")
		return
	}

	idToken, err := verifier.Verify(context.Background(), rawIDToken)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to verify ID token: %v", err)
		return
	}

	// Extract claims
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		c.String(http.StatusInternalServerError, "Failed to extract claims: %v", err)
		return
	}

	// Set Access Token in cookie
	c.SetCookie("access_token", token.AccessToken, 3600, "/", "localhost", false, true)

	c.String(http.StatusOK, "Login successful!")
}

func logoutHandler(c *gin.Context) {
	// Clear cookie
	c.SetCookie("access_token", "", -1, "/", "localhost", false, true)

	// Redirect to Keycloak logout URL with a post_logout_redirect_uri back to the login page
	logoutURLWithRedirect := fmt.Sprintf("%s?client_id=%s&post_logout_redirect_uri=%s", logoutURL, clientID, "http://localhost:8080/login")
	c.Redirect(http.StatusFound, logoutURLWithRedirect)
}

func authMiddleware(requiredRole string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get Access Token from cookie
		accessToken, err := c.Cookie("access_token")
		if err != nil {
			c.String(http.StatusUnauthorized, "Unauthorized")
			c.Abort()
			return
		}

		// Verify Access Token
		if !validateAccessToken(accessToken) {
			c.String(http.StatusUnauthorized, "Invalid token")
			c.Abort()
			return
		}

		// Check user roles or policies
		if !checkUserRoles(accessToken, requiredRole) {
			c.String(http.StatusForbidden, "Forbidden")
			c.Abort()
			return
		}

		c.Next()
	}
}

func validateAccessToken(accessToken string) bool {
	// Verify the access token with Keycloak
	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: accessToken,
	})

	client := oauth2.NewClient(context.Background(), tokenSource)

	resp, err := client.Get(userInfoURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

func checkUserRoles(accessToken string, requiredRole string) bool {
	// Parse the JWT token
	token, _, err := new(jwt.Parser).ParseUnverified(accessToken, jwt.MapClaims{})
	if err != nil {
		return false
	}

	// Extract roles from token claims
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if roles, ok := claims["realm_access"].(map[string]interface{})["roles"].([]interface{}); ok {
			for _, role := range roles {
				if role == requiredRole {
					return true
				}
			}
		}
	}

	return false
}

func protectedHandler(c *gin.Context) {
	c.String(http.StatusOK, "You have accessed a protected route!")
}
