package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/joho/godotenv"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

var (
	JITSI_SECRET = goDotEnvVariable("JITSI_SECRET")
	JITSI_URL    = goDotEnvVariable("JITSI_URL")
	JITSI_SUB    = goDotEnvVariable("JITSI_SUB")

	ISSUER_BASE_URL = goDotEnvVariable("ISSUER_BASE_URL")
	BASE_URL        = goDotEnvVariable("BASE_URL")
	CLIENT_ID       = goDotEnvVariable("CLIENT_ID")
	SECRET          = goDotEnvVariable("SECRET")
)

type PlayLoad struct {
	ID    string `json:"sub,omitempty"`
	Email string `json:"email,omitempty"`
	Name  string `json:"name,omitempty"`
}
type UserContext struct {
	User PlayLoad `json:"user"`
}

func init() {
	log.Println("[init] Checking if .env file exists")
	if _, err := os.Stat(".env"); err == nil {
		log.Println("[init] .env file found, loading environment variables...")
		err := godotenv.Load(".env")
		if err != nil {
			log.Fatalf("[init] Error loading .env file: %v", err)
		}
		log.Println("[init] .env file loaded successfully")
	} else {
		log.Println("[init] .env file not found, skipping loading")
	}
}

func goDotEnvVariable(key string) string {
	value := os.Getenv(key)
	log.Printf("[goDotEnvVariable] Retrieving env variable %s: %v", key, value)
	return value
}

func randString(nByte int) (string, error) {
	log.Printf("[randString] Generating random string of %d bytes", nByte)
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		log.Printf("[randString] Error generating random bytes: %v", err)
		return "", err
	}
	result := base64.RawURLEncoding.EncodeToString(b)
	log.Printf("[randString] Generated random string: %s", result)
	return result, nil
}

func main() {
	log.Println("[main] Application starting")

	ctx := context.Background()
	log.Printf("[main] Creating OIDC provider with ISSUER_BASE_URL: %s", ISSUER_BASE_URL)
	provider, err := oidc.NewProvider(ctx, ISSUER_BASE_URL)
	if err != nil {
		log.Fatalf("[main] Failed to create OIDC provider: %v", err)
	}
	log.Println("[main] OIDC provider created successfully")

	config := oauth2.Config{
		ClientID:     CLIENT_ID,
		ClientSecret: SECRET,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  strings.Trim(BASE_URL, "/") + "/callback",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	log.Printf("[main] OAuth2 config initialized: %+v", config)

	r := gin.Default()

	r.GET("/room/:room", func(c *gin.Context) {
		room := c.Param("room")
		log.Printf("[/room/:room] Requested for room: %s", room)

		state, err := randString(16)
		if err != nil {
			log.Printf("[/room/:room] Error generating state: %v", err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		log.Printf("[/room/:room] State generated: %s", state)

		nonce, err := randString(16)
		if err != nil {
			log.Printf("[/room/:room] Error generating nonce: %v", err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		log.Printf("[/room/:room] Nonce generated: %s", nonce)

		c.SetCookie("state", state, int(time.Hour.Seconds()), "/", "", c.Request.TLS != nil, true)
		log.Printf("[/room/:room] Set cookie: state=%s", state)
		c.SetCookie("nonce", nonce, int(time.Hour.Seconds()), "/", "", c.Request.TLS != nil, true)
		log.Printf("[/room/:room] Set cookie: nonce=%s", nonce)
		c.SetCookie("room", room, int(time.Hour.Seconds()), "/", "", c.Request.TLS != nil, true)
		log.Printf("[/room/:room] Set cookie: room=%s", room)

		authURL := config.AuthCodeURL(state, oidc.Nonce(nonce))
		log.Printf("[/room/:room] Redirecting to auth URL: %s", authURL)
		c.Redirect(http.StatusFound, authURL)
	})

	r.GET("/callback", func(c *gin.Context) {
		log.Printf("[/callback] Callback hit")

		log.Printf("[/callback] CLIENT_ID: %s", CLIENT_ID)

		state, err := c.Cookie("state")
		if err != nil {
			log.Printf("[/callback] Error retrieving state from cookie: %v", err)
			c.String(http.StatusInternalServerError, "state not found")
			return
		}
		log.Printf("[/callback] State from cookie: %s", state)
		log.Printf("[/callback] State from query: %s", c.Query("state"))

		if c.Query("state") != state {
			log.Printf("[/callback] State mismatch")
			c.String(http.StatusInternalServerError, "state did not match")
			return
		}
		log.Printf("[/callback] State matched. Clearing state cookie.")
		c.SetCookie("state", "", -1, "/", "", c.Request.TLS != nil, true)

		room, err := c.Cookie("room")
		if err != nil {
			log.Printf("[/callback] Error retrieving room from cookie: %v", err)
			c.String(http.StatusInternalServerError, "state not set")
			return
		}
		log.Printf("[/callback] Room from cookie: %s", room)
		c.SetCookie("room", "", -1, "/", "", c.Request.TLS != nil, true)

		code := c.Query("code")
		log.Printf("[/callback] Code from query: %s", code)

		oauth2Token, err := config.Exchange(ctx, code)
		if err != nil {
			log.Printf("[/callback] Failed to exchange token: %v", err)
			c.String(http.StatusInternalServerError, "Failed to exchange token: "+err.Error())
			return
		}
		log.Printf("[/callback] OAuth2 token: %+v", oauth2Token)

		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			log.Printf("[/callback] No id_token field in oauth2 token")
			c.String(http.StatusInternalServerError, "No id_token field in oauth2 token.")
			return
		}
		log.Printf("[/callback] Raw ID Token: %s", rawIDToken)

		oidcConfig := &oidc.Config{
			ClientID: CLIENT_ID,
		}
		verifier := provider.Verifier(oidcConfig)

		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			log.Printf("[/callback] Failed to verify ID Token: %v", err)
			c.String(http.StatusInternalServerError, "Failed to verify ID Token: "+err.Error())
			return
		}
		log.Printf("[/callback] ID Token verified: %+v", idToken)

		nonce, err := c.Cookie("nonce")
		if err != nil {
			log.Printf("[/callback] Error retrieving nonce from cookie: %v", err)
			c.String(http.StatusInternalServerError, "nonce not found")
			return
		}
		log.Printf("[/callback] Nonce from cookie: %s", nonce)
		log.Printf("[/callback] Nonce in ID Token: %s", idToken.Nonce)

		if idToken.Nonce != nonce {
			log.Printf("[/callback] Nonce mismatch")
			c.String(http.StatusBadRequest, "nonce did not match")
			return
		}
		log.Printf("[/callback] Nonce matched. Clearing nonce cookie.")
		c.SetCookie("nonce", "", -1, "/", "", c.Request.TLS != nil, true)

		oauth2Token.AccessToken = "*REDACTED*"
		log.Printf("[/callback] Redacted access token for logging")

		resp := struct {
			OAuth2Token   *oauth2.Token
			IDTokenClaims *json.RawMessage // ID Token payload is just JSON.
		}{oauth2Token, new(json.RawMessage)}

		if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
			log.Printf("[/callback] Error parsing ID token claims: %v", err)
			c.String(http.StatusInternalServerError, err.Error())
			return
		}

		var playLoad PlayLoad
		err = json.Unmarshal(*resp.IDTokenClaims, &playLoad)
		if err != nil {
			log.Printf("[/callback] Error unmarshaling ID token claims: %v", err)
			c.String(http.StatusInternalServerError, err.Error())
			return
		}
		log.Printf("[/callback] Parsed user payload: %+v", playLoad)

		user := &UserContext{
			User: playLoad,
		}

		user.User.ID = ""
		log.Printf("[/callback] UserContext created: %+v", user)

		claims := jwt.MapClaims{}
		claims["exp"] = time.Now().Add(time.Hour * 24 * 30).Unix()
		claims["aud"] = "jitsi"
		//claims["moderator"] = true
		claims["sub"] = JITSI_SUB
		claims["iss"] = "jitsi"
		claims["room"] = room
		claims["context"] = user
		log.Printf("[/callback] JWT claims: %+v", claims)

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

		tokenString, err := token.SignedString([]byte(JITSI_SECRET))
		if err != nil {
			log.Printf("[/callback] Error signing JWT: %v", err)
			c.String(http.StatusInternalServerError, err.Error())
			return
		}
		log.Printf("[/callback] JWT token created: %s", tokenString)

		redirectURL := JITSI_URL + "/" + room + "?jwt=" + tokenString
		log.Printf("[/callback] Redirecting to: %s", redirectURL)
		c.Redirect(http.StatusFound, redirectURL)
	})

	log.Println("[main] Starting server at :3001")
	if err := r.Run(":3001"); err != nil {
		log.Fatalf("[main] Failed to start server: %v", err)
	}
}
