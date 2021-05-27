package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

type InitParams struct {
	Router        *gin.Engine     //gin router (used to set handler for OIDC)
	ClientId      string          //id from the authorization service (OIDC provider)
	ClientSecret  string          //secret from the authorization service (OIDC provider)
	Issuer        string          //the URL identifier for the authorization service. for example: "https://accounts.google.com" - try adding "/.well-known/openid-configuration" to the path to make sure it's correct
	ClientUrl     string          //your website's/service's URL for example: "http://localhost:8081/" or "https://mydomain.com/
	Scopes        []string        //OAuth scopes. If you're unsure go with: []string{oidc.ScopeOpenID, "profile", "email"}
	ErrorHandler  gin.HandlerFunc //errors handler. for example: func(c *gin.Context) {c.String(http.StatusBadRequest, "ERROR...")}
	PostLogoutUrl string          //user will be redirected to this URL after he logs out (i.e. accesses the '/logout' endpoint added in 'Init()')
	CookieName    string          // OIDC Cookie Name
	AesKey        []byte
}

const OIDCORIGINALREQUESTURL = "___oidcOriginalRequestUrl___"

func Init(i InitParams) gin.HandlerFunc {
	verifier, config := initVerifierAndConfig(i)

	i.Router.GET("/logout", logoutHandler(i))

	i.Router.Any("/oidc-callback", callbackHandler(i, verifier, config))

	return protectMiddleware(config, i)
}

func initVerifierAndConfig(i InitParams) (*oidc.IDTokenVerifier, *oauth2.Config) {
	providerCtx := context.Background()
	provider, err := oidc.NewProvider(providerCtx, i.Issuer)
	if err != nil {
		log.Fatalf("Failed to init OIDC provider. Error: %v \n", err.Error())
	}
	oidcConfig := &oidc.Config{
		ClientID: i.ClientId,
	}
	verifier := provider.Verifier(oidcConfig)
	endpoint := provider.Endpoint()
	config := &oauth2.Config{
		ClientID:     i.ClientId,
		ClientSecret: i.ClientSecret,
		Endpoint:     endpoint,
		RedirectURL:  i.ClientUrl + "/oidc-callback",
		Scopes:       i.Scopes,
	}
	return verifier, config
}

func logoutHandler(i InitParams) func(c *gin.Context) {
	return func(c *gin.Context) {
		c.SetCookie(i.CookieName, "", 0, "", "", c.Request.TLS != nil, true)
		logoutUrl, _ := url.Parse(i.Issuer)
		logoutUrl.RawQuery = (url.Values{"redirect_uri": []string{i.PostLogoutUrl}}).Encode()
		logoutUrl.Path = "protocol/openid-connect/logout"
		c.Redirect(http.StatusFound, logoutUrl.String())
	}
}

func callbackHandler(i InitParams, verifier *oidc.IDTokenVerifier, config *oauth2.Config) func(c *gin.Context) {
	return func(c *gin.Context) {
		ctx := c.Request.Context()

		oauth2Token, err := config.Exchange(ctx, c.Query("code"))
		if handleError(c, i, err, "failed to exchange token") {
			return
		}

		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if handleOk(c, i, ok, "no id_token field in oauth2 token") {
			return
		}

		idToken, err := verifier.Verify(ctx, rawIDToken)
		if handleError(c, i, err, "failed to verify id token") {
			return
		}

		var claims map[string]interface{}
		err = idToken.Claims(&claims)
		if handleError(c, i, err, "failed to parse id token") {
			return
		}

		claimsJson, err := json.Marshal(claims)
		if handleError(c, i, err, "failed to marshal id token: ") {
			return
		}

		oidcOriginalRequestUrl, err := c.Cookie(OIDCORIGINALREQUESTURL)
		if handleError(c, i, err, "failed to parse originalRequestUrl") {
			return
		}

		encrypted, err := aesEncrypt(claimsJson, i.AesKey)
		if handleError(c, i, err, "failed save sessions.") {
			return
		}

		cookie := base64.RawStdEncoding.EncodeToString(encrypted)

		c.SetCookie(i.CookieName, cookie, int(time.Until(oauth2Token.Expiry)*time.Second), "", "", true, true)
		c.SetCookie(oidcOriginalRequestUrl, "", -1, "", "", true, true)

		c.Redirect(http.StatusFound, oidcOriginalRequestUrl)
	}
}

func protectMiddleware(config *oauth2.Config, i InitParams) func(c *gin.Context) {
	return func(c *gin.Context) {
		if c.Request.URL.Path == "oidc-callback" {
			c.Next()
			return
		}
		cookie, _ := c.Cookie(i.CookieName)
		if len(cookie) > 0 {
			encrypted, err := base64.RawStdEncoding.DecodeString(cookie)
			if err == nil {
				decrypted, err := aesDecrypt(encrypted, i.AesKey)
				if err == nil {
					var claims map[string]interface{}
					json.Unmarshal(decrypted, &claims)
					c.Next()
					return
				}
			}
		}

		state := RandomString(16)
		c.SetCookie(OIDCORIGINALREQUESTURL, c.Request.URL.String(), 3600, "", "", true, true)
		c.Redirect(http.StatusFound, config.AuthCodeURL(state)) //redirect to authorization server
	}

}

func handleError(c *gin.Context, i InitParams, err error, message string) bool {
	if err == nil {
		return false
	}
	c.Error(errors.New(message))
	i.ErrorHandler(c)
	c.Abort()
	return true
}

func handleOk(c *gin.Context, i InitParams, ok bool, message string) bool {
	if ok {
		return false
	}
	return handleError(c, i, errors.New("not ok"), message)
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

func RandomString(n int) string {
	src := rand.NewSource(time.Now().UnixNano())
	b := make([]byte, n)
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}
