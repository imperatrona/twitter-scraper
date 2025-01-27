package twitterscraper_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	twitterscraper "github.com/imperatrona/twitter-scraper"
)

var (
	proxy         = os.Getenv("PROXY")
	proxyRequired = os.Getenv("PROXY_REQUIRED") != ""
	authToken     = os.Getenv("AUTH_TOKEN")
	csrfToken     = os.Getenv("CSRF_TOKEN")
	cookies       = os.Getenv("COOKIES")
	username      = os.Getenv("TWITTER_USERNAME")
	password      = os.Getenv("TWITTER_PASSWORD")
	email         = os.Getenv("TWITTER_EMAIL")
	skipAuthTest  = os.Getenv("SKIP_AUTH_TEST") != ""
	testScraper   = newTestScraper(false)
)

func init() {
	if skipAuthTest {
		return
	}

	if authToken != "" && csrfToken != "" {
		testScraper.SetAuthToken(twitterscraper.AuthToken{Token: authToken, CSRFToken: csrfToken})
		if err := testScraper.IsLoggedIn(); err != nil {
			panic(fmt.Sprintf("AuthToken() error = %v", err))
		}
		return
	}

	if cookies != "" {
		var parsedCookies []*http.Cookie
		json.NewDecoder(strings.NewReader(cookies)).Decode(&parsedCookies)
		testScraper.SetCookies(parsedCookies)
		if err := testScraper.IsLoggedIn(); err != nil {
			panic(fmt.Sprintf("SetCookies() error = %v", err))
		}
		return
	}

	if username != "" && password != "" {
		err := testScraper.Login(username, password, email)
		if err != nil {
			panic(fmt.Sprintf("Login() error = %v", err))
		}
		return
	}

	skipAuthTest = true
	fmt.Println("None of any auth data provided, skipping all tests that requires auth")
}

func newTestScraper(skip_auth bool) *twitterscraper.Scraper {
	s := twitterscraper.New()

	if proxy != "" && proxyRequired {
		err := s.SetProxy(proxy)
		if err != nil {
			panic(fmt.Sprintf("SetProxy() error = %v", err))
		}
	}

	// Check connection by getting guest token
	if err := s.GetGuestToken(); err != nil {
		panic(fmt.Sprintf("cannot get guest token, can also be error with connection to twitter.\n %v", err))
	}

	if skip_auth == true || !skipAuthTest {
		s.ClearGuestToken()
		return s
	}

	return s
}

func TestLoginPassword(t *testing.T) {
	if skipAuthTest || username == "" || password == "" {
		t.Skip("Skipping test due to environment variable")
	}
	scraper := newTestScraper(true)
	if err := scraper.Login(username, password, email); err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if err := scraper.IsLoggedIn(); err != nil {
		t.Fatalf("IsLoggedIn() error = %v", err)
	}
	if err := scraper.Logout(); err != nil {
		t.Errorf("Logout() error = %v", err)
	}
	if err := scraper.IsLoggedIn(); err == nil {
		t.Error("Expected IsLoggedIn() = false")
	}
}

func TestLoginToken(t *testing.T) {
	if skipAuthTest || authToken == "" || csrfToken == "" {
		t.Skip("Skipping test due to environment variable")
	}

	scraper := newTestScraper(true)

	scraper.SetAuthToken(twitterscraper.AuthToken{Token: authToken, CSRFToken: csrfToken})
	if err := scraper.IsLoggedIn(); err != nil {
		t.Fatalf("AuthToken() error = %v", err)
	}
}

func TestLoginCookie(t *testing.T) {
	if skipAuthTest || cookies == "" {
		t.Skip("Skipping test due to environment variable")
	}

	scraper := newTestScraper(true)

	var c []*http.Cookie

	json.NewDecoder(strings.NewReader(cookies)).Decode(&c)

	scraper.SetCookies(c)
	if err := scraper.IsLoggedIn(); err != nil {
		t.Fatalf("SetCookies() error = %v", err)
	}
}

func TestLoginOpenAccount(t *testing.T) {
	if os.Getenv("TEST_OPEN_ACCOUNT") == "" {
		t.Skip("Skipping test due to environment variable")
	}

	scraper := twitterscraper.New()
	if proxy != "" && proxyRequired {
		err := scraper.SetProxy(proxy)
		if err != nil {
			panic(fmt.Sprintf("SetProxy() error = %v", err))
		}
	}
	account, err := scraper.LoginOpenAccount()

	if err != nil {
		t.Fatalf("LoginOpenAccount() error = %v", err)
	}

	fmt.Printf("%#v", account)
}
