package twitterscraper

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"

	"math/rand"
)

const (
	loginURL  = "https://api.twitter.com/1.1/onboarding/task.json"
	logoutURL = "https://api.twitter.com/1.1/account/logout.json"
	oAuthURL  = "https://api.twitter.com/oauth2/token"
	// Doesn't require x-client-transaction-id header in auth. x-rate-limit-limit: 2000
	bearerToken1 = "AAAAAAAAAAAAAAAAAAAAAFQODgEAAAAAVHTp76lzh3rFzcHbmHVvQxYYpTw%3DckAlMINMjmCwxUcaXbAN4XqJVdgMJaHqNOFgPMK0zN1qLqLQCF"
	// Requires x-client-transaction-id header in auth.
	bearerToken2      = "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"
	appConsumerKey    = "3nVuSoBZnx6U4vzUxf5w"
	appConsumerSecret = "Bcs59EFbbsdF6Sl9Ng71smgStWEGwXXKSjYvPVt7qys"
)

type (
	OpenAccount struct {
		OAuthToken       string `json:"oauth_token"`
		OAuthTokenSecret string `json:"oauth_token_secret"`
	}

	flow struct {
		Errors []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
		FlowToken string `json:"flow_token"`
		Status    string `json:"status"`
		Subtasks  []struct {
			SubtaskID   string      `json:"subtask_id"`
			OpenAccount OpenAccount `json:"open_account"`
		} `json:"subtasks"`
	}

	verifyCredentials struct {
		Errors []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
)

func (s *Scraper) getAccessToken(consumerKey, consumerSecret string) (string, error) {
	req, err := http.NewRequest("POST", oAuthURL, strings.NewReader("grant_type=client_credentials"))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(consumerKey, consumerSecret)

	res, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		return "", fmt.Errorf("unexpected status code: %d, body: %s", res.StatusCode, body)
	}

	var a struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&a); err != nil {
		return "", err
	}
	return a.AccessToken, nil
}

func (s *Scraper) getFlow(data map[string]interface{}) (*flow, error) {
	headers := http.Header{
		"Authorization":             []string{"Bearer " + s.bearerToken},
		"Content-Type":              []string{"application/json"},
		"User-Agent":                []string{s.userAgent},
		"X-Guest-Token":             []string{s.guestToken},
		"X-Twitter-Auth-Type":       []string{"OAuth2Client"},
		"X-Twitter-Active-User":     []string{"yes"},
		"X-Twitter-Client-Language": []string{"en"},
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", loginURL, bytes.NewReader(jsonData))
	if err != nil {
		return nil, err
	}
	req.Header = headers
	s.setCSRFToken(req)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var info flow
	err = json.NewDecoder(resp.Body).Decode(&info)
	if err != nil {
		return nil, err
	}

	return &info, nil
}

func (s *Scraper) getFlowToken(data map[string]interface{}) (string, error) {
	info, err := s.getFlow(data)
	if err != nil {
		return "", err
	}

	if len(info.Errors) > 0 {
		return "", fmt.Errorf("auth error (%d): %v", info.Errors[0].Code, info.Errors[0].Message)
	}

	if len(info.Subtasks) > 0 {
		if info.Subtasks[0].SubtaskID == "LoginEnterAlternateIdentifierSubtask" {
			err = fmt.Errorf("auth error: %v", "LoginEnterAlternateIdentifierSubtask")
		} else if info.Subtasks[0].SubtaskID == "LoginAcid" {
			err = fmt.Errorf("auth error: %v", "LoginAcid")
		} else if info.Subtasks[0].SubtaskID == "LoginTwoFactorAuthChallenge" {
			err = fmt.Errorf("auth error: %v", "LoginTwoFactorAuthChallenge")
		} else if info.Subtasks[0].SubtaskID == "DenyLoginSubtask" {
			err = fmt.Errorf("auth error: %v", "DenyLoginSubtask")
		}
	}

	return info.FlowToken, err
}

// IsLoggedIn check if scraper logged in
func (s *Scraper) IsLoggedIn() bool {
	s.isLogged = true
	s.setBearerToken(bearerToken1)
	req, err := http.NewRequest("GET", "https://api.twitter.com/1.1/account/verify_credentials.json", nil)
	if err != nil {
		return false
	}
	var verify verifyCredentials
	err = s.RequestAPI(req, &verify)
	if err != nil || verify.Errors != nil {
		s.isLogged = false
		s.setBearerToken(bearerToken)
	} else {
		s.isLogged = true
	}
	return s.isLogged
}

// randomDelay introduces a random delay between 1 and 3 seconds
func randomDelay() {
	delay := time.Duration(1000+rand.Intn(2000)) * time.Millisecond
	time.Sleep(delay)
}

// Login to Twitter
// Use Login(username, password) for ordinary login
// or Login(username, password, email) for login if you have email confirmation
// or Login(username, password, code_for_2FA) for login if you have two-factor authentication
func (s *Scraper) Login(credentials ...string) error {
	var username, password, confirmation string
	if len(credentials) < 2 || len(credentials) > 3 {
		return fmt.Errorf("invalid credentials")
	}

	username, password = credentials[0], credentials[1]
	if len(credentials) == 3 {
		confirmation = credentials[2]
	}

	s.setBearerToken(bearerToken2)

	err := s.GetGuestToken()
	if err != nil {
		return err
	}

	randomDelay()

	// flow start
	data := map[string]interface{}{
		"flow_name": "login",
		"input_flow_data": map[string]interface{}{
			"flow_context": map[string]interface{}{
				"debug_overrides": map[string]interface{}{},
				"start_location":  map[string]interface{}{"location": "splash_screen"},
			},
		},
	}
	flowToken, err := s.getFlowToken(data)
	if err != nil {
		return err
	}

	randomDelay()

	// flow instrumentation step
	data = map[string]interface{}{
		"flow_token": flowToken,
		"subtask_inputs": []map[string]interface{}{
			{
				"subtask_id":         "LoginJsInstrumentationSubtask",
				"js_instrumentation": map[string]interface{}{"response": "{}", "link": "next_link"},
			},
		},
	}
	flowToken, err = s.getFlowToken(data)
	if err != nil {
		return err
	}

	randomDelay()

	// flow username step
	data = map[string]interface{}{
		"flow_token": flowToken,
		"subtask_inputs": []map[string]interface{}{
			{
				"subtask_id": "LoginEnterUserIdentifierSSO",
				"settings_list": map[string]interface{}{
					"setting_responses": []map[string]interface{}{
						{
							"key":           "user_identifier",
							"response_data": map[string]interface{}{"text_data": map[string]interface{}{"result": username}},
						},
					},
					"link": "next_link",
				},
			},
		},
	}
	flowToken, err = s.getFlowToken(data)
	if err != nil {
		return err
	}

	randomDelay()

	// flow password step
	data = map[string]interface{}{
		"flow_token": flowToken,
		"subtask_inputs": []map[string]interface{}{
			{
				"subtask_id":     "LoginEnterPassword",
				"enter_password": map[string]interface{}{"password": password, "link": "next_link"},
			},
		},
	}
	flowToken, err = s.getFlowToken(data)
	if err != nil {
		return err
	}

	randomDelay()

	// flow duplication check
	data = map[string]interface{}{
		"flow_token": flowToken,
		"subtask_inputs": []map[string]interface{}{
			{
				"subtask_id":              "AccountDuplicationCheck",
				"check_logged_in_account": map[string]interface{}{"link": "AccountDuplicationCheck_false"},
			},
		},
	}
	flowToken, err = s.getFlowToken(data)
	if err != nil {
		var confirmationSubtask string
		for _, subtask := range []string{"LoginAcid", "LoginTwoFactorAuthChallenge"} {
			if strings.Contains(err.Error(), subtask) {
				confirmationSubtask = subtask
				break
			}
		}
		if confirmationSubtask != "" {
			if confirmation == "" {
				return fmt.Errorf("confirmation data required for %v", confirmationSubtask)
			}

			randomDelay()

			// flow confirmation
			data = map[string]interface{}{
				"flow_token": flowToken,
				"subtask_inputs": []map[string]interface{}{
					{
						"subtask_id": confirmationSubtask,
						"enter_text": map[string]interface{}{"text": confirmation, "link": "next_link"},
					},
				},
			}
			_, err = s.getFlowToken(data)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}

	s.isLogged = true
	s.isOpenAccount = false
	return nil
}

// LoginOpenAccount as Twitter app
func (s *Scraper) LoginOpenAccount() (OpenAccount, error) {
	accessToken, err := s.getAccessToken(appConsumerKey, appConsumerSecret)
	if err != nil {
		return OpenAccount{}, err
	}
	s.setBearerToken(accessToken)

	err = s.GetGuestToken()
	if err != nil {
		return OpenAccount{}, err
	}

	// flow start
	data := map[string]interface{}{
		"flow_name": "welcome",
		"input_flow_data": map[string]interface{}{
			"flow_context": map[string]interface{}{
				"debug_overrides": map[string]interface{}{},
				"start_location":  map[string]interface{}{"location": "splash_screen"},
			},
		},
	}
	flowToken, err := s.getFlowToken(data)
	if err != nil {
		return OpenAccount{}, err
	}

	// flow next link
	data = map[string]interface{}{
		"flow_token": flowToken,
		"subtask_inputs": []interface{}{
			map[string]interface{}{
				"subtask_id": "NextTaskOpenLink",
			},
		},
	}
	info, err := s.getFlow(data)
	if err != nil {
		return OpenAccount{}, err
	}

	if len(info.Subtasks) > 0 {
		if info.Subtasks[0].SubtaskID == "OpenAccount" {
			s.oAuthToken = info.Subtasks[0].OpenAccount.OAuthToken
			s.oAuthSecret = info.Subtasks[0].OpenAccount.OAuthTokenSecret
			if s.oAuthToken == "" || s.oAuthSecret == "" {
				return OpenAccount{}, fmt.Errorf("auth error: %v", "Token or Secret is empty")
			}
			s.isLogged = true
			s.isOpenAccount = true
			return OpenAccount{
				OAuthToken:       info.Subtasks[0].OpenAccount.OAuthToken,
				OAuthTokenSecret: info.Subtasks[0].OpenAccount.OAuthTokenSecret,
			}, nil
		}
	}
	return OpenAccount{}, fmt.Errorf("auth error: %v", "OpenAccount")
}

func (s *Scraper) WithOpenAccount(openAccount OpenAccount) {
	s.oAuthToken = openAccount.OAuthToken
	s.oAuthSecret = openAccount.OAuthTokenSecret
	s.isLogged = true
	s.isOpenAccount = true
}

// Logout is reset session
func (s *Scraper) Logout() error {
	req, err := http.NewRequest("POST", logoutURL, nil)
	if err != nil {
		return err
	}
	err = s.RequestAPI(req, nil)
	if err != nil {
		return err
	}

	s.isLogged = false
	s.isOpenAccount = false
	s.guestToken = ""
	s.oAuthToken = ""
	s.oAuthSecret = ""
	s.client.Jar, _ = cookiejar.New(nil)
	s.setBearerToken(bearerToken)
	return nil
}

func (s *Scraper) GetCookies() []*http.Cookie {
	var cookies []*http.Cookie
	for _, cookie := range s.client.Jar.Cookies(twURL) {
		if strings.Contains(cookie.Name, "guest") {
			continue
		}
		cookie.Domain = twURL.Host
		cookies = append(cookies, cookie)
	}
	return cookies
}

func (s *Scraper) SetCookies(cookies []*http.Cookie) {
	s.client.Jar.SetCookies(twURL, cookies)
}

func (s *Scraper) ClearCookies() {
	s.client.Jar, _ = cookiejar.New(nil)
}

// Use auth_token cookie as Token and ct0 cookie as CSRFToken
type AuthToken struct {
	Token     string
	CSRFToken string
}

// Auth using auth_token and ct0 cookies
func (s *Scraper) SetAuthToken(token AuthToken) {
	expires := time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC)
	cookies := []*http.Cookie{{
		Name:       "auth_token",
		Value:      token.Token,
		Path:       "",
		Domain:     "twitter.com",
		Expires:    expires,
		RawExpires: "",
		MaxAge:     0,
		Secure:     false,
		HttpOnly:   false,
		SameSite:   0,
		Raw:        "",
		Unparsed:   nil,
	}, {
		Name:       "ct0",
		Value:      token.CSRFToken,
		Path:       "",
		Domain:     "twitter.com",
		Expires:    expires,
		RawExpires: "",
		MaxAge:     0,
		Secure:     false,
		HttpOnly:   false,
		SameSite:   0,
		Raw:        "",
		Unparsed:   nil,
	}}

	s.SetCookies(cookies)
}

func (s *Scraper) sign(method string, ref *url.URL) string {
	m := make(map[string]string)
	m["oauth_consumer_key"] = appConsumerKey
	m["oauth_nonce"] = "0"
	m["oauth_signature_method"] = "HMAC-SHA1"
	m["oauth_timestamp"] = strconv.FormatInt(time.Now().Unix(), 10)
	m["oauth_token"] = s.oAuthToken

	key := []byte(appConsumerSecret + "&" + s.oAuthSecret)
	h := hmac.New(sha1.New, key)

	query := ref.Query()
	for k, v := range m {
		query.Set(k, v)
	}

	req := []string{method, ref.Scheme + "://" + ref.Host + ref.Path, query.Encode()}
	var reqBuf bytes.Buffer
	for _, value := range req {
		if reqBuf.Len() > 0 {
			reqBuf.WriteByte('&')
		}
		reqBuf.WriteString(url.QueryEscape(value))
	}
	h.Write(reqBuf.Bytes())

	m["oauth_signature"] = base64.StdEncoding.EncodeToString(h.Sum(nil))

	var b bytes.Buffer
	for k, v := range m {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(url.QueryEscape(v))
	}

	return "OAuth " + b.String()
}

func (s *Scraper) AutoLogin(credentials ...string) error {
	var username, password, email, confirmation string
	if len(credentials) < 2 || len(credentials) > 4 {
		return fmt.Errorf("invalid credentials")
	}

	username, password = credentials[0], credentials[1]
	email = credentials[2]
	if len(credentials) == 4 {
		confirmation = credentials[3]
	}
	s.setBearerToken(bearerToken2)

	err := s.GetGuestToken()
	if err != nil {
		return err
	}

	// Initialize login flow
	flowToken, next, err := s.initializeLoginFlow()
	if err != nil {
		fmt.Println("initializeLoginFlow", err)
		return err
	}
	var nextData map[string]interface{}
	var stop = false

	for next != "" && !stop {
		switch next {
		case "LoginJsInstrumentationSubtask":
			nextData = s.handleJsInstrumentation(flowToken)
		case "LoginEnterUserIdentifierSSO":
			nextData = s.handleEnterUserIdentifier(flowToken, username)
		case "LoginEnterPassword":
			nextData = s.handleEnterPassword(flowToken, password)
		case "LoginTwoFactorAuthChallenge":
			code := confirmation
			nextData = s.handleTwoFactorAuth(flowToken, code)
		case "AccountDuplicationCheck":
			nextData = s.handleAccountDuplicationCheck(flowToken)
		case "LoginEnterAlternateIdentifierSubtask":
			nextData = s.handleLoginEnterAlternateIdentifier(flowToken, email)
		case "LoginAcid":
			nextData = s.handleLoginAcid(flowToken, confirmation)
		case "LoginSuccessSubtask":
			s.isLogged = true
			stop = true
			continue
		default:
			return fmt.Errorf("unknown subtask: %s", next)
		}
		fmt.Printf("current flow is %s\n", next)
		flowToken, next, err = s.doFlow(nextData)

		randomDelay() // Add a delay between requests
	}
	s.isOpenAccount = false
	return err
}

func (s *Scraper) doFlow(data map[string]interface{}) (nextToken string, nextTask string, err error) {
	info, err := s.getFlow(data)
	if err != nil {
		return "", "", err
	}
	if len(info.Errors) > 0 {
		return "", "", fmt.Errorf("auth error (%d): %v", info.Errors[0].Code, info.Errors[0].Message)
	}
	next := ""

	if len(info.Subtasks) > 0 {
		if info.Subtasks[0].SubtaskID == "LoginAcid" {
			err = fmt.Errorf("auth error: %v", "LoginAcid")
		} else if info.Subtasks[0].SubtaskID == "DenyLoginSubtask" {
			err = fmt.Errorf("auth error: %v", "DenyLoginSubtask")
		} else {
			next = info.Subtasks[0].SubtaskID
		}
	}

	return info.FlowToken, next, err
}

func (s *Scraper) initializeLoginFlow() (string, string, error) {
	data := map[string]interface{}{
		"flow_name": "login",
		"input_flow_data": map[string]interface{}{
			"flow_context": map[string]interface{}{
				"referrer_context": map[string]interface{}{
					"referral_details": "utm_source=google-play&utm_medium=organic",
					"referrer_url":     "",
				},
				"debug_overrides": map[string]interface{}{},
				"start_location":  map[string]interface{}{"location": "splash_screen"},
			},
		},
		"subtask_versions": map[string]int{
			"action_list":                          2,
			"alert_dialog":                         1,
			"app_download_cta":                     1,
			"check_logged_in_account":              1,
			"choice_selection":                     3,
			"contacts_live_sync_permission_prompt": 0,
			"cta":                                  7,
			"email_verification":                   2,
			"end_flow":                             1,
			"enter_date":                           1,
			"enter_email":                          2,
			"enter_password":                       5,
			"enter_phone":                          2,
			"enter_recaptcha":                      1,
			"enter_text":                           5,
			"enter_username":                       2,
			"generic_urt":                          3,
			"in_app_notification":                  1,
			"interest_picker":                      3,
			"js_instrumentation":                   1,
			"menu_dialog":                          1,
			"notifications_permission_prompt":      2,
			"open_account":                         2,
			"open_home_timeline":                   1,
			"open_link":                            1,
			"phone_verification":                   4,
			"privacy_options":                      1,
			"security_key":                         3,
			"select_avatar":                        4,
			"select_banner":                        2,
			"settings_list":                        7,
			"show_code":                            1,
			"sign_up":                              2,
			"sign_up_review":                       4,
			"tweet_selection_urt":                  1,
			"update_users":                         1,
			"upload_media":                         1,
			"user_recommendations_list":            4,
			"user_recommendations_urt":             1,
			"wait_spinner":                         3,
			"web_modal":                            1,
		},
	}
	return s.doFlow(data)
}

func (s *Scraper) handleJsInstrumentation(flowToken string) map[string]interface{} {
	return map[string]interface{}{
		"flow_token": flowToken,
		"subtask_inputs": []map[string]interface{}{
			{
				"subtask_id":         "LoginJsInstrumentationSubtask",
				"js_instrumentation": map[string]interface{}{"response": "{}", "link": "next_link"},
			},
		},
	}
}

func (s *Scraper) handleEnterUserIdentifier(flowToken, username string) map[string]interface{} {
	return map[string]interface{}{
		"flow_token": flowToken,
		"subtask_inputs": []map[string]interface{}{
			{
				"subtask_id": "LoginEnterUserIdentifierSSO",
				"settings_list": map[string]interface{}{
					"setting_responses": []map[string]interface{}{
						{
							"key":           "user_identifier",
							"response_data": map[string]interface{}{"text_data": map[string]interface{}{"result": username}},
						},
					},
					"link": "next_link",
				},
			},
		},
	}
}

// identifier maybe email/screen_name/phone_number.
func (s *Scraper) handleLoginEnterAlternateIdentifier(flowToken, identifier string) map[string]interface{} {
	return map[string]interface{}{
		"flow_token": flowToken,
		"subtask_inputs": []map[string]interface{}{
			{
				"subtask_id": "LoginEnterAlternateIdentifierSubtask",
				"enter_text": map[string]interface{}{"text": identifier, "link": "next_link"},
			},
		},
	}
}

func (s *Scraper) handleEnterPassword(flowToken, password string) map[string]interface{} {
	return map[string]interface{}{
		"flow_token": flowToken,
		"subtask_inputs": []map[string]interface{}{
			{
				"subtask_id":     "LoginEnterPassword",
				"enter_password": map[string]interface{}{"password": password, "link": "next_link"},
			},
		},
	}
}

func (s *Scraper) handleTwoFactorAuth(flowToken, code string) map[string]interface{} {
	return map[string]interface{}{
		"flow_token": flowToken,
		"subtask_inputs": []map[string]interface{}{
			{
				"subtask_id": "LoginTwoFactorAuthChallenge",
				"enter_text": map[string]interface{}{"text": code, "link": "next_link"},
			},
		},
	}
}

func (s *Scraper) handleLoginAcid(flowToken, confirmation string) map[string]interface{} {
	return map[string]interface{}{
		"flow_token": flowToken,
		"subtask_inputs": []map[string]interface{}{
			{
				"subtask_id": "LoginAcid",
				"enter_text": map[string]interface{}{"text": confirmation, "link": "next_link"},
			},
		},
	}
}

func (s *Scraper) handleAccountDuplicationCheck(flowToken string) map[string]interface{} {
	return map[string]interface{}{
		"flow_token": flowToken,
		"subtask_inputs": []map[string]interface{}{
			{
				"subtask_id": "AccountDuplicationCheck",
				"check_logged_in_account": map[string]interface{}{
					"link": "AccountDuplicationCheck_false",
				},
			},
		},
	}
}
