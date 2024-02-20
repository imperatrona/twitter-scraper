package twitterscraper_test

import (
	"testing"
)

func TestGetGuestToken(t *testing.T) {
	scraper := newTestScraper(true)

	if err := scraper.GetGuestToken(); err != nil {
		t.Errorf("getGuestToken() error = %v", err)
	}
	if !scraper.IsGuestToken() {
		t.Error("Expected non-empty guestToken")
	}
}

func TestClearGuestToken(t *testing.T) {
	scraper := newTestScraper(false)

	scraper.ClearGuestToken()
	
	if scraper.IsGuestToken() {
		t.Error("Expected empty guestToken")
	}
}
