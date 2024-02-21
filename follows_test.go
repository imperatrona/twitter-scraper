package twitterscraper_test

import (
	"testing"
)

func TestFetchFollowing(t *testing.T) {
	users, _, err := testScraper.FetchFollowing("Support", 20, "")
	if err != nil {
		t.Error(err)
	}
	if len(users) < 1 || users[len(users)-1].Username == "" {
		t.Error("error FetchFollowing() No users found")
	}
}
