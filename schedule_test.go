package twitterscraper_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	twitterscraper "github.com/mistadikay/twitter-scraper"
)

func TestFetchScheduledTweets(t *testing.T) {
	if skipAuthTest {
		t.Skip("Skipping test due to environment variable")
	}
	scheduled, err := testScraper.FetchScheduledTweets()
	if err != nil {
		t.Error(err)
	}

	b, _ := json.Marshal(scheduled)
	fmt.Println(string(b))
}

var id string

func TestCreateScheduledTweets(t *testing.T) {
	if skipAuthTest {
		t.Skip("Skipping test due to environment variable")
	}
	var err error

	id, err = testScraper.CreateScheduledTweet(twitterscraper.TweetSchedule{
		Text:   "new tweet",
		Date:   time.Now().Add(time.Hour * 24 * 31),
		Medias: nil,
	})
	if err != nil {
		t.Error(err)
	}
}

func TestDeleteScheduledTweets(t *testing.T) {
	if id == "" {
		t.Skip("run TestCreateScheduledTweets before")
	}
	if err := testScraper.DeleteScheduledTweet(id); err != nil {
		t.Error(err)
	} else {
		id = ""
	}
}
