package twitterscraper_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	twitterscraper "github.com/imperatrona/twitter-scraper"
)

var cmpOptions = cmp.Options{
	cmpopts.IgnoreFields(twitterscraper.Tweet{}, "Likes"),
	cmpopts.IgnoreFields(twitterscraper.Tweet{}, "Replies"),
	cmpopts.IgnoreFields(twitterscraper.Tweet{}, "Retweets"),
	cmpopts.IgnoreFields(twitterscraper.Tweet{}, "Views"),

	cmpopts.IgnoreFields(twitterscraper.Tweet{}, "IsSelfThread"),
	cmpopts.IgnoreFields(twitterscraper.Tweet{}, "Thread"),
	cmpopts.IgnoreFields(twitterscraper.Tweet{}, "TimeParsed"),
}

func TestGetTweets(t *testing.T) {
	count := 0
	maxTweetsNbr := 100
	dupcheck := make(map[string]bool)
	for tweet := range testScraper.GetTweets(context.Background(), "x", maxTweetsNbr) {
		if tweet.Error != nil {
			t.Error(tweet.Error)
		} else {
			count++
			if tweet.ID == "" {
				t.Error("Expected tweet ID is empty")
			} else {
				if dupcheck[tweet.ID] {
					t.Errorf("Detect duplicated tweet ID: %s", tweet.ID)
				} else {
					dupcheck[tweet.ID] = true
				}
			}
			if tweet.UserID == "" {
				t.Error("Expected tweet UserID is empty")
			}
			if tweet.Username == "" {
				t.Error("Expected tweet Username is empty")
			}
			if tweet.PermanentURL == "" {
				t.Error("Expected tweet PermanentURL is empty")
			}
			if tweet.Text == "" {
				t.Error("Expected tweet Text is empty")
			}
			if tweet.TimeParsed.IsZero() {
				t.Error("Expected tweet TimeParsed is zero")
			}
			if tweet.Timestamp == 0 {
				t.Error("Expected tweet Timestamp is greater than zero")
			}
			for _, video := range tweet.Videos {
				if video.ID == "" {
					t.Error("Expected tweet video ID is empty")
				}
				if video.Preview == "" {
					t.Error("Expected tweet video Preview is empty")
				}
				if video.URL == "" {
					t.Error("Expected tweet video URL is empty")
				}
			}
		}
	}
	if count != maxTweetsNbr {
		t.Errorf("Expected tweets count=%v, got: %v", maxTweetsNbr, count)
	}
}

func assertGetTweet(t *testing.T, expectedTweet *twitterscraper.Tweet) {
	// to get tweet as struct fmt.Printf("%#v", actualTweet)
	actualTweet, err := testScraper.GetTweet(expectedTweet.ID)
	if err != nil {
		t.Error(err)
	} else if diff := cmp.Diff(expectedTweet, actualTweet, cmpOptions...); diff != "" {
		t.Error("Resulting tweet does not match the sample", diff)
	}
}

func TestGetTweetWithVideo(t *testing.T) {
	expectedTweet := twitterscraper.Tweet{
		ConversationID: "1697304622749086011",
		HTML:           "on iOS &amp; Android, you can now swipe to reply when you slide into their DMs <br><a href=\"https://t.co/evuWpMfBxQ\"><img src=\"https://pbs.twimg.com/amplify_video_thumb/1697304568550330368/img/BUlESpef6FmWV_j2.jpg\"/></a>",
		ID:             "1697304622749086011",
		Name:           "X",
		PermanentURL:   "https://twitter.com/X/status/1697304622749086011",
		Photos:         nil,
		Text:           "on iOS &amp; Android, you can now swipe to reply when you slide into their DMs https://t.co/evuWpMfBxQ",
		Timestamp:      1693503931,
		UserID:         "783214",
		Username:       "X",
		Videos: []twitterscraper.Video{
			{
				ID:      "1697304568550330368",
				Preview: "https://pbs.twimg.com/amplify_video_thumb/1697304568550330368/img/BUlESpef6FmWV_j2.jpg",
				URL:     "https://video.twimg.com/amplify_video/1697304568550330368/vid/720x720/KyQlZA9zaf0kqY9Z.mp4?tag=14",
			},
		},
	}
	assertGetTweet(t, &expectedTweet)
}

func TestGetTweetWithMultiplePhotos(t *testing.T) {
	expectedTweet := twitterscraper.Tweet{
		ConversationID: "1577677328968204291",
		HTML:           "More ways to discover videos on Twitter are here!<br><br>Now on iOS, videos on your timeline will open in our full screen immersive video player, where you can swipe up to keep discovering more content. <br><a href=\"https://t.co/XI2vM8DKXA\"><img src=\"https://pbs.twimg.com/media/FeUJKdnXEAEFe2j.jpg\"/></a><br><img src=\"https://pbs.twimg.com/media/FeUJKuxXEAAa6t7.jpg\"/>",
		ID:             "1577677328968204291",
		Name:           "Support",
		PermanentURL:   "https://twitter.com/Support/status/1577677328968204291",
		Photos: []twitterscraper.Photo{
			{
				ID:  "1577677319816286209",
				URL: "https://pbs.twimg.com/media/FeUJKdnXEAEFe2j.jpg",
			},
			{
				ID:  "1577677324421632000",
				URL: "https://pbs.twimg.com/media/FeUJKuxXEAAa6t7.jpg",
			},
		},
		Text:      "More ways to discover videos on Twitter are here!\n\nNow on iOS, videos on your timeline will open in our full screen immersive video player, where you can swipe up to keep discovering more content. https://t.co/XI2vM8DKXA",
		Timestamp: 1664982561,
		UserID:    "17874544",
		Username:  "Support",
	}
	assertGetTweet(t, &expectedTweet)
}

func TestGetTweetWithGIF(t *testing.T) {
	if skipAuthTest {
		t.Skip("Skipping test due to environment variable")
	}
	expectedTweet := twitterscraper.Tweet{
		ConversationID: "1517535384833605632",
		GIFs: []twitterscraper.GIF{
			{
				ID:      "1517535349890813952",
				Preview: "https://pbs.twimg.com/tweet_video_thumb/FQ9eXEhXEAA-haj.jpg",
				URL:     "https://video.twimg.com/tweet_video/FQ9eXEhXEAA-haj.mp4",
			},
		},
		HTML:         "Video captions or no captions, it’s now easier to choose for some of you on iOS, and soon on Android.<br><br>On videos that have captions available, we’re testing the option to turn captions off/on with a new “CC” button. <br><a href=\"https://t.co/Q2Q2Wmr78U\"><img src=\"https://pbs.twimg.com/tweet_video_thumb/FQ9eXEhXEAA-haj.jpg\"/></a>",
		ID:           "1517535384833605632",
		Name:         "Support",
		PermanentURL: "https://twitter.com/Support/status/1517535384833605632",
		Text:         "Video captions or no captions, it’s now easier to choose for some of you on iOS, and soon on Android.\n\nOn videos that have captions available, we’re testing the option to turn captions off/on with a new “CC” button. https://t.co/Q2Q2Wmr78U",
		Timestamp:    1650643604,
		UserID:       "17874544",
		Username:     "Support",
	}
	assertGetTweet(t, &expectedTweet)
}

func TestGetTweetWithPhotoAndGIF(t *testing.T) {
	if skipAuthTest {
		t.Skip("Skipping test due to environment variable")
	}
	expectedTweet := twitterscraper.Tweet{
		ConversationID: "1583186305722507265",
		GIFs: []twitterscraper.GIF{
			{
				ID:      "1583186295588790290",
				Preview: "https://pbs.twimg.com/tweet_video_thumb/FfibjDnWIBIt5fn.jpg",
				URL:     "https://video.twimg.com/tweet_video/FfibjDnWIBIt5fn.mp4",
			},
		},
		HTML:         "“we need to talk” <br><br>irl vs on Spaces <br><a href=\"https://t.co/hrflPpbpif\"><img src=\"https://pbs.twimg.com/tweet_video_thumb/FfibjDnWIBIt5fn.jpg\"/></a><br><img src=\"https://pbs.twimg.com/media/FfibjDwWIAwvbtJ.jpg\"/>",
		ID:           "1583186305722507265",
		Name:         "Spaces",
		PermanentURL: "https://twitter.com/XSpaces/status/1583186305722507265",
		Photos:       []twitterscraper.Photo{{ID: "1583186295626539020", URL: "https://pbs.twimg.com/media/FfibjDwWIAwvbtJ.jpg"}},
		Text:         "“we need to talk” \n\nirl vs on Spaces https://t.co/hrflPpbpif",
		Timestamp:    1666296004,
		UserID:       "1065249714214457345",
		Username:     "XSpaces",
	}
	assertGetTweet(t, &expectedTweet)
}

func TestTweetMentions(t *testing.T) {
	sample := []twitterscraper.Mention{{
		ID:       "7018222",
		Username: "davidmcraney",
		Name:     "David McRaney",
	}}
	tweet, err := testScraper.GetTweet("1554522888904101890")
	if err != nil {
		t.Error(err)
	} else {
		if diff := cmp.Diff(sample, tweet.Mentions, cmpOptions...); diff != "" {
			t.Error("Resulting tweet does not match the sample", diff)
		}
	}
}

func TestQuotedAndReply(t *testing.T) {
	sample := &twitterscraper.Tweet{
		ConversationID: "1237110546383724547",
		HTML:           "The Easiest Problem Everyone Gets Wrong <br><br>[new video] --&gt; <a href=\"https://youtu.be/ytfCdqWhmdg\">https://t.co/YdaeDYmPAU</a> <br><a href=\"https://t.co/iKu4Xs6o2V\"><img src=\"https://pbs.twimg.com/media/ESsZa9AXgAIAYnF.jpg\"/></a>",
		ID:             "1237110546383724547",
		Likes:          485,
		Name:           "Vsauce2",
		PermanentURL:   "https://twitter.com/VsauceTwo/status/1237110546383724547",
		Photos: []twitterscraper.Photo{{
			ID:  "1237110473486729218",
			URL: "https://pbs.twimg.com/media/ESsZa9AXgAIAYnF.jpg",
		}},
		Replies:   12,
		Retweets:  18,
		Text:      "The Easiest Problem Everyone Gets Wrong \n\n[new video] --&gt; https://t.co/YdaeDYmPAU https://t.co/iKu4Xs6o2V",
		Timestamp: 1583785113,
		URLs:      []string{"https://youtu.be/ytfCdqWhmdg"},
		UserID:    "978944851",
		Username:  "VsauceTwo",
	}
	tweet, err := testScraper.GetTweet("1237110897597976576")
	if err != nil {
		t.Error(err)
	} else {
		if !tweet.IsQuoted {
			t.Error("IsQuoted must be True")
		}
		if diff := cmp.Diff(sample, tweet.QuotedStatus, cmpOptions...); diff != "" {
			t.Error("Resulting quote does not match the sample", diff)
		}
	}
	tweet, err = testScraper.GetTweet("1237111868445134850")
	if err != nil {
		t.Error(err)
	} else {
		if !tweet.IsReply {
			t.Error("IsReply must be True")
		}
		if diff := cmp.Diff(sample, tweet.InReplyToStatus, cmpOptions...); diff != "" {
			t.Error("Resulting reply does not match the sample", diff)
		}
	}

}
func TestRetweet(t *testing.T) {
	sample := &twitterscraper.Tweet{
		ConversationID: "1758837061786779942",
		HTML:           "no ads, just bangers<br><br>aka your For You feed with Premium+<br><br>subscribe here → <a href=\"https://x.com/i/premium_sign_up\">https://t.co/APTO1t7kMk</a>",
		ID:             "1758837061786779942",
		URLs:           []string{"https://x.com/i/premium_sign_up"},
		IsSelfThread:   false,
		Name:           "Premium",
		PermanentURL:   "https://twitter.com/premium/status/1758837061786779942",
		Text:           "no ads, just bangers\n\naka your For You feed with Premium+\n\nsubscribe here → https://t.co/APTO1t7kMk",
		Timestamp:      1708174407,
		UserID:         "1399766153053061121",
		Username:       "premium",
	}
	tweet, err := testScraper.GetTweet("1758837226379596068")
	if err != nil {
		t.Error(err)
	} else {
		if !tweet.IsRetweet {
			t.Error("IsRetweet must be True")
		}
		if diff := cmp.Diff(sample, tweet.RetweetedStatus, cmpOptions...); diff != "" {
			t.Error("Resulting retweet does not match the sample", diff)
		}
	}
}

func TestTweetViews(t *testing.T) {
	sample := &twitterscraper.Tweet{
		HTML:         "Replies and likes don’t tell the whole story. We’re making it easier to tell *just* how many people have seen your Tweets with the addition of view counts, shown right next to likes. Now on iOS and Android, web coming soon.",
		ID:           "1606055187348688896",
		Likes:        2839,
		Name:         "Support",
		PermanentURL: "https://twitter.com/Support/status/1606055187348688896",
		Replies:      3427,
		Retweets:     783,
		Text:         "Replies and likes don’t tell the whole story. We’re making it easier to tell *just* how many people have seen your Tweets with the addition of view counts, shown right next to likes. Now on iOS and Android, web coming soon.",
		Timestamp:    1612881838,
		UserID:       "17874544",
		Username:     "Support",
		Views:        3189278,
	}
	tweet, err := testScraper.GetTweet("1606055187348688896")
	if err != nil {
		t.Error(err)
	} else {
		if tweet.Views < sample.Views {
			t.Error("Views must be greater than or equal to the sample")
		}
	}
}

func TestTweetThread(t *testing.T) {
	if skipAuthTest {
		t.Skip("Skipping test due to environment variable")
	}
	tweet, err := testScraper.GetTweet("1665602315745673217")
	if err != nil {
		t.Fatal(err)
	} else {
		if !tweet.IsSelfThread {
			t.Error("IsSelfThread must be True")
		}
		if len(tweet.Thread) != 7 {
			t.Error("Thread length must be 7")
		}
	}
}
