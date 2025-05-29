package twitterscraper

import (
	"encoding/json"
	"strconv"
	"strings"
)

type tweet struct {
	Core struct {
		UserResults struct {
			Result struct {
				IsBlueVerified bool       `json:"is_blue_verified"`
				Legacy         legacyUser `json:"legacy"`
			} `json:"result"`
		} `json:"user_results"`
	} `json:"core"`
	Views struct {
		Count string `json:"count"`
	} `json:"views"`
	NoteTweet struct {
		NoteTweetResults struct {
			Result struct {
				Text string `json:"text"`
			} `json:"result"`
		} `json:"note_tweet_results"`
	} `json:"note_tweet"`
	QuotedStatusResult struct {
		Result *result `json:"result"`
	} `json:"quoted_status_result"`
	Legacy legacyTweet `json:"legacy"`
	Card   struct {
		RestID string `json:"rest_id"`
		Legacy struct {
			BindingValues []struct {
				Key   string `json:"key"`
				Value struct {
					StringValue string `json:"string_value"`
				} `json:"value"`
			} `json:"binding_values"`
		} `json:"legacy"`
	} `json:"card"`
}

type result struct {
	Typename string `json:"__typename"`
	tweet
	Tweet tweet `json:"tweet"`
}

type UnifiedCard struct {
	Type          string   `json:"type"`
	Components    []string `json:"components"`
	MediaEntities map[string]struct {
		ID            int64  `json:"id"`
		IDStr         string `json:"id_str"`
		MediaURLHTTPS string `json:"media_url_https"`
		Type          string `json:"type"`
		OriginalInfo  struct {
			Width  int `json:"width"`
			Height int `json:"height"`
		} `json:"original_info"`
		SourceUserID int64 `json:"source_user_id"`
		VideoInfo    struct {
			AspectRatio    []int `json:"aspect_ratio"`
			DurationMillis int   `json:"duration_millis"`
			Variants       []struct {
				Bitrate     int    `json:"bitrate,omitempty"`
				ContentType string `json:"content_type"`
				URL         string `json:"url"`
			} `json:"variants"`
		} `json:"video_info"`
	} `json:"media_entities"`
}

func (result *result) parse() *Tweet {
	if result.NoteTweet.NoteTweetResults.Result.Text != "" {
		result.Legacy.FullText = result.NoteTweet.NoteTweetResults.Result.Text
	}
	var legacy *legacyTweet = &result.Legacy
	var user *legacyUser = &result.Core.UserResults.Result.Legacy
	if result.Typename == "TweetWithVisibilityResults" {
		legacy = &result.Tweet.Legacy
		user = &result.Tweet.Core.UserResults.Result.Legacy
	}
	tw := parseLegacyTweet(user, legacy)
	if tw == nil {
		return nil
	}
	if tw.Views == 0 && result.Views.Count != "" {
		tw.Views, _ = strconv.Atoi(result.Views.Count)
	}
	if result.QuotedStatusResult.Result != nil {
		tw.QuotedStatus = result.QuotedStatusResult.Result.parse()
	}

	// Get videos from cards
	for _, v := range result.Tweet.Card.Legacy.BindingValues {
		if v.Key == "unified_card" {
			var card UnifiedCard
			err := json.Unmarshal([]byte(v.Value.StringValue), &card)
			if err != nil {
				continue
			}

			for _, media := range card.MediaEntities {
				if media.Type == "video" {
					var vid Video

					vid.ID = media.IDStr
					vid.Preview = media.MediaURLHTTPS

					var bitrate int
					for _, variant := range media.VideoInfo.Variants {
						if variant.ContentType == "video/mp4" {
							if variant.Bitrate > bitrate {
								bitrate = variant.Bitrate
								vid.URL = variant.URL
							}
						} else if variant.ContentType == "application/x-mpegURL" {
							vid.HLSURL = variant.URL
						}
					}

					if vid.URL != "" {
						tw.Videos = append(tw.Videos, vid)
					}
				}
			}
		}
	}

	return tw
}

type userResult struct {
	Typename                   string                `json:"__typename"`
	ID                         string                `json:"id"`
	RestID                     string                `json:"rest_id"`
	AffiliatesHighlightedLabel struct{}              `json:"affiliates_highlighted_label"`
	HasGraduatedAccess         bool                  `json:"has_graduated_access"`
	IsBlueVerified             bool                  `json:"is_blue_verified"`
	ProfileImageShape          string                `json:"profile_image_shape"`
	Legacy                     legacyUserV2          `json:"legacy"`
	LegacyExtendedProfile      legacyExtendedProfile `json:"legacy_extended_profile"`
	IsProfileTranslatable      bool                  `json:"is_profile_translatable"`
	VerificationInfo           verificationInfo      `json:"verification_info"`
	HighlightsInfo             highlightsInfo        `json:"highlights_info"`
	UserSeedTweetCount         int                   `json:"user_seed_tweet_count"`
	PremiumGiftingEligible     bool                  `json:"premium_gifting_eligible"`
	CreatorSubscriptionsCount  int                   `json:"creator_subscriptions_count"`
}

func (result *userResult) parse() Profile {
	return parseProfileV2(*result)
}

type item struct {
	EntryID string `json:"entryId"`
	Item    struct {
		ItemContent struct {
			ItemType         string `json:"itemType"`
			TweetDisplayType string `json:"tweetDisplayType"`
			TweetResults     struct {
				Result result `json:"result"`
			} `json:"tweet_results"`
			CursorType string `json:"cursorType"`
			Value      string `json:"value"`
		} `json:"itemContent"`
	} `json:"item"`
}

type entry struct {
	Content struct {
		CursorType  string `json:"cursorType"`
		Value       string `json:"value"`
		Items       []item `json:"items"`
		ItemContent struct {
			ItemType         string `json:"itemType"`
			TweetDisplayType string `json:"tweetDisplayType"`
			TweetResults     struct {
				Result result `json:"result"`
			} `json:"tweet_results"`
			UserDisplayType string `json:"userDisplayType"`
			UserResults     struct {
				Result userResult `json:"result"`
			} `json:"user_results"`
			CursorType string `json:"cursorType"`
			Value      string `json:"value"`
		} `json:"itemContent"`
	} `json:"content"`
}

// timeline v2 JSON object
type timelineV2 struct {
	Data struct {
		User struct {
			Result struct {
				TimelineV2 struct {
					Timeline struct {
						Instructions []struct {
							ModuleItems []item  `json:"moduleItems"`
							Entries     []entry `json:"entries"`
							Entry       entry   `json:"entry"`
							Type        string  `json:"type"`
						} `json:"instructions"`
					} `json:"timeline"`
				} `json:"timeline_v2"`

				Timeline struct {
					Timeline struct {
						Instructions []struct {
							Entries []entry `json:"entries"`
							Entry   entry   `json:"entry"`
							Type    string  `json:"type"`
						} `json:"instructions"`
					} `json:"timeline"`
				} `json:"timeline"`
			} `json:"result"`
		} `json:"user"`
	} `json:"data"`
}

func (timeline *timelineV2) parseTweets() ([]*Tweet, string) {
	var cursor string
	var tweets []*Tweet
	for _, instruction := range timeline.Data.User.Result.TimelineV2.Timeline.Instructions {
		for _, entry := range instruction.Entries {
			if entry.Content.CursorType == "Bottom" {
				cursor = entry.Content.Value
				continue
			}
			if entry.Content.ItemContent.TweetResults.Result.Typename == "Tweet" || entry.Content.ItemContent.TweetResults.Result.Typename == "TweetWithVisibilityResults" {
				if tweet := entry.Content.ItemContent.TweetResults.Result.parse(); tweet != nil {
					tweets = append(tweets, tweet)
				}
			}
			if len(entry.Content.Items) > 0 {
				for _, item := range entry.Content.Items {
					if tweet := item.Item.ItemContent.TweetResults.Result.parse(); tweet != nil {
						tweets = append(tweets, tweet)
					}
				}
			}
		}
		if len(instruction.ModuleItems) > 0 {
			for _, entry := range instruction.ModuleItems {
				if entry.Item.ItemContent.TweetResults.Result.Typename == "Tweet" || entry.Item.ItemContent.TweetResults.Result.Typename == "TweetWithVisibilityResults" {
					if tweet := entry.Item.ItemContent.TweetResults.Result.parse(); tweet != nil {
						tweets = append(tweets, tweet)
					}
				}
			}
		}
	}
	return tweets, cursor
}

type bookmarksTimelineV2 struct {
	Data struct {
		Bookmarks struct {
			Timeline struct {
				Instructions []struct {
					Entries []entry `json:"entries"`
					Type    string  `json:"type"`
				} `json:"instructions"`
			} `json:"timeline"`
		} `json:"bookmark_timeline_v2"`
	} `json:"data"`
}

func (timeline *bookmarksTimelineV2) parseTweets() ([]*Tweet, string) {
	var cursor string
	var tweets []*Tweet
	for _, instruction := range timeline.Data.Bookmarks.Timeline.Instructions {
		for _, entry := range instruction.Entries {
			if entry.Content.CursorType == "Bottom" {
				cursor = entry.Content.Value
				continue
			}
			if entry.Content.ItemContent.TweetResults.Result.Typename == "Tweet" {
				if tweet := entry.Content.ItemContent.TweetResults.Result.parse(); tweet != nil {
					tweets = append(tweets, tweet)
				}
			}
		}
	}
	return tweets, cursor
}

type retweetersTimelineV2 struct {
	Data struct {
		RetweetersTimeline struct {
			Timeline struct {
				Instructions []struct {
					Type    string  `json:"type"`
					Entries []entry `json:"entries"`
				} `json:"instructions"`
			} `json:"timeline"`
		} `json:"retweeters_timeline"`
	} `json:"data"`
}

func (timeline *retweetersTimelineV2) parseUsers() ([]*Profile, string) {
	var cursor string
	var users []*Profile
	for _, instruction := range timeline.Data.RetweetersTimeline.Timeline.Instructions {
		for _, entry := range instruction.Entries {
			if entry.Content.CursorType == "Bottom" {
				cursor = entry.Content.Value
				continue
			}
			if entry.Content.ItemContent.UserResults.Result.Typename == "User" {
				user := entry.Content.ItemContent.UserResults.Result.parse()
				users = append(users, &user)
			}
		}
	}
	return users, cursor
}

func (timeline *timelineV2) parseUsers() ([]*Profile, string) {
	var cursor string
	var users []*Profile
	for _, instruction := range timeline.Data.User.Result.Timeline.Timeline.Instructions {
		for _, entry := range instruction.Entries {
			if entry.Content.CursorType == "Bottom" {
				cursor = entry.Content.Value
				continue
			}
			if entry.Content.ItemContent.UserResults.Result.Typename == "User" {
				user := entry.Content.ItemContent.UserResults.Result.parse()
				users = append(users, &user)
			}
		}
	}
	return users, cursor
}

type threadedConversation struct {
	Data struct {
		ThreadedConversationWithInjectionsV2 struct {
			Instructions []struct {
				Type        string  `json:"type"`
				Entry       entry   `json:"entry"`
				Entries     []entry `json:"entries"`
				ModuleItems []item  `json:"moduleItems"`
			} `json:"instructions"`
		} `json:"threaded_conversation_with_injections_v2"`
	} `json:"data"`
}

func (conversation *threadedConversation) parse(focalTweetID string) ([]*Tweet, []*ThreadCursor) {
	var tweets []*Tweet
	var cursors []*ThreadCursor
	for _, instruction := range conversation.Data.ThreadedConversationWithInjectionsV2.Instructions {
		for _, entry := range instruction.Entries {
			if entry.Content.ItemContent.TweetResults.Result.Typename == "Tweet" || entry.Content.ItemContent.TweetResults.Result.Typename == "TweetWithVisibilityResults" {
				if tweet := entry.Content.ItemContent.TweetResults.Result.parse(); tweet != nil {
					if entry.Content.ItemContent.TweetDisplayType == "SelfThread" {
						tweet.IsSelfThread = true
					}
					tweets = append(tweets, tweet)
				}
			}

			if entry.Content.ItemContent.CursorType != "" && entry.Content.ItemContent.Value != "" {
				cursors = append(cursors, &ThreadCursor{
					FocalTweetID: focalTweetID,
					ThreadID:     focalTweetID,
					Cursor:       entry.Content.ItemContent.Value,
					CursorType:   entry.Content.ItemContent.CursorType,
				})
			}

			for _, item := range entry.Content.Items {
				if item.Item.ItemContent.TweetResults.Result.Typename == "Tweet" || item.Item.ItemContent.TweetResults.Result.Typename == "TweetWithVisibilityResults" {
					if tweet := item.Item.ItemContent.TweetResults.Result.parse(); tweet != nil {
						if item.Item.ItemContent.TweetDisplayType == "SelfThread" {
							tweet.IsSelfThread = true
						}
						tweets = append(tweets, tweet)
					}
				}

				if item.Item.ItemContent.CursorType != "" && item.Item.ItemContent.Value != "" {
					threadID := ""

					entryId := strings.Split(item.EntryID, "-")
					if len(entryId) > 1 && entryId[0] == "conversationthread" {
						if i, _ := strconv.Atoi(entryId[1]); i != 0 {
							threadID = entryId[1]
						}
					}

					cursors = append(cursors, &ThreadCursor{
						FocalTweetID: focalTweetID,
						ThreadID:     threadID,
						Cursor:       item.Item.ItemContent.Value,
						CursorType:   item.Item.ItemContent.CursorType,
					})
				}
			}
		}
		for _, item := range instruction.ModuleItems {
			if item.Item.ItemContent.TweetResults.Result.Typename == "Tweet" || item.Item.ItemContent.TweetResults.Result.Typename == "TweetWithVisibilityResults" {
				if tweet := item.Item.ItemContent.TweetResults.Result.parse(); tweet != nil {
					if item.Item.ItemContent.TweetDisplayType == "SelfThread" {
						tweet.IsSelfThread = true
					}
					tweets = append(tweets, tweet)
				}
			}

			if item.Item.ItemContent.CursorType != "" && item.Item.ItemContent.Value != "" {
				threadID := ""

				entryId := strings.Split(item.EntryID, "-")
				if len(entryId) > 1 && entryId[0] == "conversationthread" {
					if i, _ := strconv.Atoi(entryId[1]); i != 0 {
						threadID = entryId[1]
					}
				}

				cursors = append(cursors, &ThreadCursor{
					FocalTweetID: focalTweetID,
					ThreadID:     threadID,
					Cursor:       item.Item.ItemContent.Value,
					CursorType:   item.Item.ItemContent.CursorType,
				})
			}
		}
	}

	for _, tweet := range tweets {
		if tweet.InReplyToStatusID != "" {
			for _, parentTweet := range tweets {
				if parentTweet.ID == tweet.InReplyToStatusID {
					tweet.InReplyToStatus = parentTweet
					break
				}
			}
		}
		if tweet.IsSelfThread && tweet.ConversationID == tweet.ID {
			for _, childTweet := range tweets {
				if childTweet.IsSelfThread && childTweet.ID != tweet.ID {
					tweet.Thread = append(tweet.Thread, childTweet)
				}
			}
			if len(tweet.Thread) == 0 {
				tweet.IsSelfThread = false
			}
		}
	}
	return tweets, cursors
}

type tweetResult struct {
	Data struct {
		TweetResult struct {
			Result result `json:"result"`
		} `json:"tweetResult"`
	} `json:"data"`
}

func (tweetResult *tweetResult) parse() *Tweet {
	return tweetResult.Data.TweetResult.Result.parse()
}
