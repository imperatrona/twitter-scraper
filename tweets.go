package twitterscraper

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strconv"
)

// GetTweets returns channel with tweets for a given user.
func (s *Scraper) GetTweets(ctx context.Context, user string, maxTweetsNbr int) <-chan *TweetResult {
	return getTweetTimeline(ctx, user, maxTweetsNbr, s.FetchTweets)
}

// FetchTweets gets tweets for a given user, via the Twitter frontend API.
func (s *Scraper) FetchTweets(user string, maxTweetsNbr int, cursor string) ([]*Tweet, string, error) {
	userID, err := s.GetUserIDByScreenName(user)
	if err != nil {
		return nil, "", err
	}

	if s.isOpenAccount {
		return s.FetchTweetsByUserIDLegacy(userID, maxTweetsNbr, cursor)
	}
	return s.FetchTweetsByUserID(userID, maxTweetsNbr, cursor)
}

// FetchTweetsByUserID gets tweets for a given userID, via the Twitter frontend GraphQL API.
func (s *Scraper) FetchTweetsByUserID(userID string, maxTweetsNbr int, cursor string) ([]*Tweet, string, error) {
	if maxTweetsNbr > 200 {
		maxTweetsNbr = 200
	}

	req, err := s.newRequest("GET", "https://twitter.com/i/api/graphql/UGi7tjRPr-d_U3bCPIko5Q/UserTweets")
	if err != nil {
		return nil, "", err
	}

	variables := map[string]interface{}{
		"userId":                                 userID,
		"count":                                  maxTweetsNbr,
		"includePromotedContent":                 false,
		"withQuickPromoteEligibilityTweetFields": false,
		"withVoice":                              true,
		"withV2Timeline":                         true,
	}
	features := map[string]interface{}{
		"rweb_lists_timeline_redesign_enabled":                              true,
		"responsive_web_graphql_exclude_directive_enabled":                  true,
		"verified_phone_label_enabled":                                      false,
		"creator_subscriptions_tweet_preview_api_enabled":                   true,
		"responsive_web_graphql_timeline_navigation_enabled":                true,
		"responsive_web_graphql_skip_user_profile_image_extensions_enabled": false,
		"tweetypie_unmention_optimization_enabled":                          true,
		"vibe_api_enabled":                                                        true,
		"responsive_web_edit_tweet_api_enabled":                                   true,
		"graphql_is_translatable_rweb_tweet_is_translatable_enabled":              true,
		"view_counts_everywhere_api_enabled":                                      true,
		"longform_notetweets_consumption_enabled":                                 true,
		"tweet_awards_web_tipping_enabled":                                        false,
		"freedom_of_speech_not_reach_fetch_enabled":                               true,
		"standardized_nudges_misinfo":                                             true,
		"tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled": false,
		"interactive_text_enabled":                                                true,
		"responsive_web_text_conversations_enabled":                               false,
		"longform_notetweets_rich_text_read_enabled":                              true,
		"longform_notetweets_inline_media_enabled":                                false,
		"responsive_web_enhance_cards_enabled":                                    false,
	}

	if cursor != "" {
		variables["cursor"] = cursor
	}

	query := url.Values{}
	query.Set("variables", mapToJSONString(variables))
	query.Set("features", mapToJSONString(features))
	req.URL.RawQuery = query.Encode()

	var timeline timelineV2
	err = s.RequestAPI(req, &timeline)
	if err != nil {
		return nil, "", err
	}

	tweets, nextCursor := timeline.parseTweets()
	return tweets, nextCursor, nil
}

// FetchTweetsByUserIDLegacy gets tweets for a given userID, via the Twitter frontend legacy API.
func (s *Scraper) FetchTweetsByUserIDLegacy(userID string, maxTweetsNbr int, cursor string) ([]*Tweet, string, error) {
	if maxTweetsNbr > 200 {
		maxTweetsNbr = 200
	}

	req, err := s.newRequest("GET", "https://api.twitter.com/2/timeline/profile/"+userID+".json")
	if err != nil {
		return nil, "", err
	}

	q := req.URL.Query()
	q.Add("count", strconv.Itoa(maxTweetsNbr))
	q.Add("userId", userID)
	if cursor != "" {
		q.Add("cursor", cursor)
	}
	req.URL.RawQuery = q.Encode()

	var timeline timelineV1
	err = s.RequestAPI(req, &timeline)
	if err != nil {
		return nil, "", err
	}

	tweets, nextCursor := timeline.parseTweets()
	return tweets, nextCursor, nil
}

// GetTweet get a single tweet by ID.
func (s *Scraper) GetTweet(id string) (*Tweet, error) {
	if s.isOpenAccount {
		req, err := s.newRequest("GET", "https://api.twitter.com/2/timeline/conversation/"+id+".json")
		if err != nil {
			return nil, err
		}

		var timeline timelineV1
		err = s.RequestAPI(req, &timeline)
		if err != nil {
			return nil, err
		}

		tweets, _ := timeline.parseTweets()
		for _, tweet := range tweets {
			if tweet.ID == id {
				return tweet, nil
			}
		}
	} else if s.isLogged {
		req, err := s.newRequest("GET", "https://twitter.com/i/api/graphql/VWFGPVAGkZMGRKGe3GFFnA/TweetDetail")
		if err != nil {
			return nil, err
		}

		variables := map[string]interface{}{
			"focalTweetId":                           id,
			"with_rux_injections":                    false,
			"includePromotedContent":                 true,
			"withCommunity":                          true,
			"withQuickPromoteEligibilityTweetFields": true,
			"withBirdwatchNotes":                     true,
			"withVoice":                              true,
			"withV2Timeline":                         true,
		}

		features := map[string]interface{}{
			"rweb_lists_timeline_redesign_enabled":                                    true,
			"responsive_web_graphql_exclude_directive_enabled":                        true,
			"verified_phone_label_enabled":                                            false,
			"creator_subscriptions_tweet_preview_api_enabled":                         true,
			"responsive_web_graphql_timeline_navigation_enabled":                      true,
			"responsive_web_graphql_skip_user_profile_image_extensions_enabled":       false,
			"tweetypie_unmention_optimization_enabled":                                true,
			"responsive_web_edit_tweet_api_enabled":                                   true,
			"graphql_is_translatable_rweb_tweet_is_translatable_enabled":              true,
			"view_counts_everywhere_api_enabled":                                      true,
			"longform_notetweets_consumption_enabled":                                 true,
			"tweet_awards_web_tipping_enabled":                                        false,
			"freedom_of_speech_not_reach_fetch_enabled":                               true,
			"standardized_nudges_misinfo":                                             true,
			"tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled": false,
			"longform_notetweets_rich_text_read_enabled":                              true,
			"longform_notetweets_inline_media_enabled":                                true,
			"responsive_web_enhance_cards_enabled":                                    false,
		}

		query := url.Values{}
		query.Set("variables", mapToJSONString(variables))
		query.Set("features", mapToJSONString(features))
		req.URL.RawQuery = query.Encode()

		var conversation threadedConversation

		// Surprisingly, if bearerToken2 is not set, then animated GIFs are not
		// present in the response for tweets with a GIF + a photo like this one:
		// https://twitter.com/Twitter/status/1580661436132757506
		curBearerToken := s.bearerToken
		if curBearerToken != bearerToken2 {
			s.setBearerToken(bearerToken2)
		}

		err = s.RequestAPI(req, &conversation)

		if curBearerToken != bearerToken2 {
			s.setBearerToken(curBearerToken)
		}

		if err != nil {
			return nil, err
		}

		tweets := conversation.parse()
		for _, tweet := range tweets {
			if tweet.ID == id {
				return tweet, nil
			}
		}
	} else {
		req, err := s.newRequest("GET", "https://twitter.com/i/api/graphql/xBtHv5-Xsk268T5ng_OGNg/TweetResultByRestId")
		if err != nil {
			return nil, err
		}
		variables := map[string]interface{}{
			"tweetId":                id,
			"withCommunity":          false,
			"includePromotedContent": false,
			"withVoice":              false,
		}

		features := map[string]interface{}{
			"creator_subscriptions_tweet_preview_api_enabled":                         true,
			"c9s_tweet_anatomy_moderator_badge_enabled":                               true,
			"tweetypie_unmention_optimization_enabled":                                true,
			"responsive_web_edit_tweet_api_enabled":                                   true,
			"graphql_is_translatable_rweb_tweet_is_translatable_enabled":              true,
			"view_counts_everywhere_api_enabled":                                      true,
			"longform_notetweets_consumption_enabled":                                 true,
			"responsive_web_twitter_article_tweet_consumption_enabled":                true,
			"tweet_awards_web_tipping_enabled":                                        false,
			"freedom_of_speech_not_reach_fetch_enabled":                               true,
			"standardized_nudges_misinfo":                                             true,
			"tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled": true,
			"rweb_video_timestamps_enabled":                                           true,
			"longform_notetweets_rich_text_read_enabled":                              true,
			"longform_notetweets_inline_media_enabled":                                true,
			"responsive_web_graphql_exclude_directive_enabled":                        true,
			"verified_phone_label_enabled":                                            false,
			"responsive_web_graphql_skip_user_profile_image_extensions_enabled":       false,
			"responsive_web_graphql_timeline_navigation_enabled":                      true,
			"responsive_web_enhance_cards_enabled":                                    false,
		}

		fieldToggles := map[string]interface{}{"withArticleRichContentState": true}

		query := url.Values{}
		query.Set("variables", mapToJSONString(variables))
		query.Set("features", mapToJSONString(features))
		query.Set("fieldToggles", mapToJSONString(fieldToggles))
		req.URL.RawQuery = query.Encode()

		var result tweetResult

		// Surprisingly, if bearerToken2 is not set, then animated GIFs are not
		// present in the response for tweets with a GIF + a photo like this one:
		// https://twitter.com/Twitter/status/1580661436132757506
		curBearerToken := s.bearerToken
		if curBearerToken != bearerToken2 {
			s.setBearerToken(bearerToken2)
		}

		err = s.RequestAPI(req, &result)

		if curBearerToken != bearerToken2 {
			s.setBearerToken(curBearerToken)
		}

		if err != nil {
			return nil, err
		}

		tweet := result.parse()
		return tweet, nil
	}
	return nil, fmt.Errorf("tweet with ID %s not found", id)
}

type homeEntry struct {
	EntryId   string `json:"entryId"`
	SortIndex string `json:"sortIndex"`
	Content   struct {
		EntryType   string `json:"entryType"`
		ItemContent struct {
			ItemType     string `json:"itemType"`
			TweetResults struct {
				Result result `json:"result"`
			} `json:"tweet_results"`
		} `json:"itemContent"`
	} `json:"content"`
}

// timeline v2 JSON object
type homeTimeline struct {
	Data struct {
		Home struct {
			HomeTimeline struct {
				Instructions []struct {
					Entries []homeEntry `json:"entries"`
					Type    string      `json:"type"`
				} `json:"instructions"`
				Metadata struct {
					SribeConfig []struct {
						Page string `json:"page"`
					} `json:"scribe_config"`
				} `json:"metadata"`
			} `json:"home_timeline_urt"`
		} `json:"home"`
	} `json:"data"`
}

func (timeline *homeTimeline) parseTweets() ([]*Tweet, string) {
	var cursor string
	var tweets []*Tweet
	for _, instruction := range timeline.Data.Home.HomeTimeline.Instructions {
		for _, entry := range instruction.Entries {
			if entry.Content.ItemContent.TweetResults.Result.Typename == "Tweet" {
				if tweet := entry.Content.ItemContent.TweetResults.Result.parse(); tweet != nil {
					tweets = append(tweets, tweet)
				}
			}
		}
	}
	return tweets, cursor
}

// GetHomeTweets returns channel with tweets from home timeline
func (s *Scraper) GetHomeTweets(ctx context.Context, maxTweetsNbr int) <-chan *TweetResult {
	return getTweetTimeline(ctx, "", maxTweetsNbr, s.FetchHomeTweets)
}

// FetchHomeTweets gets tweets from home timline, via the Twitter frontend API.
func (s *Scraper) FetchHomeTweets(_ string, maxTweetsNbr int, cursor string) ([]*Tweet, string, error) {
	if maxTweetsNbr > 200 {
		maxTweetsNbr = 200
	}

	req, err := s.newRequest("POST", "https://twitter.com/i/api/graphql/MquF6747JmE_NQYdkIH0OQ/HomeLatestTimeline")
	if err != nil {
		return nil, "", err
	}

	variables := map[string]interface{}{
		"count":                                  maxTweetsNbr,
		"includePromotedContent":                 true,
		"withQuickPromoteEligibilityTweetFields": true,
		"requestContext":                         "launch",
	}
	features := map[string]interface{}{
		"rweb_tipjar_consumption_enabled":                                         false,
		"responsive_web_graphql_exclude_directive_enabled":                        true,
		"verified_phone_label_enabled":                                            false,
		"creator_subscriptions_tweet_preview_api_enabled":                         true,
		"responsive_web_graphql_timeline_navigation_enabled":                      true,
		"responsive_web_graphql_skip_user_profile_image_extensions_enabled":       false,
		"communities_web_enable_tweet_community_results_fetch":                    true,
		"c9s_tweet_anatomy_moderator_badge_enabled":                               true,
		"tweetypie_unmention_optimization_enabled":                                true,
		"responsive_web_edit_tweet_api_enabled":                                   true,
		"graphql_is_translatable_rweb_tweet_is_translatable_enabled":              true,
		"view_counts_everywhere_api_enabled":                                      true,
		"longform_notetweets_consumption_enabled":                                 true,
		"responsive_web_twitter_article_tweet_consumption_enabled":                true,
		"tweet_awards_web_tipping_enabled":                                        false,
		"freedom_of_speech_not_reach_fetch_enabled":                               true,
		"standardized_nudges_misinfo":                                             true,
		"tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled": true,
		"rweb_video_timestamps_enabled":                                           true,
		"longform_notetweets_rich_text_read_enabled":                              true,
		"longform_notetweets_inline_media_enabled":                                true,
		"responsive_web_enhance_cards_enabled":                                    false,
	}

	req.Header.Set("content-type", "application/json")
	body := map[string]interface{}{
		"variables": variables,
		"features":  features,
		"queryId":   "CTOVqej0JBXAZSwkp1US0g",
	}

	b, _ := json.Marshal(body)
	req.Body = io.NopCloser(bytes.NewReader(b))

	var timeline homeTimeline
	err = s.RequestAPI(req, &timeline)
	if err != nil {
		return nil, "", err
	}

	tweets, nextCursor := timeline.parseTweets()
	return tweets, nextCursor, nil
}
