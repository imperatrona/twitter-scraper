package twitterscraper

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strconv"
	"strings"
)

type TweetReply struct {
	ReplyToTweetId string 
	ExcludeReplyUserIds []string
}

type NewTweet struct {
	Text   string
	Medias []*Media
	Reply *TweetReply
}

type newTweet struct {
	Data struct {
		CreateTweet struct {
			TweetResults struct {
				Result tweet `json:"result"`
			} `json:"tweet_results"`
		} `json:"create_tweet"`
	} `json:"data"`
}

func (newTweet *newTweet) parse() *Tweet {
	var tweet = &newTweet.Data.CreateTweet.TweetResults.Result

	if tweet.NoteTweet.NoteTweetResults.Result.Text != "" {
		tweet.Legacy.FullText = tweet.NoteTweet.NoteTweetResults.Result.Text
	}
	var legacy *legacyTweet = &tweet.Legacy
	var user *legacyUser = &tweet.Core.UserResults.Result.Legacy
	tw := parseLegacyTweet(user, legacy)
	if tw == nil {
		return nil
	}
	if tw.Views == 0 && tweet.Views.Count != "" {
		tw.Views, _ = strconv.Atoi(tweet.Views.Count)
	}
	if tweet.QuotedStatusResult.Result != nil {
		tw.QuotedStatus = tweet.QuotedStatusResult.Result.parse()
	}
	return tw
}

func (s *Scraper) CreateTweet(tweet NewTweet) (*Tweet, error) {
	req, err := s.newRequest("POST", "https://twitter.com/i/api/graphql/oB-5XsHNAbjvARJEc8CZFw/CreateTweet")
	if err != nil {
		return nil, err
	}

	req.Header.Set("content-type", "application/json")

	media_entities := []map[string]interface{}{}

	if len(tweet.Medias) > 0 {
		for _, media := range tweet.Medias {
			media_entities = append(media_entities, map[string]interface{}{
				"media_id":     strconv.Itoa(media.ID),
				"tagged_users": []string{},
			})
		}
	}

	post_medias := map[string]interface{}{
		"media_entities":     media_entities,
		"possibly_sensitive": false,
	}

	variables := map[string]interface{}{
		"dark_request":            false,
		"media":                   post_medias,
		"semantic_annotation_ids": []string{},
		"tweet_text":              tweet.Text,
	}

	// If reply is set 
	if tweet.Reply != nil {
		reply := map[string]interface{}{}

		if tweet.Reply.ReplyToTweetId != "" {
			reply["in_reply_to_tweet_id"] = tweet.Reply.ReplyToTweetId
			reply["exclude_reply_user_ids"] = []string{}
		}

		if len(tweet.Reply.ExcludeReplyUserIds) > 0 {
			reply["exclude_reply_user_ids"] = tweet.Reply.ExcludeReplyUserIds
		}

		if len(reply) > 0 {
			variables["reply"] = reply
		}
	}

	features := map[string]interface{}{
		"communities_web_enable_tweet_community_results_fetch":                    true,
		"c9s_tweet_anatomy_moderator_badge_enabled":                               true,
		"tweetypie_unmention_optimization_enabled":                                true,
		"responsive_web_edit_tweet_api_enabled":                                   true,
		"graphql_is_translatable_rweb_tweet_is_translatable_enabled":              true,
		"view_counts_everywhere_api_enabled":                                      true,
		"longform_notetweets_consumption_enabled":                                 true,
		"responsive_web_twitter_article_tweet_consumption_enabled":                true,
		"tweet_awards_web_tipping_enabled":                                        false,
		"creator_subscriptions_quote_tweet_preview_enabled":                       false,
		"longform_notetweets_rich_text_read_enabled":                              true,
		"longform_notetweets_inline_media_enabled":                                true,
		"articles_preview_enabled":                                                true,
		"rweb_video_timestamps_enabled":                                           true,
		"rweb_tipjar_consumption_enabled":                                         true,
		"responsive_web_graphql_exclude_directive_enabled":                        true,
		"verified_phone_label_enabled":                                            false,
		"freedom_of_speech_not_reach_fetch_enabled":                               true,
		"standardized_nudges_misinfo":                                             true,
		"tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled": true,
		"responsive_web_graphql_skip_user_profile_image_extensions_enabled":       false,
		"responsive_web_graphql_timeline_navigation_enabled":                      true,
		"responsive_web_enhance_cards_enabled":                                    false,
	}

	body := map[string]interface{}{
		"features":  features,
		"variables": variables,
		"queryId":   "oB-5XsHNAbjvARJEc8CZFw",
	}

	b, _ := json.Marshal(body)
	req.Body = io.NopCloser(bytes.NewReader(b))

	var response newTweet
	err = s.RequestAPI(req, &response)
	if err != nil {
		return nil, err
	}

	if result := response.parse(); result != nil {
		return result, nil
	}

	return nil, errors.New("tweet wasn't post")
}

func (s *Scraper) DeleteTweet(tweetId string) error {
	req, err := s.newRequest("POST", "https://twitter.com/i/api/graphql/VaenaVgh5q5ih7kvyVjgtg/DeleteTweet")
	if err != nil {
		return err
	}

	req.Header.Set("content-type", "application/json")
	variables := map[string]interface{}{
		"dark_request": false,
		"tweet_id":     tweetId,
	}

	body := map[string]interface{}{
		"variables": variables,
		"queryId":   "VaenaVgh5q5ih7kvyVjgtg",
	}

	b, _ := json.Marshal(body)
	req.Body = io.NopCloser(bytes.NewReader(b))

	var response struct {
		Data struct {
			CreateTweet struct {
				TweetResults struct {
				} `json:"tweet_results"`
			} `json:"delete_tweet"`
		} `json:"data"`
	}

	err = s.RequestAPI(req, &response)
	if err != nil {
		return err
	}

	return nil
}

func (s *Scraper) CreateRetweet(tweetId string) (string, error) {
	req, err := s.newRequest("POST", "https://twitter.com/i/api/graphql/ojPdsZsimiJrUGLR1sjUtA/CreateRetweet")
	if err != nil {
		return "", err
	}

	req.Header.Set("content-type", "application/json")
	variables := map[string]interface{}{
		"dark_request": false,
		"tweet_id":     tweetId,
	}

	body := map[string]interface{}{
		"variables": variables,
		"queryId":   "ojPdsZsimiJrUGLR1sjUtA",
	}

	b, _ := json.Marshal(body)
	req.Body = io.NopCloser(bytes.NewReader(b))

	var response struct {
		Data struct {
			CreateRetweet struct {
				RetweetResults struct {
					Result struct {
						RestID string `json:"rest_id"`
						Legacy struct {
							FullText string `json:"full_text"`
						} `json:"legacy"`
					} `json:"result"`
				} `json:"retweet_results"`
			} `json:"create_retweet"`
		} `json:"data"`
	}

	err = s.RequestAPI(req, &response)
	if err != nil {
		return "", err
	}

	if response.Data.CreateRetweet.RetweetResults.Result.RestID != "" {
		return response.Data.CreateRetweet.RetweetResults.Result.RestID, nil
	}

	return "", errors.New("tweet wasn't retweeted")
}

// Retweeted tweets has their own id, but to delete retweet twitter using id of source tweet
func (s *Scraper) DeleteRetweet(tweetId string) error {
	req, err := s.newRequest("POST", "https://twitter.com/i/api/graphql/iQtK4dl5hBmXewYZuEOKVw/DeleteRetweet")
	if err != nil {
		return err
	}

	req.Header.Set("content-type", "application/json")
	variables := map[string]interface{}{
		"dark_request":    false,
		"source_tweet_id": tweetId,
	}
	body := map[string]interface{}{
		"variables": variables,
		"queryId":   "iQtK4dl5hBmXewYZuEOKVw",
	}

	b, _ := json.Marshal(body)
	req.Body = io.NopCloser(bytes.NewReader(b))

	var response struct {
		Data struct {
			Unretweet struct {
				SourceTweetResults struct {
					Result struct {
						RestID string `json:"rest_id"`
						Legacy struct {
							FullText string `json:"full_text"`
						} `json:"legacy"`
					} `json:"result"`
				} `json:"source_tweet_results"`
			} `json:"unretweet"`
		} `json:"data"`
	}

	err = s.RequestAPI(req, &response)
	if err != nil {
		return err
	}

	return nil
}

func (s *Scraper) LikeTweet(tweetId string) error {
	req, err := s.newRequest("POST", "https://twitter.com/i/api/graphql/lI07N6Otwv1PhnEgXILM7A/FavoriteTweet")
	if err != nil {
		return err
	}

	req.Header.Set("content-type", "application/json")
	variables := map[string]interface{}{
		"tweet_id": tweetId,
	}
	body := map[string]interface{}{
		"variables": variables,
		"queryId":   "lI07N6Otwv1PhnEgXILM7A",
	}

	b, _ := json.Marshal(body)
	req.Body = io.NopCloser(bytes.NewReader(b))

	var response struct {
		Data struct {
			FavoriteTweet string `json:"favorite_tweet"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
			Code    int    `json:"code"`
		} `json:"errors"`
	}

	err = s.RequestAPI(req, &response)
	if err != nil {
		return err
	}

	if len(response.Errors) > 0 && response.Errors[0].Code == 139 {
		return errors.New("tweet already liked")
	}

	if response.Data.FavoriteTweet != "Done" {
		return errors.New("unknown error")
	}

	return nil
}

func (s *Scraper) UnlikeTweet(tweetId string) error {
	req, err := s.newRequest("POST", "https://twitter.com/i/api/graphql/ZYKSe-w7KEslx3JhSIk5LA/UnfavoriteTweet")
	if err != nil {
		return err
	}

	req.Header.Set("content-type", "application/json")
	variables := map[string]interface{}{
		"tweet_id": tweetId,
	}
	body := map[string]interface{}{
		"variables": variables,
		"queryId":   "ZYKSe-w7KEslx3JhSIk5LA",
	}

	b, _ := json.Marshal(body)
	req.Body = io.NopCloser(bytes.NewReader(b))

	var response struct {
		Data struct {
			UnfavoriteTweet string `json:"unfavorite_tweet"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
			Code    int    `json:"code"`
		} `json:"errors"`
	}

	err = s.RequestAPI(req, &response)
	if err != nil {
		return err
	}

	if len(response.Errors) > 0 && response.Errors[0].Code == 144 {
		return errors.New("tweet already not liked")
	}

	if response.Data.UnfavoriteTweet != "Done" {
		return errors.New("unknown error")
	}

	return nil
}
func (s *Scraper) GetTweetRetweeters(tweetId string, maxUsersNbr int, cursor string) ([]*Profile, string, error) {
	if maxUsersNbr > 200 {
		maxUsersNbr = 200
	}

	req, err := s.newRequest("GET", "https://twitter.com/i/api/graphql/8019obfgnveiPiJuS2Rtow/Retweeters")
	if err != nil {
		return nil, "", err
	}

	variables := map[string]interface{}{
		"tweetId":                tweetId,
		"includePromotedContent": false,
		"count":                  maxUsersNbr,
	}

	features := map[string]interface{}{
		"rweb_tipjar_consumption_enabled":                                         true,
		"responsive_web_graphql_exclude_directive_enabled":                        true,
		"verified_phone_label_enabled":                                            false,
		"creator_subscriptions_tweet_preview_api_enabled":                         true,
		"responsive_web_graphql_timeline_navigation_enabled":                      true,
		"responsive_web_graphql_skip_user_profile_image_extensions_enabled":       false,
		"communities_web_enable_tweet_community_results_fetch":                    true,
		"c9s_tweet_anatomy_moderator_badge_enabled":                               true,
		"articles_preview_enabled":                                                true,
		"responsive_web_edit_tweet_api_enabled":                                   true,
		"graphql_is_translatable_rweb_tweet_is_translatable_enabled":              true,
		"view_counts_everywhere_api_enabled":                                      true,
		"longform_notetweets_consumption_enabled":                                 true,
		"responsive_web_twitter_article_tweet_consumption_enabled":                true,
		"tweet_awards_web_tipping_enabled":                                        false,
		"creator_subscriptions_quote_tweet_preview_enabled":                       false,
		"freedom_of_speech_not_reach_fetch_enabled":                               true,
		"standardized_nudges_misinfo":                                             true,
		"tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled": true,
		"rweb_video_timestamps_enabled":                                           true,
		"longform_notetweets_rich_text_read_enabled":                              true,
		"longform_notetweets_inline_media_enabled":                                true,
		"responsive_web_enhance_cards_enabled":                                    false,
	}

	if cursor != "" {
		variables["cursor"] = cursor
	}

	query := url.Values{}
	query.Set("variables", mapToJSONString(variables))
	query.Set("features", mapToJSONString(features))
	req.URL.RawQuery = query.Encode()

	var timeline retweetersTimelineV2
	err = s.RequestAPI(req, &timeline)
	if err != nil {
		return nil, "", err
	}

	users, nextCursor := timeline.parseUsers()

	if strings.HasPrefix(nextCursor, "0|") {
		nextCursor = ""
	}

	return users, nextCursor, nil
}
