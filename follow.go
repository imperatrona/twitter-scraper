package twitterscraper

import (
	"net/url"
)

// FetchFollowingByUserID gets following profiles list for a given userID, via the Twitter frontend GraphQL API.
func (s *Scraper) FetchFollowingByUserID(userID string, maxFollowingNbr int, cursor string) ([]*Profile, string, error) {
	if maxFollowingNbr > 200 {
		maxFollowingNbr = 200
	}

	req, err := s.newRequest("GET", "https://twitter.com/i/api/graphql/oUxds-Fprv5NKsH67zPt5w/Following")
	if err != nil {
		return nil, "", err
	}

	variables := map[string]interface{}{
		"userId":                 userID,
		"count":                  maxFollowingNbr,
		"includePromotedContent": false,
	}
	features := map[string]interface{}{
		"responsive_web_graphql_exclude_directive_enabled":                        true,
		"verified_phone_label_enabled":                                            false,
		"creator_subscriptions_tweet_preview_api_enabled":                         true,
		"responsive_web_graphql_timeline_navigation_enabled":                      true,
		"responsive_web_graphql_skip_user_profile_image_extensions_enabled":       false,
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
		"responsive_web_media_download_video_enabled":                             false,
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

	users, nextCursor := timeline.parseUsers()
	return users, nextCursor, nil
}
