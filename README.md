# Twitter Scraper

[![Go Reference](https://pkg.go.dev/badge/github.com/mistadikay/twitter-scraper.svg)](https://pkg.go.dev/github.com/mistadikay/twitter-scraper) [![Go](https://github.com/mistadikay/twitter-scraper/actions/workflows/go.yml/badge.svg?branch=master)](https://github.com/mistadikay/twitter-scraper/actions/workflows/go.yml)

Twitter’s API is pricey and has lots of limitations. But their frontend has its own API, which was reverse-engineered by [@n0madic](https://github.com/n0madic) and maintained by [@imperatrona](https://github.com/imperatrona). Some endpoints require authentication, but it is easy to scale by buying new accounts and proxies.

You can use this library to get tweets, profiles, and trends trivially.

<details>
<summary><h2>Table of Contents</h2></summary>

- [Installation](#installation)
- [Quick start](#quick-start)
- [Rate limits](#rate-limits)
- [Methods that returns channels](#methods-that-returns-channels)
- [Authentication](#authentication)
  - [Using cookies](#using-cookies)
  - [Using AuthToken](#using-authtoken)
  - [OpenAccount](#openaccount)
  - [Login & Password](#login--password)
  - [Check if login](#check-if-login)
  - [Log out](#log-out)
- [Methods](#methods)
  - [Get tweet](#get-tweet)
  - [Get tweet replies](#get-tweet-replies)
  - [Get tweet retweeters](#get-tweet-retweeters)
  - [Get user tweets](#get-user-tweets)
  - [Get user medias](#get-user-medias)
  - [Get bookmarks](#get-bookmarks)
  - [Get home tweets](#get-home-tweets)
  - [Get foryou tweets](#get-foryou-tweets)
  - [Search tweets](#search-tweets)
  - [Search params](#search-params)
  - [Get profile](#get-profile)
  - [Search profile](#search-profile)
  - [Get trends](#get-trends)
  - [Get following](#get-following)
  - [Get followers](#get-followers)
  - [Get space](#get-space)
  - [Like tweet](#like-tweet)
  - [Unlike tweet](#unlike-tweet)
  - [Create tweet](#create-tweet)
  - [Delete tweet](#delete-tweet)
  - [Create retweet](#create-retweet)
  - [Delete retweet](#delete-retweet)
  - [Get scheduled tweets](#get-scheduled-tweets)
  - [Create scheduled tweet](#create-scheduled-tweet)
  - [Delete scheduled tweet](#delete-scheduled-tweet)
  - [Upload media](#upload-media)
- [Connection](#connection)
  - [Proxy](#proxy)
  - [HTTP(s)](#https)
  - [SOCKS5](#socks5)
  - [Delay](#delay)
  - [Load timeline with tweet replies](#load-timeline-with-tweet-replies)
- [Contributing](#contributing)
  - [Testing](#testing)

</details>

## Installation

```shell
go get -u github.com/mistadikay/twitter-scraper
```

## Quick start

```golang
package main

import (
    "context"
    "fmt"
    twitterscraper "github.com/mistadikay/twitter-scraper"
)

func main() {
    scraper := twitterscraper.New()
    scraper.SetAuthToken(twitterscraper.AuthToken{Token: "auth_token", CSRFToken: "ct0"})

    // After setting Cookies or AuthToken you have to execute IsLoggedIn method.
    // Without it, scraper wouldn't be able to make requests that requires authentication
    if !scraper.IsLoggedIn() {
      panic("Invalid AuthToken")
    }

    for tweet := range scraper.GetTweets(context.Background(), "x", 50) {
        if tweet.Error != nil {
            panic(tweet.Error)
        }
        fmt.Println(tweet.Text)
    }
}
```

## Rate limits

Api has a global limit on how many requests per second are allowed, don’t make requests more than once per 1.5 seconds from one account. Also each endpoint has its own limits, most of them are 150 requests per 15 minutes.

Apparently twitter doesn’t limit the number of accounts that can be used per one IP address. This could change at any time. As of February 2024, I have been managing 20 accounts per IP address without receiving a ban for several months.

OpenAccount was great in the past, but now it’s nerfed by twitter. They allow 180 requests instead of 150, but you can only create one account per month with one IP address. If you use OpenAccount you should save your credentials and use them later with `WithOpenAccount` method.

## Methods that returns channels

Some methods returns channels. They created to rid you from dealing with `cursor`, but under the hood they still using the same endpoints as they `Fetch` counterparts, they have the same rate limits. For example `GetTweets` using `FetchTweets` to get tweets. `FetchTweets` returns up to 20 tweets, so if you set `GetTweets` to fetch 150 tweets it will make 8 requests to `FetchTweets` (150/20=7.5 ~ 8 requests).
If under-hood `Fetch` method got the error, it will be passed to object `twitterscraper.TweetResult` and will stop further scraping. In methods that return `twitterscraper.TweetResult` you should check if `tweet.Error` is not `nil` before accessing the tweet content.

## Authentication

Most endpoints require authentication. The preferable way is to use SetCookies. You can also use `SetAuthToken` but `POST` endpoints will not work. Login with password may require confirmation with email and is often the reason of accounts ban.

Endpoints that work without authentication will not return sensitive content. To get sensitive content you need to authenticate with any available method including `OpenAccount`.

### Using cookies

```golang
// Deserialize from JSON
var cookies []*http.Cookie
f, _ := os.Open("cookies.json")
json.NewDecoder(f).Decode(&cookies)

scraper.SetCookies(cookies)
if !scraper.IsLoggedIn() {
    panic("Invalid cookies")
}
```

To save cookies from an authorized client to a file, use `GetCookies`:

```golang
cookies := scraper.GetCookies()

data, _ := json.Marshal(cookies)
f, _ = os.Create("cookies.json")
f.Write(data)
```

### Using AuthToken

`SetAuthToken` method simply set required cookies `auth_token` and `ct0`.

```golang
scraper.SetAuthToken(twitterscraper.AuthToken{Token: "auth_token", CSRFToken: "ct0"})
if !scraper.IsLoggedIn() {
    panic("Invalid AuthToken")
}
```

### OpenAccount

> [!WARNING]  
> Deprecated. Nerfed by twitter, doesn't support new endpoints.

`LoginOpenAccount` is now limited to one new account per month for IP address.

```golang
account, err := scraper.LoginOpenAccount()
```

You should save `OpenAccount` returned by `LoginOpenAccount` to reuse it later.

```golang
scraper.WithOpenAccount(twitterscraper.OpenAccount{
    OAuthToken: "TOKEN",
    OAuthTokenSecret: "TOKEN_SECRET",
})
```

### Login & Password

To log in, you have to use your username, not the email!

```golang
err := scraper.Login("username", "password")
```

If you have email confirmation, use your email address in addition:

```golang
err := scraper.Login("username", "password", "email")
```

If you have two-factor authentication, use the code:

```golang
err := scraper.Login("username", "password", "code")
```

### Check if login

Status of login can be checked with method `IsLoggedIn`:

```golang
scraper.IsLoggedIn()
```

### Log out

```golang
scraper.Logout()
```

## Methods

### Get tweet

150 requests / 15 minutes

`TweetDetail` endpoint requires auth, so `TweetResultByRestId` endpoint used instead when auth not provided. Which doesn't return `InReplyToStatus` and `Thread` tweets.

```golang
tweet, err := scraper.GetTweet("1328684389388185600")
```

### Get tweet replies

150 requests / 15 minutes

Returns by ~5-10 tweets and multiple cursors – one for each thread.

```golang
var cursor string
tweets, cursors, err := scraper.GetTweetReplies("1328684389388185600", cursor)
```

To get all replies and replies of replies for tweet you can iterate for all cursors. To get only direct replies check if `cursor.ThreadID` is equal your tweet id.

```golang
tweets, cursors, err := scraper.GetTweetReplies("1328684389388185600", "")
if err != nil {
    panic(err)
}

for {
    if len(cursors) > 0 {
        var cursor *twitterscraper.ThreadCursor
        cursor, cursors = cursors[0], cursors[1:]
        moreTweets, moreCursors, err := scraper.GetTweetReplies(tweetId, cursor.Cursor)
        if err != nil {
            // you can check here if rate limited, await and repeat request
            panic(err)
        }
        tweets = append(tweets, moreTweets...)
        if len(moreCursors) > 0 {
            cursors = append(cursors, moreCursors...)
        }
    } else {
        break
    }
}
```

### Get tweet retweeters

500 requests / 15 minutes

Returns a list of users who have retweeted the tweet.

```golang
var cursor string
retweeters, cursor, err := scraper.GetTweetRetweeters("1328684389388185600", 20, cursor)
```

### Get user tweets

150 requests / 15 minutes

`GetTweets` returns a channel with the specified number of user tweets. It’s using the `FetchTweets` method under the hood. Read how this method works in [Methods that returns channels](#methods-that-returns-channels).

```golang
for tweet := range scraper.GetTweets(context.Background(), "taylorswift13", 50) {
    if tweet.Error != nil {
        panic(tweet.Error)
    }
    fmt.Println(tweet.Text)
}
```

FetchTweets returns tweets and cursor for fetching the next page. Each request returns up to 20 tweets.

```golang
var cursor string
tweets, cursor, err := scraper.FetchTweets("taylorswift13", 20, cursor)
```

### Get user medias

500 requests / 15 minutes

`GetMediaTweets` returns a channel with the specified number of user tweets that contain media. It’s using the `FetchMediaTweets` method under the hood. Read how this method works in [Methods that returns channels](#methods-that-returns-channels).

```golang
for tweet := range scraper.GetMediaTweets(context.Background(), "taylorswift13", 50) {
    if tweet.Error != nil {
        panic(tweet.Error)
    }
    fmt.Println(tweet.Text)
}
```

`FetchMediaTweets` returns tweets and cursor for fetching the next page. Each request returns up to 20 tweets.

```golang
var cursor string
tweets, cursor, err := scraper.FetchMediaTweets("taylorswift13", 20, cursor)
```

### Get bookmarks

> [!IMPORTANT]  
> Requires authentication!

500 requests / 15 minutes

`GetBookmarks` returns a channel with the specified number of bookmarked tweets. It’s using the `FetchBookmarks` method under the hood. Read how this method works in [Methods that returns channels](#methods-that-returns-channels).

```golang
for tweet := range scraper.GetBookmarks(context.Background(), 50) {
    if tweet.Error != nil {
        panic(tweet.Error)
    }
    fmt.Println(tweet.Text)
}
```

`FetchBookmarks` returns bookmarked tweets and cursor for fetching the next page. Each request returns up to 20 tweets.

```golang
var cursor string
tweets, cursor, err := scraper.FetchBookmarks(20, cursor)
```

### Get home tweets

> [!IMPORTANT]  
> Requires authentication!

500 requests / 15 minutes

`GetHomeTweets` returns a channel with the specified number of latest home tweets. It’s using the `FetchHomeTweets` method under the hood. Read how this method works in [Methods that returns channels](#methods-that-returns-channels).

```golang
for tweet := range scraper.GetHomeTweets(context.Background(), 50) {
    if tweet.Error != nil {
        panic(tweet.Error)
    }
    fmt.Println(tweet.Text)
}
```

`FetchHomeTweets` returns latest home tweets and cursor for fetching the next page. Each request returns up to 20 tweets.

```golang
var cursor string
tweets, cursor, err := scraper.FetchHomeTweets(20, cursor)
```

### Get foryou tweets

> [!IMPORTANT]  
> Requires authentication!

500 requests / 15 minutes

`GetForYouTweets` returns a channel with the specified number of for you home tweets. It’s using the `FetchForYouTweets` method under the hood. Read how this method works in [Methods that returns channels](#methods-that-returns-channels).

```golang
for tweet := range scraper.GetForYouTweets(context.Background(), 50) {
    if tweet.Error != nil {
        panic(tweet.Error)
    }
    fmt.Println(tweet.Text)
}
```

`FetchForYouTweets` returns for you home tweets and cursor for fetching the next page. Each request returns up to 20 tweets.

```golang
var cursor string
tweets, cursor, err := scraper.FetchForYouTweets(20, cursor)
```

### Search tweets

> [!IMPORTANT]  
> Requires authentication!

150 requests / 15 minutes

`SearchTweets` returns a channel with the specified number of tweets that contain media. It’s using the `FetchSearchTweets` method under the hood. Read how this method works in [Methods that returns channels](#methods-that-returns-channels).

```golang
for tweet := range scraper.SearchTweets(context.Background(),
    "twitter scraper data -filter:retweets", 50) {
    if tweet.Error != nil {
        panic(tweet.Error)
    }
    fmt.Println(tweet.Text)
}
```

`FetchSearchTweets` returns tweets and cursor for fetching the next page. Each request returns up to 20 tweets.

```golang
tweets, cursor, err := scraper.FetchSearchTweets("taylorswift13", 20, cursor)
```

By default, search returns top tweets. You can change it by specifying the search mode before making requests. Supported modes are `SearchTop`, `SearchLatest`, `SearchPhotos`, `SearchVideos`, and `SearchUsers`.

```golang
scraper.SetSearchMode(twitterscraper.SearchLatest)
```

#### Search params

See [Rules and filtering](https://developer.twitter.com/en/docs/tweets/rules-and-filtering/overview/standard-operators) for build standard queries.

### Get profile

95 requests / 15 minutes

```golang
profile, err := scraper.GetProfile("taylorswift13")
```

### Search profile

> [!IMPORTANT]  
> Requires authentication!

150 requests / 15 minutes

`SearchProfiles` returns a channel with the specified number of tweets that contain media. It’s using the `FetchSearchProfiles` method under the hood. Read how this method works in [Methods that returns channels](#methods-that-returns-channels).

```golang
for profile := range scraper.SearchProfiles(context.Background(), "Twitter", 50) {
    if profile.Error != nil {
        panic(profile.Error)
    }
    fmt.Println(profile.Name)
}
```

`FetchSearchProfiles` returns profiles and cursor for fetching the next page. Each request returns up to 20 tweets.

```golang
profiles, cursor, err := scraper.FetchSearchProfiles("taylorswift13", 20, cursor)
```

### Get trends

```golang
trends, err := scraper.GetTrends()
```

### Get following

> [!IMPORTANT]  
> Requires authentication!

500 requests / 15 minutes

```golang
var cursor string
users, cursor, err := scraper.FetchFollowing("Support", 20, cursor)
```

### Get followers

> [!IMPORTANT]  
> Requires authentication!

50 requests / 15 minutes

```golang
var cursor string
users, cursor, err := scraper.FetchFollowers("Support", 20, cursor)
```

### Get space

> [!IMPORTANT]  
> Requires authentication!

500 requests / 15 minutes

Use to retrvie data about space and it's participants. You can get up to 1000 participants of space. If method returns less, it's probably because listeners is anonymous.

```golang
space, err := scraper.GetSpace("space_id")
```

You can get `space_id` from space url which can be retrived from tweet. For example:

```golang
tweet, err := testScraper.GetTweet("1815884577040445599")
if err != nil {
    t.Fatal(err)
}

var spaceId string
spaceUrl := tweet.URLs[0] // https://twitter.com/i/spaces/1mnxeAMPEqqxX

if strings.HasPrefix(spaceUrl, "https://twitter.com/i/spaces/") {
    spaceId = strings.Replace(spaceUrl, "https://twitter.com/i/spaces/", "", 1) // 1mnxeAMPEqqxX
}

space, err := scraper.GetSpace(spaceId)
```

### Like tweet

> [!IMPORTANT]  
> Requires authentication!

500 requests / 15 minutes (combined with `UnlikeTweet` method)

```golang
err := scraper.LikeTweet("tweet_id")
```

### Unlike tweet

> [!IMPORTANT]  
> Requires authentication!

500 requests / 15 minutes (combined with `LikeTweet` method)

```golang
err := scraper.UnlikeTweet("tweet_id")
```

### Create tweet

> [!IMPORTANT]  
> Requires authentication!

```golang
tweet, err = scraper.CreateTweet(twitterscraper.NewTweet{
    Text:   "new tweet text",
    Medias: nil,
})
```

To create tweet with medias, you need to upload media first. Up to 4 medias; jpg, mp4 and gif allowed.

```golang
var media *twitterscraper.Media
media, err = testScraper.UploadMedia("./photo.jpg")
if err != nil {
    t.Error(err)
}
tweet, err = scraper.CreateTweet(twitterscraper.NewTweet{
    Text:   "new tweet text",
    Medias: []*twitterscraper.Media{
        media,
    },
})
```

### Delete tweet

> [!IMPORTANT]  
> Requires authentication!

```golang
err := testScraper.DeleteTweet("1810458885008105870");
```

### Create retweet

> [!IMPORTANT]  
> Requires authentication!

Returns retweet id, which is not the same as source tweet id.

```golang
retweetId, err := testScraper.CreateRetweet("1792634158977568997");
```

### Delete retweet

> [!IMPORTANT]  
> Requires authentication!

To delete retweet use source tweet id instead retweet id.

```golang
err := testScraper.DeleteRetweet("1792634158977568997");
```

### Get scheduled tweets

> [!IMPORTANT]  
> Requires authentication!

500 requests / 15 minutes

```golang
tweets, err := scraper.FetchScheduledTweets()
```

### Create scheduled tweet

> [!IMPORTANT]  
> Requires authentication!

500 requests / 15 minutes

```golang
tweets, err := scraper.CreateScheduledTweet(twitterscraper.TweetSchedule{
    Text:   "New scheduled tweet text",
    Date:   time.Now().Add(time.Hour * 24 * 31),
    Medias: nil,
})
```

### Delete scheduled tweet

> [!IMPORTANT]  
> Requires authentication!

500 requests / 15 minutes

```golang
err := scraper.DeleteScheduledTweet("123")
```

### Upload media

> [!IMPORTANT]  
> Requires authentication!

50 requests / 15 minutes

Uploads photo, video or gif for further posting or scheduling. Expires in 24 hours if not used.

```golang
media, err := scraper.UploadMedia("./files/movie.mp4")
```

## Connection

### Proxy

#### HTTP(s)

```golang
err := scraper.SetProxy("http://localhost:3128")
```

#### SOCKS5

```golang
err := scraper.SetProxy("socks5://localhost:1080")
```

Socks5 proxy support authentication.

```golang
err := scraper.SetProxy("socks5://user:pass@localhost:1080")
```

### Delay

Add delay between API requests (in seconds)

```golang
scraper.WithDelay(5)
```

### Load timeline with tweet replies

```golang
scraper.WithReplies(true)
```

## Contributing

### Testing

To run some tests, you need to set any form of authentication via environment variables. You can see all possible variables in .vscode/settings.json file. You can also set them in the file to use automatically in vscode, just make sure you don’t commit them in your contribution.
