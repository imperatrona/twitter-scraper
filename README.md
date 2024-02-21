# Twitter Scraper

[![Go Reference](https://pkg.go.dev/badge/github.com/imperatrona/twitter-scraper.svg)](https://pkg.go.dev/github.com/imperatrona/twitter-scraper)

Twitter’s API is pricey and has lots of limitations. But their frontend has its own API, which was reverse-engineered by [@n0madic](https://github.com/n0madic) and maintained by [@imperatrona](https://github.com/imperatrona). Some endpoints require authentication, but it is easy to scale by buying new accounts and proxies.

You can use this library to get tweets, profiles, and trends trivially.

<details>
<summary><h2>Table of Contents</h2></summary>

- [Installation](#installation)
- [Quick start](#quick-start)
- [Rate limits](#rate-limits)
- [Authentication](#authentication)
  - [Using cookies](#using-cookies)
  - [Using AuthToken](#using-authtoken)
  - [OpenAccount](#openaccount)
  - [Login & Password](#login--password)
  - [Check if login](#check-if-login)
  - [Log out](#log-out)
- [Methods](#methods)
  - [Get tweet](#get-tweet)
  - [Get user tweets](#get-user-tweets)
  - [Get user medias](#get-user-medias)
  - [Get bookmarks](#get-bookmarks)
  - [Search tweets](#search-tweets)
  - [Search params](#search-params)
  - [Get profile](#get-profile)
  - [Search profile](#search-profile)
  - [Get trends](#get-trends)
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
go get -u github.com/imperatrona/twitter-scraper
```

## Quick start

```golang
package main

import (
    "context"
    "fmt"
    twitterscraper "github.com/imperatrona/twitter-scraper"
)

func main() {
    authToken := "auth_token"
    ct0 := "ct0"

    scraper := twitterscraper.New()
    scraper.SetAuthToken(authToken, ct0)

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

```golang
scraper.SetAuthToken(authToken, ct0)
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

```golang
tweet, err := scraper.GetTweet("1328684389388185600")
```

### Get user tweets

150 requests / 15 minutes

`GetTweets` returns a channel with the specified number of user tweets. It’s using the `FetchTweets` method under the hood.

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

`GetMediaTweets` returns a channel with the specified number of user tweets that contain media. It’s using the `FetchMediaTweets` method under the hood.

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

`GetBookmarks` returns a channel with the specified number of bookmarked tweets. It’s using the `FetchBookmarks` method under the hood.

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

### Search tweets

> [!IMPORTANT]  
> Requires authentication!

150 requests / 15 minutes

`SearchTweets` returns a channel with the specified number of tweets that contain media. It’s using the `FetchSearchTweets` method under the hood.

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

`SearchProfiles` returns a channel with the specified number of tweets that contain media. It’s using the `FetchSearchProfiles` method under the hood.

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
