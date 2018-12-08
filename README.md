# cookies

[![Build Status](https://img.shields.io/travis/vicanso/cookies.svg?label=linux+build)](https://travis-ci.org/vicanso/cookies)

Signed and unsigned cookies based on Keygrip. It derives from [pillarjs/cookies](https://github.com/pillarjs/cookies).

## API

#### New(rw ReadWriter, opts *Options)


- `rw` ReadWriter for get and set cookie
- `opts.Keys` key list for keygrip
- `opts.Path` the same as `http.Cookie.Path`
- `opts.Domain` the same as `http.Cookie.Domain`
- `opts.Expires` the same as `http.Cookie.Expires`
- `opts.MaxAge` the same as `http.Cookie.MaxAge`
- `opts.Secure` the same as `http.Cookie.Secure`
- `opts.HttpOnly` the same as `http.Cookie.HttpOnly`

It will create a cookie instance. The options will use for http.Cookie except `Options.Keys`.

```go
c := cookies.New(nil, &cookie.Options{
  Keys: []string{
    "A",
  },
  Domain: "aslant.site",
  MaxAge: 3600,
})
```

#### CreateCookie(name, value string)

Creeat a http cookie by the opts

```go
c := cookies.New(nil, nil, &cookie.Options{
  Keys: []string{
    "A",
  },
  Domain: "aslant.site",
  MaxAge: 3600,
})
cookie := c.CreateCookie("jt", "random-string")
```

### Get(name string, signed bool)

Get the cookie value, if signed is true, it will verify use `keys`.

```go
c := New(nil, opts)
cookieName := "jt"
cookieValue := "myCookie"
jt := c.CreateCookie(cookieName, cookieValue)
r := httptest.NewRequest(http.MethodGet, "http://aslant.site/api/users/me", nil)
r.AddCookie(jt)
w := httptest.NewRecorder()

c.RW = NewHTTPReadWriter(r, w)

// "" there is not sig cookie exists
fmt.Println(c.Get(cookieName, true))
```

#### Set(cookie *http.Cookie, signed bool)

Set the cookie, the signed is `true`, it will set a sig cookie too.

```go
r := httptest.NewRequest(http.MethodGet, "http://aslant.site/api/users/me", nil)
w := httptest.NewRecorder()
rw := NewHTTPReadWriter(r, w)
c := New(rw, opts)
cookieName := "jt"
cookieValue := "myCookie"
jt := c.CreateCookie(cookieName, cookieValue)
c.Set(jt, true)
```

## test

go test -race -coverprofile=test.out ./... && go tool cover --html=test.out
