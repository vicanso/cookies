package cookies

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vicanso/keygrip"
)

func TestCookies(t *testing.T) {
	opts := &Options{
		Keys: []string{
			"A",
			"B",
		},
		Path:     "/",
		Domain:   "aslant.site",
		MaxAge:   3600,
		Secure:   true,
		HttpOnly: true,
	}

	t.Run("create cookie", func(t *testing.T) {
		cookies := New(nil, nil, opts)
		cookie := cookies.CreateCookie("jt", "test")
		if cookie.String() != "jt=test; Path=/; Domain=aslant.site; Max-Age=3600; HttpOnly; Secure" {
			t.Fatalf("create cookie fail")
		}
	})

	t.Run("get cookie unsigned", func(t *testing.T) {
		cookies := New(nil, nil, opts)
		cookieName := "jt"
		cookieValue := "myCookie"
		jt := cookies.CreateCookie(cookieName, cookieValue)
		r := httptest.NewRequest(http.MethodGet, "http://aslant.site/api/users/me", nil)
		r.AddCookie(jt)
		w := httptest.NewRecorder()

		cookies.Request = r
		cookies.Response = w

		if cookies.Get(cookieName, false) != cookieValue {
			t.Fatalf("get cookie unsigned fail")
		}
	})

	t.Run("get cookie signed", func(t *testing.T) {
		cookies := New(nil, nil, opts)
		cookieName := "jt"
		cookieValue := "myCookie"
		jt := cookies.CreateCookie(cookieName, cookieValue)
		r := httptest.NewRequest(http.MethodGet, "http://aslant.site/api/users/me", nil)
		r.AddCookie(jt)
		w := httptest.NewRecorder()

		cookies.Request = r
		cookies.Response = w

		if cookies.Get(cookieName, true) != "" {
			t.Fatalf("get signed cookie should return empty without sig")
		}
		kg := keygrip.New(opts.Keys)
		sigCookieName := "jt.sig"
		sigCookieValue := kg.Sign(cookieName + "=" + cookieValue)
		sigCookie := cookies.CreateCookie(sigCookieName, sigCookieValue)
		r.AddCookie(sigCookie)
		if cookies.Get(cookieName, true) != cookieValue {
			t.Fatalf("get cookie signed fail")
		}
	})

	t.Run("get cookie invalid signed", func(t *testing.T) {
		cookies := New(nil, nil, opts)
		cookieName := "jt"
		cookieValue := "myCookie"
		jt := cookies.CreateCookie(cookieName, cookieValue)
		r := httptest.NewRequest(http.MethodGet, "http://aslant.site/api/users/me", nil)
		r.AddCookie(jt)
		w := httptest.NewRecorder()

		cookies.Request = r
		cookies.Response = w

		sigCookieName := "jt.sig"
		sigCookieValue := "ABCD"
		sigCookie := cookies.CreateCookie(sigCookieName, sigCookieValue)
		r.AddCookie(sigCookie)
		if cookies.Get(cookieName, true) != "" {
			t.Fatalf("get cookie invalid signed should be empty")
		}
		if w.Header().Get(setCookie) != "jt.sig=" {
			t.Fatalf("get cookie invalid signed shoule remove the sig cookie")
		}
	})

	t.Run("get signed cookie(not first key)", func(t *testing.T) {
		cookies := New(nil, nil, opts)
		cookieName := "jt"
		cookieValue := "myCookie"
		jt := cookies.CreateCookie(cookieName, cookieValue)
		r := httptest.NewRequest(http.MethodGet, "http://aslant.site/api/users/me", nil)
		r.AddCookie(jt)
		w := httptest.NewRecorder()

		cookies.Request = r
		cookies.Response = w

		if cookies.Get(cookieName, true) != "" {
			t.Fatalf("get signed cookie should return empty without sig")
		}
		kg := keygrip.New([]string{
			opts.Keys[1],
		})
		sigCookieName := "jt.sig"
		sigCookieValue := kg.Sign(cookieName + "=" + cookieValue)
		sigCookie := cookies.CreateCookie(sigCookieName, sigCookieValue)
		r.AddCookie(sigCookie)
		if cookies.Get(cookieName, true) != cookieValue {
			t.Fatalf("get cookie signed fail")
		}
		if w.Header().Get(setCookie) != "jt.sig=kb_bqGBtcVmP5oU8CU7lTqQCRwY; Path=/; Domain=aslant.site; Max-Age=3600; HttpOnly; Secure" {
			t.Fatalf("shoud update the signed cookie when not match first key")
		}
	})

	t.Run("set unsigned cookie", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "http://aslant.site/api/users/me", nil)
		w := httptest.NewRecorder()
		cookies := New(r, w, opts)
		cookieName := "jt"
		cookieValue := "myCookie"
		jt := cookies.CreateCookie(cookieName, cookieValue)
		cookies.Set(jt, false)
		values := w.Header()[setCookie]
		if len(values) != 1 || values[0] != "jt=myCookie; Path=/; Domain=aslant.site; Max-Age=3600; HttpOnly; Secure" {
			t.Fatalf("set unsigned cookie fail")
		}
	})

	t.Run("set signed cookie", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "http://aslant.site/api/users/me", nil)
		w := httptest.NewRecorder()
		cookies := New(r, w, opts)
		cookieName := "jt"
		cookieValue := "myCookie"
		jt := cookies.CreateCookie(cookieName, cookieValue)
		cookies.Set(jt, true)
		values := w.Header()[setCookie]
		str := "jt=myCookie; Path=/; Domain=aslant.site; Max-Age=3600; HttpOnly; Secure,jt.sig=kb_bqGBtcVmP5oU8CU7lTqQCRwY; Path=/; Domain=aslant.site; Max-Age=3600; HttpOnly; Secure"
		if len(values) != 2 || strings.Join(values, ",") != str {
			t.Fatalf("set unsigned cookie fail")
		}
	})
}
