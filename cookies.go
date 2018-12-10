package cookies

import (
	"net/http"
	"time"

	"github.com/vicanso/keygrip"
)

type (
	// HTTPReadWriter http read writer
	HTTPReadWriter struct {
		req  *http.Request
		resp http.ResponseWriter
	}
	// ReadWriter cookie reader and writer
	ReadWriter interface {
		// Get get the cookie by name
		Cookie(name string) (*http.Cookie, error)
		// SetCookie set the cookie
		SetCookie(cookie *http.Cookie) error
	}
	// Cookies cookies ins
	Cookies struct {
		RW   ReadWriter
		kg   *keygrip.Keygrip
		opts *Options
	}
	// Options init options
	Options struct {
		Keys     []string
		Path     string
		Domain   string
		Expires  time.Time
		MaxAge   int
		Secure   bool
		HttpOnly bool
	}
)

const (
	sigSuffix = ".sig"
	setCookie = "Set-Cookie"
)

// Cookie get cookie from http request
func (h *HTTPReadWriter) Cookie(name string) (*http.Cookie, error) {
	return h.req.Cookie(name)
}

// SetCookie set the cookie to http response
func (h *HTTPReadWriter) SetCookie(cookie *http.Cookie) error {
	h.resp.Header().Add(setCookie, cookie.String())
	return nil
}

// NewHTTPReadWriter new http readwriter
func NewHTTPReadWriter(req *http.Request, resp http.ResponseWriter) *HTTPReadWriter {
	return &HTTPReadWriter{
		req:  req,
		resp: resp,
	}
}

// CreateCookie create a cookie
func (c *Cookies) CreateCookie(name, value string) *http.Cookie {
	opts := c.opts
	cookie := &http.Cookie{
		Name:  name,
		Value: value,
	}
	if opts != nil {
		cookie.Path = opts.Path
		cookie.Domain = opts.Domain
		cookie.Expires = opts.Expires
		cookie.MaxAge = opts.MaxAge
		cookie.Secure = opts.Secure
		cookie.HttpOnly = opts.HttpOnly
	}
	return cookie
}

// Get get the value of cookie
func (c *Cookies) Get(name string, signed bool) string {
	rw := c.RW
	cookie, _ := rw.Cookie(name)
	if cookie == nil {
		return ""
	}
	if !signed {
		return cookie.Value
	}
	sigName := name + sigSuffix
	sigCookie, _ := rw.Cookie(sigName)
	if sigCookie == nil {
		return ""
	}
	data := name + "=" + cookie.Value
	index := c.kg.Index(data, sigCookie.Value)
	// not match, remove the sig key value
	if index < 0 {
		c.Set(c.CreateCookie(sigName, ""), false)
		return ""
	}
	if index > 0 {
		// 对于sig匹配到的key大于0的，更新sig的值，提升后续判断性能
		// 因为keygrip每次是按顺序判断
		c.Set(c.CreateCookie(sigName, c.kg.Sign(data)), false)
	}
	return cookie.Value
}

// Set set the cookie
func (c *Cookies) Set(cookie *http.Cookie, signed bool) {
	c.RW.SetCookie(cookie)
	if signed {
		// TODO 是否clone当前cookie来生成
		name := cookie.Name
		data := name + "=" + cookie.Value
		sigName := name + sigSuffix
		sigCookie := c.kg.Sign(data)
		c.Set(c.CreateCookie(sigName, sigCookie), false)
	}
}

// GetKeygrip get the keygrip instance
func (c *Cookies) GetKeygrip() *keygrip.Keygrip {
	return c.kg
}

// New create a instance of cookies
func New(rw ReadWriter, opts *Options) *Cookies {
	c := &Cookies{
		RW:   rw,
		opts: opts,
	}
	if opts != nil && len(opts.Keys) != 0 {
		c.kg = keygrip.New(opts.Keys)
	}
	return c
}
