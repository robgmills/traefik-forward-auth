package tfa

import (
	"net/http"
	"net/url"

	"github.com/containous/traefik/v2/pkg/rules"
	"github.com/rs/zerolog"
	"github.com/thomseddon/traefik-forward-auth/internal/provider"
)

// Server contains router and handler methods
type Server struct {
	router *rules.Router
}

// NewServer creates a new server object and builds router
func NewServer() *Server {
	s := &Server{}
	s.buildRoutes()
	return s
}

func (s *Server) buildRoutes() {
	var err error
	s.router, err = rules.NewRouter()
	if err != nil {
		zlog.Fatal().Err(err)
	}

	// Let's build a router
	for name, rule := range config.Rules {
		matchRule := rule.formattedRule()
		if rule.Action == "allow" {
			s.router.AddRoute(matchRule, 1, s.AllowHandler(name))
		} else {
			s.router.AddRoute(matchRule, 1, s.AuthHandler(rule.Provider, name))
		}
	}

	// Add callback handler
	s.router.Handle(config.Path, s.AuthCallbackHandler())

	// Add logout handler
	s.router.Handle(config.Path+"/logout", s.LogoutHandler())

	// Add a default handler
	if config.DefaultAction == "allow" {
		s.router.NewRoute().Handler(s.AllowHandler("default"))
	} else {
		s.router.NewRoute().Handler(s.AuthHandler(config.DefaultProvider, "default"))
	}
}

// RootHandler Overwrites the request method, host and URL with those from the
// forwarded request so it's correctly routed by mux
func (s *Server) RootHandler(w http.ResponseWriter, r *http.Request) {
	// Modify request
	r.Method = r.Header.Get("X-Forwarded-Method")
	r.Host = r.Header.Get("X-Forwarded-Host")

	// Read URI from header if we're acting as forward auth middleware
	if _, ok := r.Header["X-Forwarded-Uri"]; ok {
		r.URL, _ = url.Parse(r.Header.Get("X-Forwarded-Uri"))
	}

	// Pass to mux
	s.router.ServeHTTP(w, r)
}

// AllowHandler Allows requests
func (s *Server) AllowHandler(rule string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.logger(r, "Allow", rule, "Allowing request")
		w.WriteHeader(200)
	}
}

// AuthHandler Authenticates requests
func (s *Server) AuthHandler(providerName, rule string) http.HandlerFunc {
	p, _ := config.GetConfiguredProvider(providerName)

	return func(w http.ResponseWriter, r *http.Request) {
		// Logging setup
		logger := s.logger(r, "Auth", rule, "Authenticating request")
		logger.Debug().Msg("AuthHandler: Glad you guys are around")

		// Get auth cookie
		c, err := r.Cookie(config.CookieName)
		if err != nil {
			s.authRedirect(logger, w, r, p)
			return
		}

		// Validate cookie
		email, err := ValidateCookie(r, c)
		if err != nil {
			if err.Error() == "Cookie has expired" {
				logger.Info().Msg("Cookie has expired")
				s.authRedirect(logger, w, r, p)
			} else {
				logger.Warn().Err(err).Msg("Invalid cookie")
				http.Error(w, "Not authorized", 401)
			}
			return
		}

		// Validate user
		valid := ValidateEmail(email, rule)
		if !valid {
			logger.Warn().Str("email", email).Msg("Invalid email")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Valid request
		logger.Debug().Msg("Allowing valid request")
		w.Header().Set("X-Forwarded-User", email)
		w.WriteHeader(200)
	}
}

// AuthCallbackHandler Handles auth callback request
func (s *Server) AuthCallbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Logging setup
		logger := s.logger(r, "AuthCallback", "default", "Handling callback")

		// Check state
		state := r.URL.Query().Get("state")
		if err := ValidateState(state); err != nil {
			logger.Warn().Err(err).Msg("Error validating state")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Check for CSRF cookie
		c, err := FindCSRFCookie(r, state)
		if err != nil {
			logger.Info().Msg("Missing csrf cookie")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Validate CSRF cookie against state
		valid, providerName, redirect, err := ValidateCSRFCookie(c, state)
		if !valid {
			logger.Warn().
				Err(err).
				Interface("csrf_cookie", c).
				Msg("Error validating csrf cookie")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Get provider
		p, err := config.GetConfiguredProvider(providerName)
		if err != nil {
			logger.Warn().
				Err(err).
				Interface("csrf_cookie", c).
				Str("provider", providerName).
				Msg("Invalid provider in csrf cookie")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Clear CSRF cookie
		http.SetCookie(w, ClearCSRFCookie(r, c))

		// Exchange code for token
		token, err := p.ExchangeCode(redirectUri(r), r.URL.Query().Get("code"))
		if err != nil {
			logger.Error().Err(err).Msg("Code exchange failed with provider")
			http.Error(w, "Service unavailable", 503)
			return
		}

		// Get user
		user, err := p.GetUser(token)
		if err != nil {
			logger.Error().Err(err).Msg("Error getting user")
			http.Error(w, "Service unavailable", 503)
			return
		}

		// Generate cookie
		authCookie := MakeCookie(r, user.Email)
		http.SetCookie(w, authCookie)
		logger.Info().
			Str("provider", providerName).
			Str("redirect", redirect).
			Str("user", user.Email).
			Interface("auth_cookie", authCookie).
			Msg("Successfully generated auth cookie, redirecting user.")

		// Redirect
		http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
	}
}

// LogoutHandler logs a user out
func (s *Server) LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Clear cookie
		http.SetCookie(w, ClearCookie(r))

		logger := s.logger(r, "Logout", "default", "Handling logout")
		logger.Info().Msg("Logged out user")

		if config.LogoutRedirect != "" {
			http.Redirect(w, r, config.LogoutRedirect, http.StatusTemporaryRedirect)
		} else {
			http.Error(w, "You have been logged out", 401)
		}
	}
}

func (s *Server) authRedirect(logger *zerolog.Logger, w http.ResponseWriter, r *http.Request, p provider.Provider) {
	// Error indicates no cookie, generate nonce
	err, nonce := Nonce()
	if err != nil {
		logger.Error().Err(err).Msg("Error generating nonce")
		http.Error(w, "Service unavailable", 503)
		return
	}

	// Set the CSRF cookie
	csrf := MakeCSRFCookie(r, nonce)
	http.SetCookie(w, csrf)

	if !config.InsecureCookie && r.Header.Get("X-Forwarded-Proto") != "https" {
		logger.Warn().Msg("You are using \"secure\" cookies for a request that was not " +
			"received via https. You should either redirect to https or pass the " +
			"\"insecure-cookie\" config option to permit cookies via http.")
	}

	// Forward them on
	loginURL := p.GetLoginURL(redirectUri(r), MakeState(r, p, nonce))
	http.Redirect(w, r, loginURL, http.StatusTemporaryRedirect)

	logger.Debug().
		Interface("csrf_cookie", csrf).
		Str("login_url", loginURL).
		Msg("Set CSRF cookie and redirected to provider login url")
}

func (s *Server) logger(r *http.Request, handler, rule, msg string) *zerolog.Logger {
	// // Create logger
	// logger := log.WithFields(logrus.Fields{
	// 	"handler":   handler,
	// 	"rule":      rule,
	// 	"method":    r.Header.Get("X-Forwarded-Method"),
	// 	"proto":     r.Header.Get("X-Forwarded-Proto"),
	// 	"host":      r.Header.Get("X-Forwarded-Host"),
	// 	"uri":       r.Header.Get("X-Forwarded-Uri"),
	// 	"source_ip": r.Header.Get("X-Forwarded-For"),
	// })

	// // Log request
	// logger.WithFields(logrus.Fields{
	// 	"cookies": r.Cookies(),
	// }).Debug(msg)

	// return logger
	zlog.Debug().Msg("Log: I'm here!")
	logger := zlog.With().
		Str("handler", handler).
		Str("rule", rule).
		Str("method", r.Header.Get("X-Forwarded-Method")).
		Str("proto", r.Header.Get("X-Forwarded-Proto")).
		Str("host", r.Header.Get("X-Forwarded-Host")).
		Str("uri", r.Header.Get("X-Forwarded-Uri")).
		Str("source_ip", r.Header.Get("X-Forwarded-For")).
		Logger()
	logger.Debug().Msg("Logger: So am I!")
	return &logger
}
