package tfa

import (
	"os"

	"github.com/rs/zerolog"
)

var zlog zerolog.Logger

func NewLogger() *zerolog.Logger {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zlog = zerolog.New(os.Stdout).With().Timestamp().Logger()

	// // Set logger format
	// switch config.LogFormat {
	// case "pretty":
	// 	break
	// case "json":
	// 	logrus.SetFormatter(&logrus.JSONFormatter{})
	// // "text" is the default
	// default:
	// 	logrus.SetFormatter(&logrus.TextFormatter{
	// 		DisableColors: true,
	// 		FullTimestamp: true,
	// 	})
	// }

	// Set logger level
	switch config.LogLevel {
	case "trace":
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	case "fatal":
		zerolog.SetGlobalLevel(zerolog.FatalLevel)
	case "panic":
		zerolog.SetGlobalLevel(zerolog.PanicLevel)
	// warn is the default
	default:
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	}

	zlog.Debug().Msg("Initialized new logger")
	return &zlog
}
