package main

import (
	"context"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/rs/zerolog/log"
)

// cachedSSMPCR0Reader returns a closure suitable for
// RoutingManager.SetCurrentPCR0Reader: it reads the named SSM
// parameter and caches the value for `ttl` so the hot path
// (ClaimForEnrollment, called on every fresh enrollment) doesn't
// round-trip AWS each call. Errors are logged and the prior cached
// value is returned (or "" on first failure), which is the
// fail-open behavior the gate wants — when SSM is down we still
// accept enrollments rather than bricking the fleet.
//
// Used by parent.go to wire the #239 migration-window enrollment
// gate after instance startup.
func (p *ParentProcess) cachedSSMPCR0Reader(paramName string, ttl time.Duration) func() string {
	var (
		mu          sync.Mutex
		cached      string
		cachedAt    time.Time
		lastErrLog  time.Time
	)
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		if time.Since(cachedAt) < ttl {
			return cached
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		awsCfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			if time.Since(lastErrLog) > time.Minute {
				log.Warn().Err(err).Msg("routing: SSM PCR0 read — AWS config load failed; falling back to cached value")
				lastErrLog = time.Now()
			}
			return cached
		}
		client := ssm.NewFromConfig(awsCfg)
		out, err := client.GetParameter(ctx, &ssm.GetParameterInput{Name: &paramName})
		if err != nil {
			if time.Since(lastErrLog) > time.Minute {
				log.Warn().Err(err).Str("param", paramName).Msg("routing: SSM PCR0 read failed; falling back to cached value")
				lastErrLog = time.Now()
			}
			return cached
		}
		if out.Parameter == nil || out.Parameter.Value == nil {
			return cached
		}
		cached = *out.Parameter.Value
		cachedAt = time.Now()
		return cached
	}
}
