// Package aws provides the AWS identity token for WorkOS workload identity
// federation.
//
// New returns a provider that asks AWS STS for a web identity token (a JWT)
// representing the workload's IAM identity. Pass it to the WorkOS SDK as the
// identity token provider:
//
//	provider, err := aws.New(ctx, aws.Options{Audience: "https://api.workos.com"})
//	if err != nil {
//		log.Fatal(err)
//	}
//	creds, err := workos.NewWorkloadIdentityCredentials(workos.WorkloadIdentityConfig{
//		ClientID:              "client_01...",
//		TokenURL:              "https://auth.example.com/oauth2/token",
//		IdentityTokenProvider: provider,
//	})
//
// The workload's IAM identity needs the sts:GetWebIdentityToken permission.
//
// This module does not depend on the WorkOS SDK, and it is the only place the
// AWS SDK is needed. The provider is a plain function and does no caching.
// Each call sends one STS request and gives up on it after 10 seconds: the
// AWS SDK's own retries are turned off for the provider's STS client, because
// the WorkOS SDK calls the provider again when it retries the token exchange.
package aws

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

// signingAlgorithm is the algorithm STS signs the token with.
const signingAlgorithm = "RS256"

// globalRegion is the pseudo-region that selects the global STS endpoint,
// which does not serve GetWebIdentityToken.
const globalRegion = "aws-global"

// requestTimeout limits one STS request twice: connecting, and the request as
// a whole. It is the limit the GitHub Actions and Google Cloud providers use.
const requestTimeout = 10 * time.Second

// Options configures New.
type Options struct {
	// Audience is the audience the token is issued for. It must match the
	// audience of the trust rule in WorkOS; the conventional value is
	// "https://api.workos.com". Required.
	Audience string
	// Region is the AWS region whose STS endpoint issues the token. Optional
	// when the AWS SDK can resolve one, from AWS_REGION or the shared
	// configuration file.
	Region string
}

// tokenIssuer is the one STS operation the provider calls.
type tokenIssuer interface {
	GetWebIdentityToken(ctx context.Context, params *sts.GetWebIdentityTokenInput, optFns ...func(*sts.Options)) (*sts.GetWebIdentityTokenOutput, error)
}

// Tests replace these to stub the AWS SDK. Nothing else changes them.
var (
	loadConfig     = config.LoadDefaultConfig
	newTokenIssuer = func(cfg awssdk.Config) tokenIssuer {
		return sts.NewFromConfig(cfg, oneRequestWithin(requestTimeout))
	}
)

// oneRequestWithin makes an STS client send each call as one request and give
// up on it after limit.
//
// The AWS SDK retries a throttled or failed request by default, and sets no
// limit on the request as a whole. The WorkOS SDK already calls the provider
// again when it retries the token exchange, within a deadline of its own, so
// a provider that also retried would multiply the requests and could outlast
// that deadline.
//
// Only this client changes. The AWS configuration it was built from, and with
// it the credential chain, keep the retry settings and the HTTP client they
// have.
func oneRequestWithin(limit time.Duration) func(*sts.Options) {
	return func(o *sts.Options) {
		// Both are set: the STS client adds error codes of its own to the
		// retryer, and the attempt limit holds for those too.
		o.Retryer = awssdk.NopRetryer{}
		o.RetryMaxAttempts = 1

		// The AWS SDK's HTTP client is copied with the limits. Its other
		// settings stay, such as a CA bundle from the AWS configuration.
		if client, ok := o.HTTPClient.(*awshttp.BuildableClient); ok {
			o.HTTPClient = client.WithTimeout(limit).WithDialerOptions(func(d *net.Dialer) {
				// AWS_DEFAULTS_MODE can already set a shorter limit on
				// connecting. Keep it.
				if d.Timeout <= 0 || d.Timeout > limit {
					d.Timeout = limit
				}
			})
		}
	}
}

// New loads the AWS configuration from the SDK's default chain and returns a
// provider of STS web identity tokens for opts.Audience. The STS client is
// built once, here, and reused by every call of the provider.
//
// New fails when no region is configured. The token is always requested from
// a regional STS endpoint; the global endpoint does not issue it.
func New(ctx context.Context, opts Options) (func(ctx context.Context) (string, error), error) {
	if opts.Audience == "" {
		return nil, errors.New("aws: Options.Audience is required")
	}

	var loadOptions []func(*config.LoadOptions) error
	if opts.Region != "" {
		loadOptions = append(loadOptions, config.WithRegion(opts.Region))
	}
	cfg, err := loadConfig(ctx, loadOptions...)
	if err != nil {
		return nil, fmt.Errorf("aws: loading the AWS configuration: %w", err)
	}
	switch cfg.Region {
	case "":
		return nil, errors.New("aws: no AWS region is configured; set Options.Region or AWS_REGION")
	case globalRegion:
		return nil, fmt.Errorf("aws: the region %q selects the global STS endpoint, which does not serve sts:GetWebIdentityToken; set a region such as us-east-1", globalRegion)
	}

	issuer := newTokenIssuer(cfg)
	return func(ctx context.Context) (string, error) {
		// DurationSeconds is left unset, so STS applies its default lifetime.
		out, err := issuer.GetWebIdentityToken(ctx, &sts.GetWebIdentityTokenInput{
			Audience:         []string{opts.Audience},
			SigningAlgorithm: awssdk.String(signingAlgorithm),
		})
		if err != nil {
			var apiErr smithy.APIError
			if errors.As(err, &apiErr) {
				return "", fmt.Errorf("aws: sts:GetWebIdentityToken failed with %s: %w", apiErr.ErrorCode(), err)
			}
			return "", fmt.Errorf("aws: sts:GetWebIdentityToken failed: %w", err)
		}
		if out == nil || out.WebIdentityToken == nil || *out.WebIdentityToken == "" {
			return "", errors.New("aws: sts:GetWebIdentityToken returned no token")
		}
		return *out.WebIdentityToken, nil
	}, nil
}
