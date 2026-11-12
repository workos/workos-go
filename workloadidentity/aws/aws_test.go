package aws

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

const testAudience = "https://api.workos.com"

// fakeIssuer stubs the STS client behind its one-method seam.
type fakeIssuer struct {
	inputs []*sts.GetWebIdentityTokenInput
	out    *sts.GetWebIdentityTokenOutput
	err    error
}

func (f *fakeIssuer) GetWebIdentityToken(_ context.Context, params *sts.GetWebIdentityTokenInput, _ ...func(*sts.Options)) (*sts.GetWebIdentityTokenOutput, error) {
	f.inputs = append(f.inputs, params)
	return f.out, f.err
}

// stubIssuer makes New build the fake instead of an STS client and returns
// the AWS configuration New built it from.
func stubIssuer(t *testing.T, issuer tokenIssuer) *awssdk.Config {
	t.Helper()
	var used awssdk.Config
	original := newTokenIssuer
	newTokenIssuer = func(cfg awssdk.Config) tokenIssuer {
		used = cfg
		return issuer
	}
	t.Cleanup(func() { newTokenIssuer = original })
	return &used
}

// isolateAWSEnvironment keeps the machine's AWS configuration, credentials
// and metadata service out of a test.
func isolateAWSEnvironment(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{
		"AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PROFILE", "AWS_DEFAULT_PROFILE",
		"AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_STS", "AWS_USE_FIPS_ENDPOINT", "AWS_USE_DUALSTACK_ENDPOINT",
	} {
		t.Setenv(name, "") // registers the restore
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
}

// recordingHTTPClient stands in for the network under a real STS client. It
// records where each request was sent and answers with an STS error.
type recordingHTTPClient struct {
	mu     sync.Mutex
	hosts  []string
	bodies []string
}

const accessDeniedResponse = `<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error>
    <Type>Sender</Type>
    <Code>AccessDenied</Code>
    <Message>not authorized</Message>
  </Error>
  <RequestId>request-1</RequestId>
</ErrorResponse>`

func (c *recordingHTTPClient) Do(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
		req.Body.Close()
	}
	c.mu.Lock()
	c.hosts = append(c.hosts, req.URL.Host)
	c.bodies = append(c.bodies, string(body))
	c.mu.Unlock()
	return &http.Response{
		StatusCode: http.StatusForbidden,
		Header:     http.Header{"Content-Type": {"text/xml"}},
		Body:       io.NopCloser(strings.NewReader(accessDeniedResponse)),
		Request:    req,
	}, nil
}

// useRecordingHTTPClient makes New build a real STS client that sends its
// requests to the recorder, with static credentials and no retries.
func useRecordingHTTPClient(t *testing.T) *recordingHTTPClient {
	t.Helper()
	recorder := &recordingHTTPClient{}
	original := loadConfig
	loadConfig = func(ctx context.Context, optFns ...func(*config.LoadOptions) error) (awssdk.Config, error) {
		return original(ctx, append(optFns,
			config.WithHTTPClient(recorder),
			config.WithCredentialsProvider(awssdk.CredentialsProviderFunc(func(context.Context) (awssdk.Credentials, error) {
				return awssdk.Credentials{AccessKeyID: "test-access-key-id", SecretAccessKey: "test-secret-access-key"}, nil
			})),
			config.WithRetryMaxAttempts(1),
		)...)
	}
	t.Cleanup(func() { loadConfig = original })
	return recorder
}

func TestWIF_AWS_01_RequestsTokenFromRegionalSTS(t *testing.T) {
	ctx := context.Background()

	t.Run("calls GetWebIdentityToken with the audience and RS256", func(t *testing.T) {
		isolateAWSEnvironment(t)
		issuer := &fakeIssuer{out: &sts.GetWebIdentityTokenOutput{WebIdentityToken: awssdk.String("aws-jwt")}}
		cfg := stubIssuer(t, issuer)

		provider, err := New(ctx, Options{Audience: testAudience, Region: "us-east-1"})
		if err != nil {
			t.Fatalf("New failed: %v", err)
		}
		token, err := provider(ctx)
		if err != nil {
			t.Fatalf("provider failed: %v", err)
		}

		if token != "aws-jwt" {
			t.Errorf("token = %q, want %q", token, "aws-jwt")
		}
		if cfg.Region != "us-east-1" {
			t.Errorf("the STS client was built for region %q, want us-east-1", cfg.Region)
		}
		if len(issuer.inputs) != 1 {
			t.Fatalf("the stub received %d calls, want 1", len(issuer.inputs))
		}
		input := issuer.inputs[0]
		if len(input.Audience) != 1 || input.Audience[0] != testAudience {
			t.Errorf("Audience = %q, want [%q]", input.Audience, testAudience)
		}
		if input.SigningAlgorithm == nil || *input.SigningAlgorithm != "RS256" {
			t.Errorf("SigningAlgorithm = %v, want RS256", input.SigningAlgorithm)
		}
		if input.DurationSeconds != nil {
			t.Errorf("DurationSeconds = %d, want it unset", *input.DurationSeconds)
		}

		// The STS client is built once, not per call.
		if _, err := provider(ctx); err != nil {
			t.Fatalf("second call failed: %v", err)
		}
		if len(issuer.inputs) != 2 {
			t.Errorf("the stub received %d calls after two provider calls, want 2", len(issuer.inputs))
		}
	})

	t.Run("sends the request to the regional endpoint", func(t *testing.T) {
		isolateAWSEnvironment(t)
		recorder := useRecordingHTTPClient(t)

		provider, err := New(ctx, Options{Audience: testAudience, Region: "us-east-1"})
		if err != nil {
			t.Fatalf("New failed: %v", err)
		}
		_, _ = provider(ctx) // the recorder answers with an error; only the destination matters here

		if len(recorder.hosts) != 1 {
			t.Fatalf("the STS client sent %d requests, want 1", len(recorder.hosts))
		}
		if got, want := recorder.hosts[0], "sts.us-east-1.amazonaws.com"; got != want {
			t.Errorf("the request went to %q, want the regional endpoint %q", got, want)
		}
		if !strings.Contains(recorder.bodies[0], "Action=GetWebIdentityToken") {
			t.Errorf("the request body %q does not call GetWebIdentityToken", recorder.bodies[0])
		}
	})

	t.Run("takes the region from the AWS configuration", func(t *testing.T) {
		isolateAWSEnvironment(t)
		t.Setenv("AWS_REGION", "eu-west-1")
		cfg := stubIssuer(t, &fakeIssuer{})

		if _, err := New(ctx, Options{Audience: testAudience}); err != nil {
			t.Fatalf("New failed: %v", err)
		}
		if cfg.Region != "eu-west-1" {
			t.Errorf("the STS client was built for region %q, want eu-west-1", cfg.Region)
		}
	})

	t.Run("fails with no region", func(t *testing.T) {
		isolateAWSEnvironment(t)
		stubIssuer(t, &fakeIssuer{})

		provider, err := New(ctx, Options{Audience: testAudience})

		if err == nil || provider != nil {
			t.Fatalf("New returned (%v, %v), want an error", provider != nil, err)
		}
		if !strings.Contains(err.Error(), "region") {
			t.Errorf("error %q does not mention the region", err)
		}
	})

	t.Run("refuses the global endpoint", func(t *testing.T) {
		isolateAWSEnvironment(t)
		stubIssuer(t, &fakeIssuer{})

		if _, err := New(ctx, Options{Audience: testAudience, Region: "aws-global"}); err == nil {
			t.Fatal("New accepted the global STS endpoint")
		}
	})
}

func TestWIF_AWS_02_STSErrorNamesTheCall(t *testing.T) {
	ctx := context.Background()
	const secret = "SECRET-JWT-VALUE"

	requireProviderError := func(t *testing.T, err error) {
		t.Helper()
		if err == nil {
			t.Fatal("the provider succeeded")
		}
		for _, want := range []string{"sts:GetWebIdentityToken", "AccessDenied"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not contain %q", err, want)
			}
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error %q contains a token", err)
		}
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "AccessDenied" {
			t.Errorf("error %q does not wrap the AWS error", err)
		}
	}

	t.Run("an error from the stubbed STS client", func(t *testing.T) {
		isolateAWSEnvironment(t)
		stubIssuer(t, &fakeIssuer{
			out: &sts.GetWebIdentityTokenOutput{WebIdentityToken: awssdk.String(secret)},
			err: &smithy.GenericAPIError{Code: "AccessDenied", Message: "not authorized"},
		})
		provider, err := New(ctx, Options{Audience: testAudience, Region: "us-east-1"})
		if err != nil {
			t.Fatalf("New failed: %v", err)
		}

		token, err := provider(ctx)

		requireProviderError(t, err)
		if token != "" {
			t.Errorf("token = %q, want none with an error", token)
		}
	})

	t.Run("an error response decoded by the STS client", func(t *testing.T) {
		isolateAWSEnvironment(t)
		useRecordingHTTPClient(t)
		provider, err := New(ctx, Options{Audience: testAudience, Region: "us-east-1"})
		if err != nil {
			t.Fatalf("New failed: %v", err)
		}

		_, err = provider(ctx)

		requireProviderError(t, err)
	})
}

func TestNewRequiresAnAudience(t *testing.T) {
	isolateAWSEnvironment(t)
	stubIssuer(t, &fakeIssuer{})

	if _, err := New(context.Background(), Options{Region: "us-east-1"}); err == nil {
		t.Fatal("New succeeded with no audience")
	}
}

func TestProviderRejectsAnEmptyToken(t *testing.T) {
	isolateAWSEnvironment(t)
	stubIssuer(t, &fakeIssuer{out: &sts.GetWebIdentityTokenOutput{}})
	provider, err := New(context.Background(), Options{Audience: testAudience, Region: "us-east-1"})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	if _, err := provider(context.Background()); err == nil {
		t.Fatal("the provider returned an empty token without an error")
	}
}
