package aws

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
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
		"AWS_MAX_ATTEMPTS", "AWS_RETRY_MODE", "AWS_DEFAULTS_MODE",
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
// records where each request was sent and answers each one the same way: with
// failure when it is set, else with the STS error response of status and
// code, which default to 403 AccessDenied.
type recordingHTTPClient struct {
	status  int
	code    string
	failure error

	mu     sync.Mutex
	hosts  []string
	bodies []string
}

// stsErrorResponse is the body STS sends for an error with the code.
func stsErrorResponse(code string) string {
	return fmt.Sprintf(`<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error>
    <Type>Sender</Type>
    <Code>%s</Code>
    <Message>not authorized</Message>
  </Error>
  <RequestId>request-1</RequestId>
</ErrorResponse>`, code)
}

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
	if c.failure != nil {
		return nil, c.failure
	}
	status, code := c.status, c.code
	if status == 0 {
		status, code = http.StatusForbidden, "AccessDenied"
	}
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": {"text/xml"}},
		Body:       io.NopCloser(strings.NewReader(stsErrorResponse(code))),
		Request:    req,
	}, nil
}

// requests is the number of requests the STS client sent.
func (c *recordingHTTPClient) requests() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.hosts)
}

// withStaticCredentials makes New load its AWS configuration with fixed
// credentials and the extra options, so that no test reads the machine's.
func withStaticCredentials(t *testing.T, extra ...func(*config.LoadOptions) error) {
	t.Helper()
	original := loadConfig
	loadConfig = func(ctx context.Context, optFns ...func(*config.LoadOptions) error) (awssdk.Config, error) {
		optFns = append(optFns, config.WithCredentialsProvider(awssdk.CredentialsProviderFunc(func(context.Context) (awssdk.Credentials, error) {
			return awssdk.Credentials{AccessKeyID: "test-access-key-id", SecretAccessKey: "test-secret-access-key"}, nil
		})))
		return original(ctx, append(optFns, extra...)...)
	}
	t.Cleanup(func() { loadConfig = original })
}

// useRecordingHTTPClient makes New build a real STS client that sends its
// requests to the recorder. Retries are left as New sets them.
func useRecordingHTTPClient(t *testing.T) *recordingHTTPClient {
	t.Helper()
	recorder := &recordingHTTPClient{}
	withStaticCredentials(t, config.WithHTTPClient(recorder))
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

// The exchange calls the provider again when it retries, so one provider call
// is one STS request, whatever STS answers and whatever the AWS configuration
// says about retries.
func TestProviderSendsOneRequestWhenSTSFails(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name     string
		status   int
		code     string
		failure  error
		setenv   map[string]string
		wantText string
	}{
		{name: "a throttling error", status: http.StatusBadRequest, code: "Throttling", wantText: "Throttling"},
		{name: "a 500", status: http.StatusInternalServerError, code: "InternalFailure", wantText: "InternalFailure"},
		{name: "a 503", status: http.StatusServiceUnavailable, code: "ServiceUnavailable", wantText: "ServiceUnavailable"},
		{
			name:     "a connection that cannot be opened",
			failure:  &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")},
			wantText: "connection refused",
		},
		{
			name: "a throttling error when the AWS configuration asks for retries", status: http.StatusBadRequest, code: "Throttling",
			setenv:   map[string]string{"AWS_MAX_ATTEMPTS": "5", "AWS_RETRY_MODE": "standard"},
			wantText: "Throttling",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateAWSEnvironment(t)
			for name, value := range tc.setenv {
				t.Setenv(name, value)
			}
			recorder := useRecordingHTTPClient(t)
			recorder.status, recorder.code, recorder.failure = tc.status, tc.code, tc.failure
			provider, err := New(ctx, Options{Audience: testAudience, Region: "us-east-1"})
			if err != nil {
				t.Fatalf("New failed: %v", err)
			}

			_, err = provider(ctx)

			if err == nil {
				t.Fatal("the provider succeeded")
			}
			for _, want := range []string{"sts:GetWebIdentityToken", tc.wantText} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err, want)
				}
			}
			if got := recorder.requests(); got != 1 {
				t.Errorf("one provider call sent %d STS requests, want 1", got)
			}
		})
	}
}

// builtSTSClient returns the STS client that New builds.
func builtSTSClient(t *testing.T) *sts.Client {
	t.Helper()
	var built tokenIssuer
	original := newTokenIssuer
	newTokenIssuer = func(cfg awssdk.Config) tokenIssuer {
		built = original(cfg)
		return built
	}
	t.Cleanup(func() { newTokenIssuer = original })
	withStaticCredentials(t)

	if _, err := New(context.Background(), Options{Audience: testAudience, Region: "us-east-1"}); err != nil {
		t.Fatalf("New failed: %v", err)
	}
	client, ok := built.(*sts.Client)
	if !ok {
		t.Fatalf("New built a %T, want an STS client", built)
	}
	return client
}

// The STS client gives up on connecting, and on the request as a whole, after
// the same 10 seconds as the GitHub Actions and Google Cloud providers. A
// shorter limit on connecting that the AWS configuration chose is kept.
func TestSTSClientLimitsConnectingAndTheRequest(t *testing.T) {
	if requestTimeout != 10*time.Second {
		t.Fatalf("requestTimeout = %s, want 10s", requestTimeout)
	}
	// AWS_DEFAULTS_MODE selects the AWS SDK's own limit on connecting: none
	// in legacy mode, a short one in standard mode, 30 seconds in mobile mode.
	for _, mode := range []string{"legacy", "standard", "mobile"} {
		t.Run(mode+" defaults mode", func(t *testing.T) {
			isolateAWSEnvironment(t)
			t.Setenv("AWS_DEFAULTS_MODE", mode)

			options := builtSTSClient(t).Options()

			client, ok := options.HTTPClient.(*awshttp.BuildableClient)
			if !ok {
				t.Fatalf("the STS client sends requests with a %T, want the AWS SDK's HTTP client", options.HTTPClient)
			}
			if got := client.GetTimeout(); got != requestTimeout {
				t.Errorf("the limit on the whole request is %s, want %s", got, requestTimeout)
			}
			wantConnect := requestTimeout
			cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion("us-east-1"))
			if err != nil {
				t.Fatal(err)
			}
			unchanged := sts.NewFromConfig(cfg).Options().HTTPClient.(*awshttp.BuildableClient).GetDialer().Timeout
			if unchanged > 0 && unchanged < wantConnect {
				wantConnect = unchanged
			}
			if got := client.GetDialer().Timeout; got != wantConnect {
				t.Errorf("the limit on connecting is %s, want %s (the AWS SDK alone sets %s)", got, wantConnect, unchanged)
			}
			if got := options.Retryer.MaxAttempts(); got != 1 {
				t.Errorf("the STS client makes up to %d attempts, want 1", got)
			}
		})
	}
}

// A stalled STS holds the provider for no longer than the limit, and the
// request that timed out is not sent again.
func TestProviderGivesUpOnAStalledSTSAfterOneRequest(t *testing.T) {
	isolateAWSEnvironment(t)

	// A server that accepts connections and never answers.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var (
		mu          sync.Mutex
		connections []net.Conn
	)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			connections = append(connections, conn)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range connections {
			conn.Close()
		}
	})

	withStaticCredentials(t, config.WithBaseEndpoint("http://"+listener.Addr().String()))
	const limit = 250 * time.Millisecond
	original := newTokenIssuer
	newTokenIssuer = func(cfg awssdk.Config) tokenIssuer { return sts.NewFromConfig(cfg, oneRequestWithin(limit)) }
	t.Cleanup(func() { newTokenIssuer = original })

	// The context only ends the test if the client has no limit of its own.
	ctx, cancel := context.WithTimeout(context.Background(), 20*limit)
	defer cancel()
	provider, err := New(ctx, Options{Audience: testAudience, Region: "us-east-1"})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	start := time.Now()
	_, err = provider(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("the provider succeeded against a server that never answers")
	}
	if !strings.Contains(err.Error(), "sts:GetWebIdentityToken") {
		t.Errorf("error %q does not name the call", err)
	}
	if elapsed < limit || elapsed > 10*limit {
		t.Errorf("the provider returned after %s, want about %s", elapsed, limit)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(connections) != 1 {
		t.Errorf("the STS client opened %d connections, want 1", len(connections))
	}
}
