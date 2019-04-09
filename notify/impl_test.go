// Copyright 2018 Prometheus Team
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-kit/kit/log"
	commoncfg "github.com/prometheus/common/config"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"

	"github.com/sumeshkanayi/alertmanager/config"
	"github.com/sumeshkanayi/alertmanager/template"
	"github.com/sumeshkanayi/alertmanager/types"
)

func TestWebhookRetry(t *testing.T) {
	u, err := url.Parse("http://example.com")
	if err != nil {
		t.Fatalf("failed to parse URL: %v", err)
	}
	notifier := &Webhook{conf: &config.WebhookConfig{URL: &config.URL{u}}}
	for statusCode, expected := range retryTests(defaultRetryCodes()) {
		actual, _ := notifier.retry(statusCode)
		require.Equal(t, expected, actual, fmt.Sprintf("error on status %d", statusCode))
	}
}

func TestPagerDutyRetryV1(t *testing.T) {
	notifier := new(PagerDuty)

	retryCodes := append(defaultRetryCodes(), http.StatusForbidden)
	for statusCode, expected := range retryTests(retryCodes) {
		resp := &http.Response{
			StatusCode: statusCode,
		}
		actual, _ := notifier.retryV1(resp)
		require.Equal(t, expected, actual, fmt.Sprintf("retryv1 - error on status %d", statusCode))
	}
}

func TestPagerDutyRetryV2(t *testing.T) {
	notifier := new(PagerDuty)

	retryCodes := append(defaultRetryCodes(), http.StatusTooManyRequests)
	for statusCode, expected := range retryTests(retryCodes) {
		resp := &http.Response{
			StatusCode: statusCode,
		}
		actual, _ := notifier.retryV2(resp)
		require.Equal(t, expected, actual, fmt.Sprintf("retryv2 - error on status %d", statusCode))
	}
}

func TestPagerDutyErr(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   io.Reader

		exp string
	}{
		{
			status: http.StatusBadRequest,
			body: bytes.NewBuffer([]byte(
				`{"status":"invalid event","message":"Event object is invalid","errors":["Length of 'routing_key' is incorrect (should be 32 characters)"]}`,
			)),

			exp: "Length of 'routing_key' is incorrect",
		},
		{
			status: http.StatusBadRequest,
			body:   bytes.NewBuffer([]byte(`{"status"}`)),

			exp: "unexpected status code: 400",
		},
		{
			status: http.StatusBadRequest,
			body:   nil,

			exp: "unexpected status code: 400",
		},
		{
			status: http.StatusTooManyRequests,
			body:   bytes.NewBuffer([]byte("")),

			exp: "unexpected status code: 429",
		},
	} {
		tc := tc
		t.Run("", func(t *testing.T) {
			err := pagerDutyErr(tc.status, tc.body)
			require.Contains(t, err.Error(), tc.exp)
		})
	}
}

func TestSlackRetry(t *testing.T) {
	notifier := new(Slack)
	for statusCode, expected := range retryTests(defaultRetryCodes()) {
		actual, _ := notifier.retry(statusCode)
		require.Equal(t, expected, actual, fmt.Sprintf("error on status %d", statusCode))
	}
}

func TestSlackRedactedURL(t *testing.T) {
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cancel()
		<-done
	}))
	defer func() {
		close(done)
		srv.Close()
	}()

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)

	notifier := NewSlack(
		&config.SlackConfig{
			APIURL:     &config.SecretURL{URL: u},
			HTTPConfig: &commoncfg.HTTPClientConfig{},
		},
		createTmpl(t),
		log.NewNopLogger(),
	)

	ok, err := notifier.Notify(ctx, []*types.Alert{}...)
	require.True(t, ok)
	require.Error(t, err)
	require.NotContains(t, err.Error(), srv.URL)
}

func TestHipchatRetry(t *testing.T) {
	notifier := new(Hipchat)
	retryCodes := append(defaultRetryCodes(), http.StatusTooManyRequests)
	for statusCode, expected := range retryTests(retryCodes) {
		actual, _ := notifier.retry(statusCode)
		require.Equal(t, expected, actual, fmt.Sprintf("error on status %d", statusCode))
	}
}

func TestOpsGenieRetry(t *testing.T) {
	notifier := new(OpsGenie)

	retryCodes := append(defaultRetryCodes(), http.StatusTooManyRequests)
	for statusCode, expected := range retryTests(retryCodes) {
		actual, _ := notifier.retry(statusCode)
		require.Equal(t, expected, actual, fmt.Sprintf("error on status %d", statusCode))
	}
}

func TestVictorOpsRetry(t *testing.T) {
	notifier := new(VictorOps)
	for statusCode, expected := range retryTests(defaultRetryCodes()) {
		actual, _ := notifier.retry(statusCode)
		require.Equal(t, expected, actual, fmt.Sprintf("error on status %d", statusCode))
	}
}

func TestPushoverRetry(t *testing.T) {
	notifier := new(Pushover)
	for statusCode, expected := range retryTests(defaultRetryCodes()) {
		actual, _ := notifier.retry(statusCode)
		require.Equal(t, expected, actual, fmt.Sprintf("error on status %d", statusCode))
	}
}

func retryTests(retryCodes []int) map[int]bool {
	tests := map[int]bool{
		// 1xx
		http.StatusContinue:           false,
		http.StatusSwitchingProtocols: false,
		http.StatusProcessing:         false,

		// 2xx
		http.StatusOK:                   false,
		http.StatusCreated:              false,
		http.StatusAccepted:             false,
		http.StatusNonAuthoritativeInfo: false,
		http.StatusNoContent:            false,
		http.StatusResetContent:         false,
		http.StatusPartialContent:       false,
		http.StatusMultiStatus:          false,
		http.StatusAlreadyReported:      false,
		http.StatusIMUsed:               false,

		// 3xx
		http.StatusMultipleChoices:   false,
		http.StatusMovedPermanently:  false,
		http.StatusFound:             false,
		http.StatusSeeOther:          false,
		http.StatusNotModified:       false,
		http.StatusUseProxy:          false,
		http.StatusTemporaryRedirect: false,
		http.StatusPermanentRedirect: false,

		// 4xx
		http.StatusBadRequest:                   false,
		http.StatusUnauthorized:                 false,
		http.StatusPaymentRequired:              false,
		http.StatusForbidden:                    false,
		http.StatusNotFound:                     false,
		http.StatusMethodNotAllowed:             false,
		http.StatusNotAcceptable:                false,
		http.StatusProxyAuthRequired:            false,
		http.StatusRequestTimeout:               false,
		http.StatusConflict:                     false,
		http.StatusGone:                         false,
		http.StatusLengthRequired:               false,
		http.StatusPreconditionFailed:           false,
		http.StatusRequestEntityTooLarge:        false,
		http.StatusRequestURITooLong:            false,
		http.StatusUnsupportedMediaType:         false,
		http.StatusRequestedRangeNotSatisfiable: false,
		http.StatusExpectationFailed:            false,
		http.StatusTeapot:                       false,
		http.StatusUnprocessableEntity:          false,
		http.StatusLocked:                       false,
		http.StatusFailedDependency:             false,
		http.StatusUpgradeRequired:              false,
		http.StatusPreconditionRequired:         false,
		http.StatusTooManyRequests:              false,
		http.StatusRequestHeaderFieldsTooLarge:  false,
		http.StatusUnavailableForLegalReasons:   false,

		// 5xx
		http.StatusInternalServerError:           false,
		http.StatusNotImplemented:                false,
		http.StatusBadGateway:                    false,
		http.StatusServiceUnavailable:            false,
		http.StatusGatewayTimeout:                false,
		http.StatusHTTPVersionNotSupported:       false,
		http.StatusVariantAlsoNegotiates:         false,
		http.StatusInsufficientStorage:           false,
		http.StatusLoopDetected:                  false,
		http.StatusNotExtended:                   false,
		http.StatusNetworkAuthenticationRequired: false,
	}

	for _, statusCode := range retryCodes {
		tests[statusCode] = true
	}

	return tests
}

func defaultRetryCodes() []int {
	return []int{
		http.StatusInternalServerError,
		http.StatusNotImplemented,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout,
		http.StatusHTTPVersionNotSupported,
		http.StatusVariantAlsoNegotiates,
		http.StatusInsufficientStorage,
		http.StatusLoopDetected,
		http.StatusNotExtended,
		http.StatusNetworkAuthenticationRequired,
	}
}

func createTmpl(t *testing.T) *template.Template {
	tmpl, err := template.FromGlobs()
	require.NoError(t, err)
	tmpl.ExternalURL, _ = url.Parse("http://am")
	return tmpl
}

func readBody(t *testing.T, r *http.Request) string {
	body, err := ioutil.ReadAll(r.Body)
	require.NoError(t, err)
	return string(body)
}

func TestOpsGenie(t *testing.T) {
	u, err := url.Parse("https://opsgenie/api")
	if err != nil {
		t.Fatalf("failed to parse URL: %v", err)
	}
	logger := log.NewNopLogger()
	tmpl := createTmpl(t)
	conf := &config.OpsGenieConfig{
		NotifierConfig: config.NotifierConfig{
			VSendResolved: true,
		},
		Message:     `{{ .CommonLabels.Message }}`,
		Description: `{{ .CommonLabels.Description }}`,
		Source:      `{{ .CommonLabels.Source }}`,
		Teams:       `{{ .CommonLabels.Teams }}`,
		Tags:        `{{ .CommonLabels.Tags }}`,
		Note:        `{{ .CommonLabels.Note }}`,
		Priority:    `{{ .CommonLabels.Priority }}`,
		APIKey:      `{{ .ExternalURL }}`,
		APIURL:      &config.URL{u},
	}
	notifier := NewOpsGenie(conf, tmpl, logger)

	ctx := context.Background()
	ctx = WithGroupKey(ctx, "1")

	expectedURL, _ := url.Parse("https://opsgenie/apiv2/alerts")

	// Empty alert.
	alert1 := &types.Alert{
		Alert: model.Alert{
			StartsAt: time.Now(),
			EndsAt:   time.Now().Add(time.Hour),
		},
	}
	expectedBody := `{"alias":"6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b","message":"","details":{},"source":""}
`
	req, retry, err := notifier.createRequest(ctx, alert1)
	require.NoError(t, err)
	require.Equal(t, true, retry)
	require.Equal(t, expectedURL, req.URL)
	require.Equal(t, "GenieKey http://am", req.Header.Get("Authorization"))
	require.Equal(t, expectedBody, readBody(t, req))

	// Fully defined alert.
	alert2 := &types.Alert{
		Alert: model.Alert{
			Labels: model.LabelSet{
				"Message":     "message",
				"Description": "description",
				"Source":      "http://prometheus",
				"Teams":       "TeamA,TeamB,",
				"Tags":        "tag1,tag2",
				"Note":        "this is a note",
				"Priotity":    "P1",
			},
			StartsAt: time.Now(),
			EndsAt:   time.Now().Add(time.Hour),
		},
	}
	expectedBody = `{"alias":"6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b","message":"message","description":"description","details":{},"source":"http://prometheus","teams":[{"name":"TeamA"},{"name":"TeamB"}],"tags":["tag1","tag2"],"note":"this is a note"}
`
	req, retry, err = notifier.createRequest(ctx, alert2)
	require.NoError(t, err)
	require.Equal(t, true, retry)
	require.Equal(t, expectedBody, readBody(t, req))

	// Broken API Key Template.
	conf.APIKey = "{{ kaput "
	_, _, err = notifier.createRequest(ctx, alert2)
	require.Error(t, err)
	require.Equal(t, err.Error(), "templating error: template: :1: function \"kaput\" not defined")
}

func TestVictorOpsCustomFields(t *testing.T) {
	logger := log.NewNopLogger()
	tmpl := createTmpl(t)

	url, err := url.Parse("http://nowhere.com")

	require.NoError(t, err, "unexpected error parsing mock url")

	conf := &config.VictorOpsConfig{
		APIKey:            `12345`,
		APIURL:            &config.URL{url},
		EntityDisplayName: `{{ .CommonLabels.Message }}`,
		StateMessage:      `{{ .CommonLabels.Message }}`,
		RoutingKey:        `test`,
		MessageType:       ``,
		MonitoringTool:    `AM`,
		CustomFields: map[string]string{
			"Field_A": "{{ .CommonLabels.Message }}",
		},
	}

	notifier := NewVictorOps(conf, tmpl, logger)

	ctx := context.Background()
	ctx = WithGroupKey(ctx, "1")

	alert := &types.Alert{
		Alert: model.Alert{
			Labels: model.LabelSet{
				"Message": "message",
			},
			StartsAt: time.Now(),
			EndsAt:   time.Now().Add(time.Hour),
		},
	}

	msg, err := notifier.createVictorOpsPayload(ctx, alert)
	require.NoError(t, err)

	var m map[string]string
	err = json.Unmarshal(msg.Bytes(), &m)

	require.NoError(t, err)

	// Verify that a custom field was added to the payload and templatized.
	require.Equal(t, "message", m["Field_A"])
}

func TestTruncate(t *testing.T) {
	testCases := []struct {
		in string
		n  int

		out   string
		trunc bool
	}{
		{
			in:    "",
			n:     5,
			out:   "",
			trunc: false,
		},
		{
			in:    "abcde",
			n:     2,
			out:   "ab",
			trunc: true,
		},
		{
			in:    "abcde",
			n:     4,
			out:   "a...",
			trunc: true,
		},
		{
			in:    "abcde",
			n:     5,
			out:   "abcde",
			trunc: false,
		},
		{
			in:    "abcdefgh",
			n:     5,
			out:   "ab...",
			trunc: true,
		},
		{
			in:    "a⌘cde",
			n:     5,
			out:   "a⌘cde",
			trunc: false,
		},
		{
			in:    "a⌘cdef",
			n:     5,
			out:   "a⌘...",
			trunc: true,
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("truncate(%s,%d)", tc.in, tc.n), func(t *testing.T) {
			s, trunc := truncate(tc.in, tc.n)
			require.Equal(t, tc.trunc, trunc)
			require.Equal(t, tc.out, s)
		})
	}
}
