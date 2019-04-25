package oauth

import (
	"reflect"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func requestHeaderIDP(challenge, login bool) configv1.IdentityProviderConfig {
	var challengeURL, loginURL string

	if challenge {
		challengeURL = "https://sso.corporate.coolpeople.se/challenges/oauth/authorize?${query}"
	}
	if login {
		loginURL = "https://sso.corporate.coolpeople.se/loginz/oauth/authorize?${query}"
	}

	return configv1.IdentityProviderConfig{
		Type: configv1.IdentityProviderTypeRequestHeader,
		RequestHeader: &configv1.RequestHeaderIdentityProvider{
			LoginURL:     loginURL,
			ChallengeURL: challengeURL,
			ClientCA: configv1.ConfigMapNameReference{
				Name: "coolpeople-client-ca",
			},
			ClientCommonNames: []string{"authn-proxy"},
			Headers:           []string{"X-Remote-User", "SSO-User"},
			NameHeaders:       []string{"X-Remote-User-Display-Name"},
		},
	}
}

func TestValidateRequestHeaderIdentityProvider(t *testing.T) {
	type args struct {
		provider  *configv1.RequestHeaderIdentityProvider
		fieldPath *field.Path
	}
	tests := []struct {
		name string
		args args
		want field.ErrorList
	}{
		{
			name: "nil input provider",
			want: field.ErrorList{
				field.Required(nil, ""),
			},
		},
		{
			name: "empty provider",
			args: args{
				provider: &configv1.RequestHeaderIdentityProvider{},
			},
			want: field.ErrorList{
				field.Required(field.NewPath("headers"), ""),
			},
		},
		{
			name: "wrong ca refname",
			args: args{
				provider: &configv1.RequestHeaderIdentityProvider{
					Headers:  []string{"X-Remote-User"},
					ClientCA: configv1.ConfigMapNameReference{Name: "dat_badrefname"},
				},
			},
			want: field.ErrorList{
				field.Invalid(field.NewPath("clientCA", "name"), "dat_badrefname", wrongConfigMapSecretErrMsg),
			},
		},
		{
			name: "client cert names w/o client ca ref",
			args: args{
				provider: &configv1.RequestHeaderIdentityProvider{
					Headers:           []string{"X-Remote-User"},
					ClientCommonNames: []string{"red-team-proxy"},
				},
			},
			want: field.ErrorList{
				field.Invalid(field.NewPath("clientCommonNames"), []string{"red-team-proxy"}, "clientCA must be specified in order to use clientCommonNames"),
			},
		},
		{
			name: "challenge url without query, no client CA set",
			args: args{
				provider: &configv1.RequestHeaderIdentityProvider{
					Headers:      []string{"X-Remote-User"},
					ChallengeURL: "http://oauth.coolpeoplecorp.com/challenge-endpoint",
				},
			},
			want: field.ErrorList{
				field.Invalid(field.NewPath("challengeURL"), "http://oauth.coolpeoplecorp.com/challenge-endpoint", "query does not include \"${url}\" or \"${query}\", redirect will not preserve original authorize parameters"),
				field.Invalid(field.NewPath("clientCA"), "", "if no clientCA is set, no request verification is done, and any request directly against the OAuth server can impersonate any identity from this provider"),
			},
		},
		{
			name: "challenge url with query - no ${url}, ${query}",
			args: args{
				provider: &configv1.RequestHeaderIdentityProvider{
					Headers:      []string{"X-Remote-User"},
					ChallengeURL: "http://oauth.coolpeoplecorp.com/challenge-endpoint?${sender}",
					ClientCA:     configv1.ConfigMapNameReference{Name: "auth-ca"},
				},
			},
			want: field.ErrorList{
				field.Invalid(field.NewPath("challengeURL"), "http://oauth.coolpeoplecorp.com/challenge-endpoint?${sender}", "query does not include \"${url}\" or \"${query}\", redirect will not preserve original authorize parameters"),
			},
		},
		{
			name: "challenge url with query - ${url}",
			args: args{
				provider: &configv1.RequestHeaderIdentityProvider{
					Headers:      []string{"X-Remote-User"},
					ChallengeURL: "http://oauth.coolpeoplecorp.com/challenge-endpoint?${url}",
					ClientCA:     configv1.ConfigMapNameReference{Name: "auth-ca"},
				},
			},
			want: field.ErrorList{},
		},
		{
			name: "login url without query and authorize",
			args: args{
				provider: &configv1.RequestHeaderIdentityProvider{
					Headers:  []string{"X-Remote-User"},
					LoginURL: "http://oauth.coolpeoplecorp.com/challenge-endpoint",
					ClientCA: configv1.ConfigMapNameReference{Name: "auth-ca"},
				},
			},
			want: field.ErrorList{
				field.Invalid(field.NewPath("loginURL"), "http://oauth.coolpeoplecorp.com/challenge-endpoint", "query does not include \"${url}\" or \"${query}\", redirect will not preserve original authorize parameters"),
				field.Invalid(field.NewPath("loginURL"), "http://oauth.coolpeoplecorp.com/challenge-endpoint", "path does not end with \"/authorize\", grant approval flows will not function correctly"),
			},
		},
		{
			name: "login url with query - no ${url}, ${query} - no client CA set",
			args: args{
				provider: &configv1.RequestHeaderIdentityProvider{
					Headers:  []string{"X-Remote-User"},
					LoginURL: "http://oauth.coolpeoplecorp.com/login-endpoint/authorize?${custom}",
				},
			},
			want: field.ErrorList{
				field.Invalid(field.NewPath("loginURL"), "http://oauth.coolpeoplecorp.com/login-endpoint/authorize?${custom}", "query does not include \"${url}\" or \"${query}\", redirect will not preserve original authorize parameters"),
				field.Invalid(field.NewPath("clientCA"), "", "if no clientCA is set, no request verification is done, and any request directly against the OAuth server can impersonate any identity from this provider"),
			},
		},
		{
			name: "login url with query - ${query} - no /authorize",
			args: args{
				provider: &configv1.RequestHeaderIdentityProvider{
					Headers:  []string{"X-Remote-User"},
					LoginURL: "http://oauth.coolpeoplecorp.com/login-endpoint?${query}",
					ClientCA: configv1.ConfigMapNameReference{Name: "auth-ca"},
				},
			},
			want: field.ErrorList{
				field.Invalid(field.NewPath("loginURL"), "http://oauth.coolpeoplecorp.com/login-endpoint?${query}", "path does not end with \"/authorize\", grant approval flows will not function correctly"),
			},
		},
		{
			name: "login url with query - ${query} - ends with /",
			args: args{
				provider: &configv1.RequestHeaderIdentityProvider{
					Headers:  []string{"X-Remote-User"},
					LoginURL: "http://oauth.coolpeoplecorp.com/login-endpoint/authorize/?${query}",
					ClientCA: configv1.ConfigMapNameReference{Name: "auth-ca"},
				},
			},
			want: field.ErrorList{
				field.Invalid(field.NewPath("loginURL"), "http://oauth.coolpeoplecorp.com/login-endpoint/authorize/?${query}", "path ends with \"/\", grant approval flows will not function correctly"),
				field.Invalid(field.NewPath("loginURL"), "http://oauth.coolpeoplecorp.com/login-endpoint/authorize/?${query}", "path does not end with \"/authorize\", grant approval flows will not function correctly"),
			},
		},
		{
			name: "login url with query - ${query}",
			args: args{
				provider: &configv1.RequestHeaderIdentityProvider{
					Headers:  []string{"X-Remote-User"},
					LoginURL: "http://oauth.coolpeoplecorp.com/login-endpoint/authorize?${query}",
					ClientCA: configv1.ConfigMapNameReference{Name: "auth-ca"},
				},
			},
			want: field.ErrorList{},
		},
		{
			name: "more complicated use",
			args: args{
				provider: requestHeaderIDP(true, true).RequestHeader,
			},
			want: field.ErrorList{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidateRequestHeaderIdentityProvider(tt.args.provider, tt.args.fieldPath); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ValidateRequestHeaderIdentityProvider() = %v, want %v", got, tt.want)
			}
		})
	}
}
