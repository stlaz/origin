package oauth

import (
	g "github.com/onsi/ginkgo"
	o "github.com/onsi/gomega"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	restclient "k8s.io/client-go/rest"
	e2e "k8s.io/kubernetes/test/e2e/framework"

	osinv1 "github.com/openshift/api/osin/v1"
	userv1client "github.com/openshift/client-go/user/clientset/versioned/typed/user/v1"
	exutil "github.com/openshift/origin/test/extended/util"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	scheme  = runtime.NewScheme()
	codecs  = serializer.NewCodecFactory(scheme)
	encoder = codecs.LegacyCodec(osinv1.GroupVersion) // TODO I think there is a better way to do this
)

func init() {
	utilruntime.Must(osinv1.Install(scheme))
}

var _ = g.Describe("[Suite:openshift/oauth/run-oauth-server] Run the integrated OAuth server", func() {
	defer g.GinkgoRecover()
	var (
		oc = exutil.NewCLI("oauth-server-configure", exutil.KubeConfigPath())
	)

	g.It("should successfully configure htpasswd and be responsive", func() {
		secrets := []corev1.Secret{{
			ObjectMeta: metav1.ObjectMeta{
				Name: "htpasswd-secret",
			},
			Data: map[string][]byte{
				"htpasswd": []byte("testuser:$2y$05$pOYBCbJ1RXr.vDzPXdyTxuE96Nojc9dNI9R3QjkWUj2t/Ae/jmFy."), // userinfo testuser:password
			},
		}}

		htpasswdConfig := osinv1.IdentityProvider{
			Name:            "htpasswd",
			UseAsChallenger: true,
			UseAsLogin:      true,
			MappingMethod:   "claim",
			Provider:        runtime.RawExtension{Raw: encodeOrDie(&osinv1.HTPasswdPasswordIdentityProvider{File: exutil.GetPathFromConfigMapSecretName("htpasswd-secret", "htpasswd")})},
		}
		tokenReqOpts, cleanup, err := exutil.DeployOAuthServer(oc, []osinv1.IdentityProvider{htpasswdConfig}, nil, secrets)
		defer cleanup()
		o.Expect(err).ToNot(o.HaveOccurred())
		e2e.Logf("got the OAuth server address: %s", tokenReqOpts.Issuer)

		token, err := exutil.RequestTokenForUser(tokenReqOpts, "testuser", "password")
		o.Expect(err).ToNot(o.HaveOccurred())

		userConfig := restclient.AnonymousClientConfig(oc.AdminConfig())
		userConfig.BearerToken = token
		userClient, err := userv1client.NewForConfig(userConfig)
		o.Expect(err).ToNot(o.HaveOccurred())

		user, err := userClient.Users().Get("~", metav1.GetOptions{})
		o.Expect(err).ToNot(o.HaveOccurred())
		o.Expect(user.Name).To(o.Equal("testuser"))
	})
})

func encodeOrDie(obj runtime.Object) []byte {
	bytes, err := runtime.Encode(encoder, obj)
	if err != nil {
		panic(err) // indicates static generated code is broken, unrecoverable
	}
	return bytes
}
