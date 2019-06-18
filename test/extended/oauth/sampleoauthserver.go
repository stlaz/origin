package oauth

import (
	"io/ioutil"
	"net/http"

	g "github.com/onsi/ginkgo"
	o "github.com/onsi/gomega"

	"k8s.io/client-go/rest"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	e2e "k8s.io/kubernetes/test/e2e/framework"

	osinv1 "github.com/openshift/api/osin/v1"
	"github.com/openshift/oc/pkg/helpers/tokencmd"
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
				"htpasswd": []byte("testuser:$apr1$iD9QmkLW$dfVpx1X7533hKAVSiRfhd1"), // userinfo testuser:password
			},
		}}

		htpasswdConfig := osinv1.IdentityProvider{
			Name:            "htpasswd",
			UseAsChallenger: true,
			UseAsLogin:      true,
			MappingMethod:   "claim",
			Provider:        runtime.RawExtension{Raw: encodeOrDie(&osinv1.HTPasswdPasswordIdentityProvider{File: exutil.GetPathFromConfigMapSecretName("htpasswd-secret", "htpasswd")})},
		}
		serverAddress, cleanup, err := exutil.DeployOAuthServer(oc, []osinv1.IdentityProvider{htpasswdConfig}, nil, secrets)
		defer cleanup()
		o.Expect(err).ToNot(o.HaveOccurred())
		e2e.Logf("got the OAuth server address: %s", serverAddress)

		tlsClientConfig, err := rest.TLSConfigFor(oc.AdminConfig())
		o.Expect(err).NotTo(o.HaveOccurred())
		http.DefaultTransport.(*http.Transport).TLSClientConfig = tlsClientConfig
		resp, err := http.Get(serverAddress)
		o.Expect(err).ToNot(o.HaveOccurred())
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		e2e.Logf("The body received: %s", string(body))
		o.Expect(err).ToNot(o.HaveOccurred())

		// I could not quite figure this out
		challengingClient, err := oc.AdminOAuthClient().OauthV1().OAuthClients().Get("openshift-challenging-client", metav1.GetOptions{})
		o.Expect(err).ToNot(o.HaveOccurred())
		tokenOpts := tokencmd.NewRequestTokenOptions(oc.AdminConfig(), nil, "testuser", "password", false)
		err = tokenOpts.SetDefaultOsinConfig()
		o.Expect(err).NotTo(o.HaveOccurred())
		tokenOpts.OsinConfig.ClientId = challengingClient.Name
		tokenOpts.OsinConfig.RedirectUrl = challengingClient.RedirectURIs[0]
		e2e.Logf("The RedirectURI: %s", tokenOpts.OsinConfig.RedirectUrl)
		token, err := tokenOpts.RequestToken()
		e2e.Logf("The token: %s", token)
		o.Expect(err).ToNot(o.HaveOccurred())
	})
})

func encodeOrDie(obj runtime.Object) []byte {
	bytes, err := runtime.Encode(encoder, obj)
	if err != nil {
		panic(err) // indicates static generated code is broken, unrecoverable
	}
	return bytes
}
