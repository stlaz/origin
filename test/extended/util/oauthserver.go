package util

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"path"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"

	configv1 "github.com/openshift/api/config/v1"
	legacyconfigv1 "github.com/openshift/api/legacyconfig/v1"
	osinv1 "github.com/openshift/api/osin/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	"github.com/openshift/library-go/pkg/config/helpers"
	"github.com/openshift/library-go/pkg/crypto"

	"github.com/openshift/origin/test/extended/testdata"
)

const (
	serviceURLFmt = "https://test-oauth-svc.%s.svc" // fill in the namespace

	servingCertDirPath  = "/var/config/system/secrets/serving-cert"
	servingCertPathCert = "/var/config/system/secrets/serving-cert/tls.crt"
	servingCertPathKey  = "/var/config/system/secrets/serving-cert/tls.key"

	routerCertsDirPath = "/var/config/system/secrets/router-certs"

	sessionSecretDirPath = "/var/config/system/secrets/session-secret"
	sessionSecretPath    = "/var/config/system/secrets/session-secret/session"

	oauthConfigPath  = "/var/config/system/configmaps/oauth-config"
	serviceCADirPath = "/var/config/system/configmaps/service-ca"

	configObjectsDir = "/var/oauth/configobjects/"

	RouteName = "test-oauth-route"
	SAName    = "e2e-oauth"
)

var (
	serviceCAPath = "/var/config/system/configmaps/service-ca/service-ca.crt" // has to be var so that we can use its address

	osinScheme = runtime.NewScheme()
	codecs     = serializer.NewCodecFactory(osinScheme)
	encoder    = codecs.LegacyCodec(osinv1.GroupVersion)

	defaultProcMount         = corev1.DefaultProcMount
	volumesDefaultMode int32 = 420
)

func init() {
	utilruntime.Must(osinv1.Install(osinScheme))
}

// DeployOAuthServer - deployes an instance of an OpenShift OAuth server
// very simplified for now
// returns OAuth server url, cleanup function, error
func DeployOAuthServer(oc *CLI, idps []osinv1.IdentityProvider, configMaps []corev1.ConfigMap, secrets []corev1.Secret) (string, func(), error) {
	oauthServerDataDir := FixturePath("testdata", "oauthserver")
	cleanups := func() {
		oc.AsAdmin().Run("delete").Args("clusterrolebinding", oc.Namespace()).Execute()
	}

	if err := oc.AsAdmin().Run("create").Args("-f", path.Join(oauthServerDataDir, "oauth-sa.yaml")).Execute(); err != nil {
		return "", cleanups, err
	}

	// the oauth server needs access to kube-system configmaps/extension-apiserver-authentication
	oauthSARolebinding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: oc.Namespace(), // TODO: probably something more cleaver?
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     "cluster-admin", // FIXME: Nope!
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      SAName,
				Namespace: oc.Namespace(),
			},
		},
	}
	if _, err := oc.AdminKubeClient().RbacV1().ClusterRoleBindings().Create(oauthSARolebinding); err != nil {
		return "", cleanups, err
	}

	for _, res := range []string{"cabundle-cm.yaml", "oauth-server.yaml"} {
		if err := oc.AsAdmin().Run("create").Args("-f", path.Join(oauthServerDataDir, res)).Execute(); err != nil {
			return "", cleanups, err
		}
	}

	// create the secrets and configmaps the OAuth server config requires to get the server going
	coreClient := oc.AdminKubeClient().CoreV1()
	cmClient := coreClient.ConfigMaps(oc.Namespace())
	secretsClient := coreClient.Secrets(oc.Namespace())

	for _, cm := range configMaps {
		if _, err := cmClient.Create(&cm); err != nil {
			return "", cleanups, err
		}
	}

	for _, secret := range secrets {
		if _, err := secretsClient.Create(&secret); err != nil {
			return "", cleanups, err
		}
	}

	// generate a session secret for the oauth server
	sessionSecret, err := randomSessionSecret()
	if err != nil {
		return "", cleanups, err
	}
	if _, err := secretsClient.Create(sessionSecret); err != nil {
		return "", cleanups, err
	}

	// get the route of the future OAuth server
	route, err := oc.AdminRouteClient().RouteV1().Routes(oc.Namespace()).Get(RouteName, metav1.GetOptions{})
	if err != nil {
		return "", cleanups, err
	}
	routeURL := fmt.Sprintf("https://%s", route.Spec.Host)

	// prepare the config, inject it with the route URL and the IdP config we got
	config, err := oauthServerConfig(oc, routeURL, idps)
	if err != nil {
		return "", cleanups, err
	}

	configBytes := encode(config)
	if configBytes == nil {
		return "", cleanups, fmt.Errorf("error encoding the OSIN config")
	}

	if err = oc.AsAdmin().Run("create").Args("configmap", "oauth-config", "--from-literal", fmt.Sprintf("oauth.conf=%s", string(configBytes))).Execute(); err != nil {
		return "", cleanups, err
	}

	// finally create the oauth server, wait till it starts running
	oauthServerPod, err := oauthServerPod(configMaps, secrets)
	if err != nil {
		return "", cleanups, err
	}
	if _, err := coreClient.Pods(oc.Namespace()).Create(oauthServerPod); err != nil {
		return "", cleanups, err
	}

	err = wait.PollImmediate(1*time.Second, 45*time.Second, func() (bool, error) {
		pod, err := oc.AdminKubeClient().CoreV1().Pods(oc.Namespace()).Get("test-oauth-server", metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return CheckPodIsReady(*pod), nil
	})
	if err != nil {
		return "", cleanups, err
	}

	return routeURL, cleanups, nil
}

func oauthServerPod(configMaps []corev1.ConfigMap, secrets []corev1.Secret) (*corev1.Pod, error) {
	oauthServerAsset := testdata.MustAsset("test/extended/testdata/oauthserver/oauth-pod.yaml")

	obj, err := helpers.ReadYAML(bytes.NewBuffer(oauthServerAsset), corev1.AddToScheme)
	if err != nil {
		return nil, err
	}

	oauthServerPod, ok := obj.(*corev1.Pod)
	if ok != true {
		return nil, err
	}

	volumes := oauthServerPod.Spec.Volumes
	volumeMounts := oauthServerPod.Spec.Containers[0].VolumeMounts

	for _, cm := range configMaps {
		volumes, volumeMounts = addCMMount(volumes, volumeMounts, &cm)
	}

	for _, sec := range secrets {
		volumes, volumeMounts = addSecretMount(volumes, volumeMounts, &sec)
	}

	oauthServerPod.Spec.Volumes = volumes
	oauthServerPod.Spec.Containers[0].VolumeMounts = volumeMounts

	return oauthServerPod, nil
}

func addCMMount(volumes []corev1.Volume, volumeMounts []corev1.VolumeMount, cm *corev1.ConfigMap) ([]corev1.Volume, []corev1.VolumeMount) {
	volumes = append(volumes, corev1.Volume{
		Name: cm.ObjectMeta.Name,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: cm.ObjectMeta.Name},
				DefaultMode:          &volumesDefaultMode,
			},
		},
	})

	volumeMounts = append(volumeMounts, corev1.VolumeMount{
		Name:      cm.ObjectMeta.Name,
		MountPath: GetDirPathFromConfigMapSecretName(cm.ObjectMeta.Name),
		ReadOnly:  true,
	})

	return volumes, volumeMounts
}

func addSecretMount(volumes []corev1.Volume, volumeMounts []corev1.VolumeMount, secret *corev1.Secret) ([]corev1.Volume, []corev1.VolumeMount) {
	volumes = append(volumes, corev1.Volume{
		Name: secret.ObjectMeta.Name,
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName:  secret.ObjectMeta.Name,
				DefaultMode: &volumesDefaultMode,
			},
		},
	})

	volumeMounts = append(volumeMounts, corev1.VolumeMount{
		Name:      secret.ObjectMeta.Name,
		MountPath: GetDirPathFromConfigMapSecretName(secret.ObjectMeta.Name),
		ReadOnly:  true,
	})

	return volumes, volumeMounts
}

func GetDirPathFromConfigMapSecretName(name string) string {
	return fmt.Sprintf("%s/%s", configObjectsDir, name) // always concat with / in case this is run on windows
}

func GetPathFromConfigMapSecretName(name, key string) string {
	return fmt.Sprintf("%s/%s/%s", configObjectsDir, name, key)
}

// TODO:consider: we could just as well grab whatever config there is in openshift-authentication
// namespace and interpolate it with our values
// TODO: add []osinv1.IdentityProvider as input?
func oauthServerConfig(oc *CLI, routeURL string, idps []osinv1.IdentityProvider) (*osinv1.OsinServerConfig, error) {
	adminConfigClient := configclient.NewForConfigOrDie(oc.AdminConfig()).ConfigV1()

	infrastructure, err := adminConfigClient.Infrastructures().Get("cluster", metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	console, err := adminConfigClient.Consoles().Get("cluster", metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	namedRouterCerts, err := routerCertsToSNIConfig(oc)
	if err != nil {
		return nil, err
	}

	return &osinv1.OsinServerConfig{
		GenericAPIServerConfig: configv1.GenericAPIServerConfig{
			ServingInfo: configv1.HTTPServingInfo{
				ServingInfo: configv1.ServingInfo{
					BindAddress: "0.0.0.0:6443",
					BindNetwork: "tcp4",
					// we have valid serving certs provided by service-ca
					// this is our main server cert which is used if SNI does not match
					CertInfo: configv1.CertInfo{
						CertFile: servingCertPathCert,
						KeyFile:  servingCertPathKey,
					},
					ClientCA:          "", // I think this can be left unset
					NamedCertificates: namedRouterCerts,
					MinTLSVersion:     crypto.TLSVersionToNameOrDie(crypto.DefaultTLSVersion()),
					CipherSuites:      crypto.CipherSuitesToNamesOrDie(crypto.DefaultCiphers()),
				},
				MaxRequestsInFlight:   1000,   // TODO this is a made up number
				RequestTimeoutSeconds: 5 * 60, // 5 minutes
			},
			// TODO: see if we need CORS set
			// CORSAllowedOrigins: corsAllowedOrigins,     // set console route as valid CORS (so JS can logout)
			AuditConfig: configv1.AuditConfig{}, // TODO probably need this
			KubeClientConfig: configv1.KubeClientConfig{
				KubeConfig: "", // this should use in cluster config
				ConnectionOverrides: configv1.ClientConnectionOverrides{
					QPS:   400, // TODO figure out values
					Burst: 400,
				},
			},
		},
		OAuthConfig: osinv1.OAuthConfig{
			MasterCA:                    &serviceCAPath, // we have valid serving certs provided by service-ca so we can use the service for loopback
			MasterURL:                   fmt.Sprintf(serviceURLFmt, oc.Namespace()),
			MasterPublicURL:             routeURL,
			LoginURL:                    infrastructure.Status.APIServerURL,
			AssetPublicURL:              console.Status.ConsoleURL, // set console route as valid 302 redirect for logout
			AlwaysShowProviderSelection: false,
			IdentityProviders:           idps,
			GrantConfig: osinv1.GrantConfig{
				Method:               osinv1.GrantHandlerDeny, // force denial as this field must be set per OAuth client
				ServiceAccountMethod: osinv1.GrantHandlerPrompt,
			},
			SessionConfig: &osinv1.SessionConfig{
				SessionSecretsFile:   sessionSecretPath,
				SessionMaxAgeSeconds: 5 * 60, // 5 minutes
				SessionName:          "ssn",
			},
			TokenConfig: osinv1.TokenConfig{
				AuthorizeTokenMaxAgeSeconds: 5 * 60,       // 5 minutes
				AccessTokenMaxAgeSeconds:    24 * 60 * 60, // 1 day
				// AccessTokenInactivityTimeoutSeconds: xxx, TODO: see whether we need this
			},
			//  Templates: templates, TODO: we might eventually want this
		},
	}, nil
}

func routerCertsToSNIConfig(oc *CLI) ([]configv1.NamedCertificate, error) {
	routerSecret, err := oc.AdminKubeClient().CoreV1().Secrets("openshift-config-managed").Get("router-certs", metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	localRouterSecret := routerSecret.DeepCopy()
	localRouterSecret.ResourceVersion = ""
	localRouterSecret.Namespace = oc.Namespace()
	if _, err := oc.AdminKubeClient().CoreV1().Secrets(oc.Namespace()).Create(localRouterSecret); err != nil {
		return nil, err
	}

	var out []configv1.NamedCertificate
	for domain := range localRouterSecret.Data {
		out = append(out, configv1.NamedCertificate{
			Names: []string{"*." + domain}, // ingress domain is always a wildcard
			CertInfo: configv1.CertInfo{ // the cert and key are appended together
				CertFile: routerCertsDirPath + "/" + domain,
				KeyFile:  routerCertsDirPath + "/" + domain,
			},
		})
	}
	return out, nil
}

func randomSessionSecret() (*corev1.Secret, error) {
	skey, err := newSessionSecretsJSON()
	if err != nil {
		return nil, err
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "session-secret",
			Labels: map[string]string{
				"app": "test-oauth-server",
			},
		},
		Data: map[string][]byte{
			"session": skey,
		},
	}, nil
}

// this is less random than the actual secret generated in cluster-authentication-operator
func newSessionSecretsJSON() ([]byte, error) {
	const (
		sha256KeyLenBytes = sha256.BlockSize // max key size with HMAC SHA256
		aes256KeyLenBytes = 32               // max key size with AES (AES-256)
	)

	secrets := &legacyconfigv1.SessionSecrets{
		TypeMeta: metav1.TypeMeta{
			Kind:       "SessionSecrets",
			APIVersion: "v1",
		},
		Secrets: []legacyconfigv1.SessionSecret{
			{
				Authentication: randomString(sha256KeyLenBytes), // 64 chars
				Encryption:     randomString(aes256KeyLenBytes), // 32 chars
			},
		},
	}
	secretsBytes, err := json.Marshal(secrets)
	if err != nil {
		return nil, fmt.Errorf("error marshalling the session secret: %v", err) // should never happen
	}

	return secretsBytes, nil
}

//randomString - random string of A-Z chars with len size
func randomString(size int) string {
	bytes := make([]byte, size)
	for i := 0; i < size; i++ {
		bytes[i] = byte(65 + rand.Intn(25))
	}
	return base64.RawURLEncoding.EncodeToString(bytes)
}

func encode(obj runtime.Object) []byte {
	bytes, err := runtime.Encode(encoder, obj)
	if err != nil {
		return nil
	}
	return bytes
}
