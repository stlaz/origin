package oauth

import (
	"strings"

	"k8s.io/apimachinery/pkg/util/validation/field"

	configv1 "github.com/openshift/api/config/v1"
	crvalidation "github.com/openshift/origin/pkg/admission/customresourcevalidation"
	"github.com/openshift/origin/pkg/cmd/server/apis/config/validation/common"
)

func ValidateOpenIDIdentityProvider(provider *configv1.OpenIDIdentityProvider, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	if provider == nil {
		allErrs = append(allErrs, field.Required(fieldPath, ""))
		return allErrs
	}

	allErrs = append(allErrs, ValidateOAuthIdentityProvider(provider.ClientID, provider.ClientSecret, fieldPath)...)

	if provider.Issuer != strings.TrimRight(provider.Issuer, "/") {
		allErrs = append(allErrs, field.Invalid(fieldPath.Child("issuer"), provider.Issuer, "cannot end with '/'"))
	}

	// The specs are a bit ambiguous on whether this must or needn't be https://
	// schema, but they do require (MUST) TLS support for the discovery and we do
	// require this in out API description
	// https://openid.net/specs/openid-connect-discovery-1_0.html#TLSRequirements
	_, issuerErrs := common.ValidateSecureURL(provider.Issuer, fieldPath.Child("issuer"))
	allErrs = append(allErrs, issuerErrs...)

	allErrs = append(allErrs, crvalidation.ValidateConfigMapReference(fieldPath.Child("ca"), provider.CA, false)...)

	return allErrs
}
