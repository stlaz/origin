package oauth

import (
	"k8s.io/apimachinery/pkg/util/validation/field"

	configv1 "github.com/openshift/api/config/v1"
)

func ValidateGoogleIdentityProvider(provider *configv1.GoogleIdentityProvider, mappingMethod configv1.MappingMethodType, fieldPath *field.Path) field.ErrorList {
	errs := field.ErrorList{}
	if provider == nil {
		errs = append(errs, field.Required(fieldPath, ""))
		return errs
	}

	errs = append(errs, ValidateOAuthIdentityProvider(provider.ClientID, provider.ClientSecret, fieldPath)...)

	if len(provider.HostedDomain) == 0 && mappingMethod != configv1.MappingMethodLookup {
		errs = append(errs, field.Invalid(fieldPath.Child("hostedDomain"), nil, "no hostedDomain specified, any Google user will be allowed to authenticate"))
	}

	return errs
}
