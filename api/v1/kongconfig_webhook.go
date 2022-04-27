/*
Copyright 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

// log is for logging in this package.
var kongconfiglog = logf.Log.WithName("kongconfig-resource")

func (r *KongConfig) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

// TODO(user): EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!

//+kubebuilder:webhook:webhookVersions={v1beta1},path=/mutate-kong-pyfdtic-com-v1-kongconfig,mutating=true,failurePolicy=fail,sideEffects=None,groups=kong.pyfdtic.com,resources=kongconfigs,verbs=create;update,versions=v1,name=mkongconfig.kb.io,admissionReviewVersions={v1,v1beta1}

var _ webhook.Defaulter = &KongConfig{}

// Default implements webhook.Defaulter so a webhook will be registered for the type
func (r *KongConfig) Default() {
	kongconfiglog.Info("default", "name", r.Name)
	// kong service
	if r.Spec.Service.Port == nil {
		r.Spec.Service.Port = new(int32)
		*r.Spec.Service.Port = 80
	}
	if r.Spec.Service.Path == "" {
		r.Spec.Service.Path = "/"
	}
	if r.Spec.Service.Protocol == "" {
		r.Spec.Service.Protocol = "http"
	}
	if r.Spec.Service.Retries == nil {
		r.Spec.Service.Retries = new(int32)
		*r.Spec.Service.Retries = 5
	}
	if r.Spec.Service.ConnectTimeout == nil {
		r.Spec.Service.ConnectTimeout = new(int32)
		*r.Spec.Service.ConnectTimeout = 60000
	}
	if r.Spec.Service.WriteTimeout == nil {
		r.Spec.Service.WriteTimeout = new(int32)
		*r.Spec.Service.WriteTimeout = 60000
	}
	if r.Spec.Service.ReadTimeout == nil {
		r.Spec.Service.ReadTimeout = new(int32)
		*r.Spec.Service.ReadTimeout = 60000
	}
	// route
	if r.Spec.Route.Methods == nil || len(r.Spec.Route.Methods) == 0 {
		r.Spec.Route.Methods = []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE", "CONNECT"}
	}
	if r.Spec.Route.PathHandling == "" {
		r.Spec.Route.PathHandling = "v1"
	}
	if r.Spec.Route.HttpsRedirectStatusCode == nil {
		r.Spec.Route.HttpsRedirectStatusCode = new(int32)
		*r.Spec.Route.HttpsRedirectStatusCode = 426
	}
	if r.Spec.Route.RegexPriority == nil {
		r.Spec.Route.RegexPriority = new(int32)
		*r.Spec.Route.RegexPriority = 0
	}
	if r.Spec.Route.StripPath == nil {
		r.Spec.Route.StripPath = new(bool)
		*r.Spec.Route.StripPath = true
	}
	if r.Spec.Route.PreserveHost == nil {
		r.Spec.Route.PreserveHost = new(bool)
	}
	if r.Spec.Route.Protocols == nil || len(r.Spec.Route.Protocols) == 0 {
		r.Spec.Route.Protocols = []string{"http", "https"}
	}
}

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
//+kubebuilder:webhook:webhookVersions={v1beta1},path=/validate-kong-pyfdtic-com-v1-kongconfig,mutating=false,failurePolicy=fail,sideEffects=None,groups=kong.pyfdtic.com,resources=kongconfigs,verbs=create;update;delete,versions=v1,name=vkongconfig.kb.io,admissionReviewVersions={v1,v1beta1}

var _ webhook.Validator = &KongConfig{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (r *KongConfig) ValidateCreate() error {
	kongconfiglog.Info("validate create", "name", r.Name)

	// TODO(user): fill in your validation logic upon object creation.
	return nil
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *KongConfig) ValidateUpdate(old runtime.Object) error {
	kongconfiglog.Info("validate update", "name", r.Name)

	// TODO(user): fill in your validation logic upon object update.
	return nil
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *KongConfig) ValidateDelete() error {
	kongconfiglog.Info("validate delete", "name", r.Name)

	// TODO(user): fill in your validation logic upon object delete.
	return nil
}
