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
	"errors"
	"fmt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net/http"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

const (
	// kong plugins
	KP_CORS                string = "cors"
	KP_REQUEST_TERMINATION string = "request-termination"
	KP_RATE_LIMITING       string = "rate-limiting"
	KP_KEY_AUTH            string = "key-auth"
	KP_JWT                 string = "jwt"
	KP_IP_RESTRICTION      string = "ip-restriction"
)

type KongServiceConfig struct {
	Host           string `json:"host"`
	Port           *int32 `json:"port,omitempty"`           // default 80
	Path           string `json:"path,omitempty"`           // default empty
	Protocol       string `json:"protocol,omitempty"`       // default http
	Retries        *int32 `json:"retries,omitempty"`        // default 5
	ConnectTimeout *int32 `json:"connectTimeout,omitempty"` // default 60000
	WriteTimeout   *int32 `json:"writeTimeout,omitempty"`   // default 60000
	ReadTimeout    *int32 `json:"readTimeout,omitempty"`    // default 60000
}

type KongRouteConfig struct {
	Hosts                   []string    `json:"hosts"`
	Paths                   []string    `json:"paths"`
	Methods                 []string    `json:"methods,omitempty"`                 // default all http methods
	PathHandling            string      `json:"pathHandling,omitempty"`            // default v1
	HttpsRedirectStatusCode *int32      `json:"httpsRedirectStatusCode,omitempty"` // default 426
	RegexPriority           *int32      `json:"regexPriority,omitempty"`           // default 0
	StripPath               *bool       `json:"stripPath,omitempty"`               // default True
	PreserveHost            *bool       `json:"preserveHost,omitempty"`            // default False
	Protocols               []string    `json:"protocols,omitempty"`               // default ["http", "https"]
	Plugins                 KongPlugins `json:"plugins,omitempty"`                 // only support route plugin
}

type KongPlugins struct {
	Cors               KongPluginCORS               `json:"cors,omitempty"`
	IpRestriction      KongPluginIpRestriction      `json:"ipRestriction,omitempty"`
	Jwt                KongPluginJwt                `json:"jwt,omitempty"`
	RequestTermination KongPluginRequestTermination `json:"requestTermination,omitempty"`
	KeyAuth            KongPluginKeyAuth            `json:"keyAuth,omitempty"`
	RateLimiting       KongPluginRateLimiting       `json:"rateLimiting,omitempty"`
}

type KongPluginCORS struct {
	Enabled           *bool    `json:"enabled,omitempty"`           // default true
	Methods           []string `json:"methods,omitempty"`           // default ["GET", "HEAD", "PUT", "PATCH", "POST", "DELETE", "OPTIONS", "TRACE", "CONNECT"]
	ExposedHeaders    []string `json:"exposedHeaders,omitempty"`    // default null
	Headers           []string `json:"headers,omitempty"`           // default null
	MaxAge            *int32   `json:"maxAge,omitempty"`            // default null, Indicated how long the results of the preflight request can be cached, in seconds.
	Credentials       *bool    `json:"credentials,omitempty"`       // default false
	PreflightContinue *bool    `json:"preflightContinue,omitempty"` // default false
	Origins           []string `json:"origins,omitempty"`           // default ["*"]
}

type KongPluginIpRestriction struct {
	Enabled *bool    `json:"enabled,omitempty"` // default true
	Allow   []string `json:"allow,omitempty"`   // default []
	Deny    []string `json:"deny,omitempty"`    // default []
}

type KongPluginJwt struct {
	Enabled           *bool    `json:"enabled,omitempty"`           // default true
	SecretIsBase64    *bool    `json:"secretIsBase64,omitempty"`    // default false
	RunOnPreflight    *bool    `json:"runOnPreflight,omitempty"`    // default true
	UriParamNames     []string `json:"uriParamNames,omitempty"`     // default jwt
	KeyClaimName      string   `json:"keyClaimName,omitempty"`      // default iss
	HeaderNames       []string `json:"headerNames,omitempty"`       // default authorization,
	MaximumExpiration *int32   `json:"maximumExpiration,omitempty"` // default 0
	Anonymous         string   `json:"anonymous,omitempty"`         // default null
	ClaimsToVerify    string   `json:"claimsToVerify,omitempty"`    // default null
	CookieNames       []string `json:"cookieNames,omitempty"`       // default []
}

type KongPluginRequestTermination struct {
	Enabled     *bool  `json:"enabled,omitempty"`     // default true
	StatusCode  *int32 `json:"statusCode,omitempty"`  // default 503
	ContentType string `json:"contentType,omitempty"` // default null
	Body        string `json:"body,omitempty"`        // default ""
	Message     string `json:"message,omitempty"`     // default null
}

type KongPluginRateLimiting struct {
	Enabled           *bool  `json:"enabled,omitempty"`           // default true
	HideClientHeaders *bool  `json:"hideClientHeaders,omitempty"` // default false
	Policy            string `json:"policy,omitempty"`            // default cluster, 存储位置: cluter 数据库 全局共享， redis 全局共享，local：节点内存。
	LimitBy           string `json:"limitBy,omitempty"`           // default ip, 可选：ip,service,header,credential,consumer
	HeaderName        string `json:"headerName,omitempty"`        // default null
	FaultTolerant     *bool  `json:"faultTolerant,omitempty"`     // default true

	RedisHost     string `json:"redisHost,omitempty"`     // default null
	RedisPort     *int32 `json:"redisPort,omitempty"`     // default 6379
	RedisDatabase *int32 `json:"redisDatabase,omitempty"` // default 0
	RedisPassword string `json:"redisPassword,omitempty"` // default null
	RedisTimeout  *int32 `json:"redisTimeout,omitempty"`  // default 2000

	Year   *int32 `json:"year,omitempty"`   // default null, 每年可请求数
	Month  *int32 `json:"month,omitempty"`  // default null, 每月可请求数
	Day    *int32 `json:"day,omitempty"`    // default null, 每日可请求数
	Hour   *int32 `json:"hour,omitempty"`   // default null, 每时可请求数
	Minute *int32 `json:"minute,omitempty"` // default null, 每分可请求数
	Second *int32 `json:"second,omitempty"` // default null, 每秒可请求数
}

type KongPluginKeyAuth struct {
	Enabled         *bool    `json:"enabled,omitempty"` // default true
	KeyNames        []string `json:"keyNames,omitempty"`
	RunOnPreflight  *bool    `json:"runOnPreflight,omitempty"`  // default true
	Anonymous       string   `json:"anonymous,omitempty"`       // default null
	HideCredentials *bool    `json:"hideCredentials,omitempty"` // default false
	KeyInBody       *bool    `json:"KeyInBody,omitempty"`       // default false
}

// KongConfigSpec defines the desired state of KongConfig
type KongConfigSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	Service KongServiceConfig `json:"service"`
	Route   KongRouteConfig   `json:"route"`
	KongUrl string            `json:"kongUrl"`
	Tags    []string          `json:"tags,omitempty"` // default empty
}

// KongConfigStatus defines the observed state of KongConfig
type KongConfigStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// +optional
	ServiceId string `json:"serviceId,omitempty"`

	// +optional
	RouteId string `json:"routeId,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// KongConfig is the Schema for the kongconfigs API
type KongConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KongConfigSpec   `json:"spec,omitempty"`
	Status KongConfigStatus `json:"status,omitempty"`
}

func (kc *KongConfig) IsKongObjectExist(kongUrl, t string) bool {
	isExist := false

	url := fmt.Sprintf("%s/%s/%s", kongUrl, t, kc.ObjectMeta.Name)
	resp, _ := http.Get(url)
	if resp.StatusCode == 200 {
		isExist = true
	}
	defer resp.Body.Close()
	return isExist
}

func (kc *KongConfig) IsServiceExist(kongUrl string) bool {
	return kc.IsKongObjectExist(kongUrl, "services")
}

func (kc *KongConfig) IsRouteExist(kongUrl string) bool {
	return kc.IsKongObjectExist(kongUrl, "routes")
}

func (kc *KongConfig) DeleteRouteAndService(kongUrl string) error {
	if kc.IsRouteExist(kongUrl) {
		if err := kc.DeleteKongRoute(kongUrl); err != nil {
			return err
		}
	}

	if kc.IsServiceExist(kongUrl) {
		if err := kc.DeleteKongService(kongUrl); err != nil {
			return err
		}
	}
	return nil
}

func (kc *KongConfig) DeleteKongObject(kongUrl, t string) error {
	url := fmt.Sprintf("%s/%s/%s", kongUrl, t, kc.ObjectMeta.Name)
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 204 {
		return nil
	}

	return errors.New(fmt.Sprintf("error delete %s %s, response code: %v", t, kc.ObjectMeta.Name, resp.StatusCode))
}

func (kc *KongConfig) DeleteKongService(kongUrl string) error {
	return kc.DeleteKongObject(kongUrl, "services")
}

func (kc *KongConfig) DeleteKongRoute(kongUrl string) error {
	return kc.DeleteKongObject(kongUrl, "routes")
}

//+kubebuilder:object:root=true

// KongConfigList contains a list of KongConfig
type KongConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KongConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KongConfig{}, &KongConfigList{})
}
