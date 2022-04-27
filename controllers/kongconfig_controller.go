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

package controllers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-logr/logr"
	"io/ioutil"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"math/rand"
	"net/http"
	"reflect"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"time"

	kongv1 "git.pyfdtic.com/sre/kong-config/api/v1"
)

var logp logr.Logger = log.FromContext(nil)

// KongConfigReconciler reconciles a KongConfig object
type KongConfigReconciler struct {
	client.Client
	Eventer record.EventRecorder
	Scheme  *runtime.Scheme
}

//+kubebuilder:rbac:groups=kong.pyfdtic.com,resources=kongconfigs,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=kong.pyfdtic.com,resources=kongconfigs/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=kong.pyfdtic.com,resources=kongconfigs/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// the KongConfig object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.10.0/pkg/reconcile
func (r *KongConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	kclog := log.FromContext(ctx)
	t := genRandTimeDuration(600)
	time.Sleep(200 * time.Millisecond) // 防止吧 kong 打挂
	kclog.Info("loop log", "name", "kongConfig")

	var kongConfig kongv1.KongConfig
	if err := r.Get(ctx, req.NamespacedName, &kongConfig); err != nil {
		kclog.Error(err, "unable to fetch kongConfig")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	kclog.Info("kongConfig statue",
		"serviceId", kongConfig.Status.ServiceId,
		"routeId", kongConfig.Status.RouteId)

	// finalizer
	kongFinalizerName := "kong.pyfdtic.com/finalizer"
	if kongConfig.ObjectMeta.DeletionTimestamp.IsZero() {
		if !containsString(kongConfig.GetFinalizers(), kongFinalizerName) {
			controllerutil.AddFinalizer(&kongConfig, kongFinalizerName)
			if err := r.Update(ctx, &kongConfig); err != nil {
				return ctrl.Result{}, err
			}
		}
	} else {
		// kongConfig is being deleted
		if containsString(kongConfig.GetFinalizers(), kongFinalizerName) {
			// delete external resources
			if err := r.deleteExternalResources(&kongConfig); err != nil {
				return ctrl.Result{}, err
			}
			// remove finalizer from kongConofig
			controllerutil.RemoveFinalizer(&kongConfig, kongFinalizerName)
			if err := r.Update(ctx, &kongConfig); err != nil {
				return ctrl.Result{}, err
			}
			r.Eventer.Eventf(&kongConfig, "Normal", "Delete",
				fmt.Sprintf("Delete KongConfig %s success", kongConfig.ObjectMeta.Name))
		}
		return ctrl.Result{}, nil
	}

	// Create or Update kong service : kong service/route name 需是唯一的.
	svcData := map[string]interface{}{
		"name":            kongConfig.Name,
		"tags":            kongConfig.Spec.Tags,
		"host":            kongConfig.Spec.Service.Host,
		"port":            kongConfig.Spec.Service.Port,
		"path":            kongConfig.Spec.Service.Path,
		"retries":         kongConfig.Spec.Service.Retries,
		"connect_timeout": kongConfig.Spec.Service.ConnectTimeout,
		"write_timeout":   kongConfig.Spec.Service.WriteTimeout,
		"read_timeout":    kongConfig.Spec.Service.ReadTimeout,
		"protocol":        kongConfig.Spec.Service.Protocol,
	}
	svcDataJson, _ := json.Marshal(svcData)
	svcReq, _ := http.NewRequest(http.MethodPut,
		fmt.Sprintf("%s/%s/%s", kongConfig.Spec.KongUrl, "services", kongConfig.Name),
		bytes.NewBuffer(svcDataJson))
	svcReq.Header.Set("Content-Type", "application/json")
	httpClient := &http.Client{}
	svcResp, err := httpClient.Do(svcReq)
	if err != nil {
		kclog.Error(err, "create/update kong service error", "postData", svcData)
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !(svcResp.StatusCode == 201 || svcResp.StatusCode == 200) {
		kclog.Error(err, fmt.Sprintf("create/update kong service error status code: %d, content: %v",
			svcResp.StatusCode, svcResp.Body),
			"svcData", svcData)
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	decoder := json.NewDecoder(svcResp.Body)
	defer svcResp.Body.Close()

	var svcBody map[string]interface{}
	err = decoder.Decode(&svcBody)
	if err != nil {
		kclog.Error(err, fmt.Sprintf("json response decode error: %v", err.Error()),
			"svcData", svcData)
		r.Eventer.Eventf(&kongConfig, "Warning", "CreateKongServiceFail",
			fmt.Sprintf("Create KongConfig Service %s Fail", kongConfig.ObjectMeta.Name))

		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	kclog.Info("create/update service result", "result", svcBody)
	kongConfig.Status.ServiceId = fmt.Sprintf("%s", svcBody["id"])
	kclog.Info("kongConfig update service status", "serviceId", kongConfig.Status.ServiceId)
	r.Eventer.Eventf(&kongConfig, "Normal", "CreateKongService",
		fmt.Sprintf("Create KongConfig Service %s@%s success", kongConfig.ObjectMeta.Name, kongConfig.Status.ServiceId))

	// create/update kong route
	if kongConfig.Status.ServiceId != "" {
		routeData := map[string]interface{}{
			"name":                       kongConfig.Name,
			"tags":                       kongConfig.Spec.Tags,
			"hosts":                      kongConfig.Spec.Route.Hosts,
			"paths":                      kongConfig.Spec.Route.Paths,
			"methods":                    kongConfig.Spec.Route.Methods,
			"path_handling":              kongConfig.Spec.Route.PathHandling,
			"https_redirect_status_code": kongConfig.Spec.Route.HttpsRedirectStatusCode,
			"regex_priority":             kongConfig.Spec.Route.RegexPriority,
			"strip_path":                 kongConfig.Spec.Route.StripPath,
			"preserve_host":              kongConfig.Spec.Route.PreserveHost,
			"protocols":                  kongConfig.Spec.Route.Protocols,
			"service":                    map[string]string{"id": kongConfig.Status.ServiceId},
		}
		routeDataJson, _ := json.Marshal(routeData)
		routeReq, _ := http.NewRequest("PUT",
			fmt.Sprintf("%s/%s/%s", kongConfig.Spec.KongUrl, "routes", kongConfig.Name),
			bytes.NewBuffer(routeDataJson))
		routeReq.Header.Set("Content-Type", "application/json")
		httpClient := &http.Client{}
		routeResp, err := httpClient.Do(routeReq)
		if err != nil {
			kclog.Error(err, "create kong route error")
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
		if !(routeResp.StatusCode == 201 || routeResp.StatusCode == 200) {
			kclog.Error(err,
				fmt.Sprintf("create kong route error status code: %d, content: %v", routeResp.StatusCode, routeResp.Body),
				"routeData", routeData)
			r.Eventer.Eventf(&kongConfig, "Warning", "CreateKongRouteFail",
				fmt.Sprintf("Create KongConfig Route %s Fail", kongConfig.ObjectMeta.Name))
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
		routeDecoder := json.NewDecoder(routeResp.Body)
		defer routeResp.Body.Close()

		var routeBody map[string]interface{}
		err = routeDecoder.Decode(&routeBody)
		if err != nil {
			kclog.Error(err, fmt.Sprintf("json response decode error: %v", err.Error()))
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
		kongConfig.Status.RouteId = fmt.Sprintf("%s", routeBody["id"])
		kclog.Info("update/create route done", "route", kongConfig.Name,
			"routeId", kongConfig.Status.RouteId)
		r.Eventer.Eventf(&kongConfig, "Normal", "CreateKongRouteSuccess",
			fmt.Sprintf("Create KongConfig Route %s@%s Success", kongConfig.ObjectMeta.Name, kongConfig.Status.RouteId))
	}

	if err := r.Status().Update(ctx, &kongConfig); err != nil {
		kclog.Error(err, "unable to update KongConfig status")
		return ctrl.Result{}, err
	}

	// route plugins
	if !reflect.DeepEqual(kongConfig.Spec.Route.Plugins, kongv1.KongPlugins{}) && kongConfig.Status.RouteId != "" {
		var err error
		if err = CreateOrUpdateCors(&kongConfig, r.Eventer); err != nil {
			kclog.Error(err, fmt.Sprintf("create or update %s plugin error !!!", kongv1.KP_CORS))
			return ctrl.Result{}, err
		}

		//if err = CreateOrUpdateIpRestriction(&kongConfig, r.Eventer); err != nil {
		//	kclog.Error(err, fmt.Sprintf("create or update %s plugin error !!!", kongv1.KP_IP_RESTRICTION))
		//	return ctrl.Result{}, err
		//}
		//
		//if err = CreateOrUpdateJwt(&kongConfig, r.Eventer); err != nil {
		//	kclog.Error(err, fmt.Sprintf("create or update %s plugin error !!!", kongv1.KP_JWT))
		//	return ctrl.Result{}, err
		//}
		//
		//if err = CreateOrUpdateRequestTermination(&kongConfig, r.Eventer); err != nil {
		//	kclog.Error(err, fmt.Sprintf("create or update %s plugin error !!!", kongv1.KP_REQUEST_TERMINATION))
		//	return ctrl.Result{}, err
		//}
		//
		//if err = CreateOrUpdateRateLimiting(&kongConfig, r.Eventer); err != nil {
		//	kclog.Error(err, fmt.Sprintf("create or update %s plugin error !!!", kongv1.KP_RATE_LIMITING))
		//	return ctrl.Result{}, err
		//}
		//
		//if err = CreateOrUpdateKeyAuth(&kongConfig, r.Eventer); err != nil {
		//	kclog.Error(err, fmt.Sprintf("create or update %s plugin error !!!", kongv1.KP_KEY_AUTH))
		//	return ctrl.Result{}, err
		//}
	}
	kclog.Info(fmt.Sprintf("RequeueAfter: %v", t))
	return ctrl.Result{RequeueAfter: t}, nil
}

func (r *KongConfigReconciler) deleteExternalResources(kc *kongv1.KongConfig) error {
	return kc.DeleteRouteAndService(kc.Spec.KongUrl)
}

type KongPluginCommonSchema struct {
	CreateAt  *int32                 `json:"create_at,omitempty"`
	Id        string                 `json:"id,omitempty"`
	Tags      []string               `json:"tags,omitempty"`
	Enabled   bool                   `json:"enabled"`
	Protocols []string               `json:"protocols"`
	Name      string                 `json:"name"`
	Consumer  map[string]string      `json:"consumer,omitempty"`
	Service   map[string]string      `json:"service"`
	Route     map[string]string      `json:"route"`
	Config    map[string]interface{} `json:"config"`
}

type KongPluginsListResponse struct {
	Next string `json:"next"`
	Data []KongPluginCommonSchema
}

func IsKongPluginExist(kc *kongv1.KongConfig, t, pn string) (bool, string) {
	// t : type, services/routes
	// pn: plugin name
	// return: pluginId, isExist
	isExist := false
	url := fmt.Sprintf("%s/%s/%s/%s", kc.Spec.KongUrl, t, kc.ObjectMeta.Name, "plugins")
	resp, err := http.Get(url)
	if err != nil {
		return isExist, ""
	}
	defer resp.Body.Close()

	var plugins KongPluginsListResponse
	body, _ := ioutil.ReadAll(resp.Body)
	_ = json.Unmarshal(body, &plugins)
	for _, p := range plugins.Data {
		if p.Name == pn {
			return true, p.Id
		}
	}
	return isExist, ""
}

func CreateOrUpdatePlugin(
	kc *kongv1.KongConfig,
	pn string,
	pluginConfig map[string]interface{},
	isPluginStructEmpty bool,
	isPluginEnable *bool,
	eventer record.EventRecorder) error {

	logp.Info(fmt.Sprintf("createOrUpdatePlugins: %s", pn))
	isExist, plId := IsKongPluginExist(kc, "routes", pn)
	eventer.Eventf(kc, "Normal", "PluginExists",
		fmt.Sprintf("Kong route %s plugin %s exist %t, id: %s", kc.Name, pn, isExist, plId))
	logp.Info(fmt.Sprintf("is %s plugin exist: %v, %s", pn, isExist, plId))

	// if exist and (enable or not) -> update
	if isExist && isPluginStructEmpty {
		// delete
		url := fmt.Sprintf("%s/routes/%s/plugins/%s", kc.Spec.KongUrl, kc.ObjectMeta.Name, plId)
		req, _ := http.NewRequest(http.MethodDelete, url, nil)
		httpClient := &http.Client{}
		resp, err := httpClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != 204 {
			eventer.Eventf(kc, "Warning", "DeletePluginFail",
				fmt.Sprintf("Kong route %s delete plugin %s Fail", kc.Name, pn))
			return errors.New(fmt.Sprintf("Delete Plugin %s error: %d", pn, resp.StatusCode))
		}
		eventer.Eventf(kc, "Normal", "DeletePluginSucess",
			fmt.Sprintf("Kong route %s delete plugin %s success", kc.Name, pn))
	}

	// if not exist and enable -> create
	if !isPluginStructEmpty {
		logp.Info(fmt.Sprintf("Create/Update kong %s plugin, route: %s.", pn, kc.ObjectMeta.Name))
		// post for create
		method := http.MethodPost
		url := fmt.Sprintf("%s/routes/%s/plugins", kc.Spec.KongUrl, kc.ObjectMeta.Name)
		statusCode := 201

		if isExist { // patch for update
			method = http.MethodPatch
			url = fmt.Sprintf("%s/routes/%s/plugins/%s", kc.Spec.KongUrl, kc.ObjectMeta.Name, plId)
			statusCode = 200
		}

		logp.Info(fmt.Sprintf("plugin: %s, method: %s, url: %s, statusCode: %d", pn, method, url, statusCode))

		pluginConfig := map[string]interface{}{
			"name":      pn,
			"enabled":   isPluginEnable,
			"protocols": []string{"grpc", "grpcs", "http", "https"},
			"config":    pluginConfig,
			"route":     map[string]string{"id": kc.Status.RouteId},
			"tags":      kc.Spec.Tags,
		}

		config, _ := json.Marshal(pluginConfig)
		req, _ := http.NewRequest(method, url, bytes.NewBuffer(config))
		req.Header.Set("Content-Type", "application/json")

		httpClient := &http.Client{}
		resp, err := httpClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		var respData interface{}
		json.NewDecoder(resp.Body).Decode(respData)
		logp.Info(fmt.Sprintf("%d %v", resp.StatusCode, respData))
		if resp.StatusCode != statusCode {
			eventer.Eventf(kc, "Normal", "UpdatePluginFail",
				fmt.Sprintf("Kong route %s create/update plugin %s fail", kc.Name, pn))
			return errors.New(fmt.Sprintf("create/update kong %s plugins error: %d, %v",
				pn, resp.StatusCode, pluginConfig))
		}
		eventer.Eventf(kc, "Normal", "UpdatePluginSuccess",
			fmt.Sprintf("Kong route %s create/update plugin %s success", kc.Name, pn))
	}

	return nil
}

func CreateOrUpdateCors(kc *kongv1.KongConfig, eventer record.EventRecorder) error {
	pn := kongv1.KP_CORS
	isPluginStructEmpty := reflect.DeepEqual(kc.Spec.Route.Plugins.Cors, kongv1.KongPluginCORS{})
	pluginConfig := map[string]interface{}{
		"methods":            kc.Spec.Route.Plugins.Cors.Methods,
		"exposed_headers":    kc.Spec.Route.Plugins.Cors.ExposedHeaders,
		"max_age":            kc.Spec.Route.Plugins.Cors.MaxAge,
		"headers":            kc.Spec.Route.Plugins.Cors.Headers,
		"origins":            kc.Spec.Route.Plugins.Cors.Origins,
		"credentials":        kc.Spec.Route.Plugins.Cors.Credentials,
		"preflight_continue": kc.Spec.Route.Plugins.Cors.PreflightContinue,
	}
	return CreateOrUpdatePlugin(kc, pn, pluginConfig, isPluginStructEmpty, kc.Spec.Route.Plugins.Cors.Enabled, eventer)
}

func CreateOrUpdateIpRestriction(kc *kongv1.KongConfig, eventer record.EventRecorder) error {
	pn := kongv1.KP_IP_RESTRICTION
	isPluginStructEmpty := reflect.DeepEqual(kc.Spec.Route.Plugins.IpRestriction, kongv1.KongPluginIpRestriction{})
	pluginConfig := map[string]interface{}{
		"allow": kc.Spec.Route.Plugins.IpRestriction.Allow,
		"deny":  kc.Spec.Route.Plugins.IpRestriction.Deny,
	}
	return CreateOrUpdatePlugin(kc, pn, pluginConfig, isPluginStructEmpty, kc.Spec.Route.Plugins.IpRestriction.Enabled, eventer)
}

func CreateOrUpdateJwt(kc *kongv1.KongConfig, eventer record.EventRecorder) error {
	pn := kongv1.KP_JWT
	isPluginStructEmpty := reflect.DeepEqual(kc.Spec.Route.Plugins.Jwt, kongv1.KongPluginJwt{})
	pluginConfig := map[string]interface{}{
		"secret_is_base64":   kc.Spec.Route.Plugins.Jwt.SecretIsBase64,
		"run_on_preflight":   kc.Spec.Route.Plugins.Jwt.RunOnPreflight,
		"uri_param_names":    kc.Spec.Route.Plugins.Jwt.UriParamNames,
		"key_claim_name":     kc.Spec.Route.Plugins.Jwt.KeyClaimName,
		"header_names":       kc.Spec.Route.Plugins.Jwt.HeaderNames,
		"maximum_expiration": kc.Spec.Route.Plugins.Jwt.MaximumExpiration,
	}

	if kc.Spec.Route.Plugins.Jwt.Anonymous != "" {
		pluginConfig["anonymous"] = kc.Spec.Route.Plugins.Jwt.Anonymous
	}
	if kc.Spec.Route.Plugins.Jwt.ClaimsToVerify != "" {
		pluginConfig["claims_to_verify"] = kc.Spec.Route.Plugins.Jwt.ClaimsToVerify
	}
	if len(kc.Spec.Route.Plugins.Jwt.CookieNames) > 0 {
		pluginConfig["cookie_names"] = kc.Spec.Route.Plugins.Jwt.CookieNames
	}

	return CreateOrUpdatePlugin(kc, pn, pluginConfig, isPluginStructEmpty, kc.Spec.Route.Plugins.Jwt.Enabled, eventer)
}

func CreateOrUpdateRequestTermination(kc *kongv1.KongConfig, eventer record.EventRecorder) error {
	pn := kongv1.KP_REQUEST_TERMINATION
	isPluginStructEmpty := reflect.DeepEqual(kc.Spec.Route.Plugins.RequestTermination, kongv1.KongPluginRequestTermination{})
	pluginConfig := map[string]interface{}{
		"status_code": kc.Spec.Route.Plugins.RequestTermination.StatusCode,
		//"content_type": kc.Spec.Route.Plugins.RequestTermination.ContentType,
		//"body":         kc.Spec.Route.Plugins.RequestTermination.Body,
		//"message":      kc.Spec.Route.Plugins.RequestTermination.Message,
	}

	if kc.Spec.Route.Plugins.RequestTermination.ContentType != "" && kc.Spec.Route.Plugins.RequestTermination.Body != "" {
		pluginConfig["content_type"] = kc.Spec.Route.Plugins.RequestTermination.ContentType
		pluginConfig["body"] = kc.Spec.Route.Plugins.RequestTermination.Body
	}
	if kc.Spec.Route.Plugins.RequestTermination.Message != "" {
		pluginConfig["message"] = kc.Spec.Route.Plugins.RequestTermination.Message
	}

	return CreateOrUpdatePlugin(kc, pn, pluginConfig, isPluginStructEmpty, kc.Spec.Route.Plugins.RequestTermination.Enabled, eventer)
}

func CreateOrUpdateRateLimiting(kc *kongv1.KongConfig, eventer record.EventRecorder) error {
	pn := kongv1.KP_RATE_LIMITING
	isPluginStructEmpty := reflect.DeepEqual(kc.Spec.Route.Plugins.RateLimiting, kongv1.KongPluginRateLimiting{})
	pluginConfig := map[string]interface{}{
		"hide_client_headers": kc.Spec.Route.Plugins.RateLimiting.HideClientHeaders,
		"policy":              kc.Spec.Route.Plugins.RateLimiting.Policy,
		"limit_by":            kc.Spec.Route.Plugins.RateLimiting.LimitBy,
		//"header_name":         kc.Spec.Route.Plugins.RateLimiting.HeaderName,
		"fault_tolerant": kc.Spec.Route.Plugins.RateLimiting.FaultTolerant,

		//"year":   kc.Spec.Route.Plugins.RateLimiting.Year,
		//"month":  kc.Spec.Route.Plugins.RateLimiting.Month,
		//"day":    kc.Spec.Route.Plugins.RateLimiting.Day,
		//"hour":   kc.Spec.Route.Plugins.RateLimiting.Hour,
		//"minute": kc.Spec.Route.Plugins.RateLimiting.Minute,
		//"second": kc.Spec.Route.Plugins.RateLimiting.Second,

		//"redis_host":     kc.Spec.Route.Plugins.RateLimiting.RedisHost,
		//"redis_port":     kc.Spec.Route.Plugins.RateLimiting.RedisPort,
		//"redis_database": kc.Spec.Route.Plugins.RateLimiting.RedisDatabase,
		//"redis_password": kc.Spec.Route.Plugins.RateLimiting.RedisPassword,
		//"redis_timeout": kc.Spec.Route.Plugins.RateLimiting.RedisTimeout,
	}

	if kc.Spec.Route.Plugins.RateLimiting.HeaderName != "" {
		pluginConfig["header_name"] = kc.Spec.Route.Plugins.RateLimiting.HeaderName
	}

	if kc.Spec.Route.Plugins.RateLimiting.RedisHost != "" {
		pluginConfig["redis_host"] = kc.Spec.Route.Plugins.RateLimiting.RedisHost
	}
	if kc.Spec.Route.Plugins.RateLimiting.RedisPort != nil {
		pluginConfig["redis_port"] = kc.Spec.Route.Plugins.RateLimiting.RedisPort
	}
	if kc.Spec.Route.Plugins.RateLimiting.RedisDatabase != nil {
		pluginConfig["redis_database"] = kc.Spec.Route.Plugins.RateLimiting.RedisDatabase
	}
	if kc.Spec.Route.Plugins.RateLimiting.RedisPassword != "" {
		pluginConfig["redis_password"] = kc.Spec.Route.Plugins.RateLimiting.RedisPassword
	}
	if kc.Spec.Route.Plugins.RateLimiting.RedisTimeout != nil {
		pluginConfig["redis_timeout"] = kc.Spec.Route.Plugins.RateLimiting.RedisTimeout
	}

	if kc.Spec.Route.Plugins.RateLimiting.Year != nil {
		pluginConfig["year"] = kc.Spec.Route.Plugins.RateLimiting.Year
	}
	if kc.Spec.Route.Plugins.RateLimiting.Month != nil {
		pluginConfig["month"] = kc.Spec.Route.Plugins.RateLimiting.Month
	}
	if kc.Spec.Route.Plugins.RateLimiting.Day != nil {
		pluginConfig["day"] = kc.Spec.Route.Plugins.RateLimiting.Day
	}
	if kc.Spec.Route.Plugins.RateLimiting.Hour != nil {
		pluginConfig["hour"] = kc.Spec.Route.Plugins.RateLimiting.Hour
	}
	if kc.Spec.Route.Plugins.RateLimiting.Minute != nil {
		pluginConfig["minute"] = kc.Spec.Route.Plugins.RateLimiting.Minute
	}
	if kc.Spec.Route.Plugins.RateLimiting.Second != nil {
		pluginConfig["second"] = kc.Spec.Route.Plugins.RateLimiting.Second
	}

	return CreateOrUpdatePlugin(kc, pn, pluginConfig, isPluginStructEmpty, kc.Spec.Route.Plugins.RateLimiting.Enabled, eventer)
}

func CreateOrUpdateKeyAuth(kc *kongv1.KongConfig, eventer record.EventRecorder) error {
	pn := kongv1.KP_KEY_AUTH
	isPluginStructEmpty := reflect.DeepEqual(kc.Spec.Route.Plugins.KeyAuth, kongv1.KongPluginKeyAuth{})
	pluginConfig := map[string]interface{}{
		"key_names":        kc.Spec.Route.Plugins.KeyAuth.KeyNames,
		"run_on_preflight": kc.Spec.Route.Plugins.KeyAuth.RunOnPreflight,
		//"anonymous":        kc.Spec.Route.Plugins.KeyAuth.Anonymous,
		"hide_credentials": kc.Spec.Route.Plugins.KeyAuth.HideCredentials,
		"key_in_body":      kc.Spec.Route.Plugins.KeyAuth.KeyInBody,
	}

	if kc.Spec.Route.Plugins.KeyAuth.Anonymous != "" {
		pluginConfig["anonymous"] = kc.Spec.Route.Plugins.KeyAuth.Anonymous
	}

	return CreateOrUpdatePlugin(kc, pn, pluginConfig, isPluginStructEmpty, kc.Spec.Route.Plugins.KeyAuth.Enabled, eventer)
}

// Helper functions to check and remove string from a slice of strings.
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func genRandTimeDuration(r int) time.Duration {
	// 生成 大于120 的随机秒数
	tBase := 120
	r1 := rand.New(rand.NewSource(time.Now().UnixNano()))
	return time.Duration(r1.Intn(r)+tBase) * time.Second
}

// SetupWithManager sets up the controller with the Manager.
func (r *KongConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&kongv1.KongConfig{}).
		Complete(r)
}
