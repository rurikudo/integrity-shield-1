//
// Copyright 2020 IBM Corporation
//
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
//

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	cosign "github.com/sigstore/cosign/cmd/cosign/cli"
	log "github.com/sirupsen/logrus"
	k8smnfconfig "github.com/stolostron/integrity-shield/shield/pkg/config"
	"github.com/stolostron/integrity-shield/shield/pkg/shield"

	admission "k8s.io/api/admission/v1"
	// "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	tlsDir      = `/run/secrets/tls`
	tlsCertFile = `tls.crt`
	tlsKeyFile  = `tls.key`
)

const (
	apiVersion = "externaldata.gatekeeper.sh/v1alpha1"
	kind       = "ProviderResponse"
)

func init() {
	log.SetFormatter(&log.JSONFormatter{})
	log.Info("Integrity Shield has been started.")

	log.Info("initialize cosign.")
	//  "TUF_ROOT" is set to "/ishield-app/sigstore"
	_ = cosign.Initialize()
}

func defaultHandler(w http.ResponseWriter, r *http.Request) {
	errorHandler(w, r, http.StatusNotFound)
}

func errorHandler(w http.ResponseWriter, r *http.Request, status int) {
	w.WriteHeader(status)
	if status == http.StatusNotFound {
		fmt.Fprint(w, "Custom 404")
	}
}

func requestHandler(w http.ResponseWriter, r *http.Request) {
	log.Info("request received")
	response := externaldata.ProviderResponse{
		APIVersion: apiVersion,
		Kind:       kind,
		Response: externaldata.Response{
			Idempotent: true, // mutation requires idempotent results
		},
	}

	if r.Method != "POST" {
		w.WriteHeader(http.StatusBadRequest)
		SendResponse(nil, "only POST is allowed", w)
		return
	}

	if r.Header.Get("Content-Type") != "application/json" {
		w.WriteHeader(http.StatusBadRequest)
		SendResponse(nil, "only application/json content type is allowed", w)
		return
	}

	bufbody := new(bytes.Buffer)
	_, _ = bufbody.ReadFrom(r.Body)
	body := bufbody.Bytes()

	// parse request body
	var providerRequest externaldata.ProviderRequest
	err := json.Unmarshal(body, &providerRequest)
	if err != nil {
		// utils.SendResponse(nil, fmt.Sprintf("unable to unmarshal request body: %v", err), w)
		SendResponse(nil, fmt.Sprintf("unable to unmarshal request body: %v", err), w)
		return
	}

	key := providerRequest.Request.Keys[0]
	var inputMap map[string]interface{}
	var request *admission.AdmissionRequest
	var parameters *k8smnfconfig.ParameterObject

	if strings.HasSuffix(key, "_systemError") {
		SendResponse(nil, "testing system error", w)
		return
	}

	results := make([]externaldata.Item, 0)

	err = json.Unmarshal([]byte(key), &inputMap)
	if err != nil {
		http.Error(w, fmt.Sprintf("unmarshaling input data as map[string]interface{}: %v", err), http.StatusInternalServerError)
		response.Response.SystemError = fmt.Sprintf("unmarshaling input data as map[string]interface{}: %v", err)
		return
	}

	requestIf, requestFound := inputMap["request"]
	if !requestFound {
		http.Error(w, "failed to find `request` key in input object", http.StatusInternalServerError)
		return
	}
	if requestIf != nil {
		requestMap := requestIf.(map[string]interface{})
		requestBytes, _ := json.Marshal(requestMap)
		_ = json.Unmarshal(requestBytes, &request)
	}
	if request == nil {
		http.Error(w, fmt.Sprintf("failed to convert `request` in input object into %T", request), http.StatusInternalServerError)
		return
	}
	log.Infof("request has been parsed successfully, kind: %s, name: %s", request.Kind.Kind, request.Name)
	subKey := fmt.Sprintf("%s_%s", request.Kind.Kind, request.Name)

	parametersIf, parametersFound := inputMap["parameters"]
	if !parametersFound {
		http.Error(w, "failed to find `parameters` key in input object", http.StatusInternalServerError)
		return
	}
	if parametersIf != nil {
		parametersMap := parametersIf.(map[string]interface{})
		parametersBytes, _ := json.Marshal(parametersMap)
		_ = json.Unmarshal(parametersBytes, &parameters)
	}
	if parameters == nil {
		http.Error(w, fmt.Sprintf("failed to convert `parameters` in input object into %T", parameters), http.StatusInternalServerError)
		return
	}

	result := shield.RequestHandler(request, parameters)
	if !result.Allow {
		results = append(results, externaldata.Item{
			Key:   subKey,
			Error: result.Message,
		})
	} else {
		results = append(results, externaldata.Item{
			Key:   subKey,
			Value: result.Message,
		})
	}

	// resp, err := json.Marshal(result)
	// if err != nil {
	// 	http.Error(w, fmt.Sprintf("marshaling request handler result: %v", err), http.StatusInternalServerError)
	// 	return
	// }

	log.Infof("returning a response, allow: %v", result.Allow)
	// w.WriteHeader(http.StatusOK)
	// if _, err := w.Write(resp); err != nil {
	// 	http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
	// 	return
	// }
	SendResponse(&results, "", w)
}

func checkLiveness(w http.ResponseWriter, r *http.Request) {
	msg := "liveness ok"
	_, _ = w.Write([]byte(msg))
}

func checkReadiness(w http.ResponseWriter, r *http.Request) {
	msg := "readiness ok"
	_, _ = w.Write([]byte(msg))
}

func main() {
	tlsCertPath := path.Join(tlsDir, tlsCertFile)
	tlsKeyPath := path.Join(tlsDir, tlsKeyFile)

	pair, err := tls.LoadX509KeyPair(tlsCertPath, tlsKeyPath)

	if err != nil {
		panic(fmt.Sprintf("unable to load certs: %v", err))
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/api", defaultHandler)
	mux.HandleFunc("/api/request", requestHandler)
	mux.HandleFunc("/health/liveness", checkLiveness)
	mux.HandleFunc("/health/readiness", checkReadiness)

	serverObj := &http.Server{
		Addr:      ":8080",
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12},
		Handler:   mux,
	}

	if err := serverObj.ListenAndServeTLS("", ""); err != nil {
		panic(fmt.Sprintf("Fail to run integrity shield api: %v", err))
	}
}

// sendResponse sends back the response to Gatekeeper.
func SendResponse(results *[]externaldata.Item, systemErr string, w http.ResponseWriter) {
	response := externaldata.ProviderResponse{
		APIVersion: apiVersion,
		Kind:       kind,
		Response: externaldata.Response{
			Idempotent: true, // mutation requires idempotent results
		},
	}

	if results != nil {
		response.Response.Items = *results
	} else {
		response.Response.SystemError = systemErr
	}

	log.Info("sending response", "response", response)

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Error(err, "unable to encode response")
		os.Exit(1)
	}
}
