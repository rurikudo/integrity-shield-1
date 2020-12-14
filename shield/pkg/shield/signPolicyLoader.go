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

package shield

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	spolapi "github.com/IBM/integrity-enforcer/shield/pkg/apis/signpolicy/v1alpha1"
	spolclient "github.com/IBM/integrity-enforcer/shield/pkg/client/signpolicy/clientset/versioned/typed/signpolicy/v1alpha1"
	cache "github.com/IBM/integrity-enforcer/shield/pkg/util/cache"
	"github.com/IBM/integrity-enforcer/shield/pkg/util/kubeutil"
	logger "github.com/IBM/integrity-enforcer/shield/pkg/util/logger"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SignPolicy

type SignPolicyLoader struct {
	interval        time.Duration
	shieldNamespace string

	Client *spolclient.ApisV1alpha1Client
	Data   *spolapi.SignPolicy
}

func NewSignPolicyLoader(shieldNamespace string) *SignPolicyLoader {
	interval := time.Second * 10
	config, _ := kubeutil.GetKubeConfig()
	client, _ := spolclient.NewForConfig(config)

	return &SignPolicyLoader{
		interval:        interval,
		shieldNamespace: shieldNamespace,
		Client:          client,
	}
}

func (self *SignPolicyLoader) GetData(doK8sApiCall bool) *spolapi.SignPolicy {
	if self.Data == nil {
		self.Load(doK8sApiCall)
	}
	return self.Data
}

func (self *SignPolicyLoader) Load(doK8sApiCall bool) {
	var err error
	var list1 *spolapi.SignPolicyList
	var keyName string

	keyName = fmt.Sprintf("SignPolicyLoader/%s/list", self.shieldNamespace)
	if cached := cache.GetString(keyName); cached == "" && doK8sApiCall {
		list1, err = self.Client.SignPolicies(self.shieldNamespace).List(context.Background(), metav1.ListOptions{})
		if err != nil {
			logger.Error("failed to get SignPolicy:", err)
			return
		}
		logger.Debug("SignPolicy reloaded.")
		if len(list1.Items) > 0 {
			tmp, _ := json.Marshal(list1)
			cache.SetString(keyName, string(tmp), &(self.interval))
		}
	} else if cached != "" {
		err = json.Unmarshal([]byte(cached), &list1)
		if err != nil {
			logger.Error("failed to Unmarshal cached SignPolicy:", err)
			return
		}
	}

	data := &spolapi.SignPolicy{}
	if list1 != nil && len(list1.Items) > 0 {
		item := list1.Items[0]
		data.ObjectMeta = item.ObjectMeta
		data.Spec = item.Spec
	}
	self.Data = data
	return
}
