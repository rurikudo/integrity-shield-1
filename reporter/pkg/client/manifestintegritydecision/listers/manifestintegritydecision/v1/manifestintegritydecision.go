/*
Copyright The Kubernetes Authors.

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

// Code generated by lister-gen. DO NOT EDIT.

package v1

import (
	v1 "github.com/stolostron/integrity-shield/reporter/pkg/apis/manifestintegritydecision/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// ManifestIntegrityDecisionLister helps list ManifestIntegrityDecisions.
// All objects returned here must be treated as read-only.
type ManifestIntegrityDecisionLister interface {
	// List lists all ManifestIntegrityDecisions in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1.ManifestIntegrityDecision, err error)
	// ManifestIntegrityDecisions returns an object that can list and get ManifestIntegrityDecisions.
	ManifestIntegrityDecisions(namespace string) ManifestIntegrityDecisionNamespaceLister
	ManifestIntegrityDecisionListerExpansion
}

// manifestIntegrityDecisionLister implements the ManifestIntegrityDecisionLister interface.
type manifestIntegrityDecisionLister struct {
	indexer cache.Indexer
}

// NewManifestIntegrityDecisionLister returns a new ManifestIntegrityDecisionLister.
func NewManifestIntegrityDecisionLister(indexer cache.Indexer) ManifestIntegrityDecisionLister {
	return &manifestIntegrityDecisionLister{indexer: indexer}
}

// List lists all ManifestIntegrityDecisions in the indexer.
func (s *manifestIntegrityDecisionLister) List(selector labels.Selector) (ret []*v1.ManifestIntegrityDecision, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1.ManifestIntegrityDecision))
	})
	return ret, err
}

// ManifestIntegrityDecisions returns an object that can list and get ManifestIntegrityDecisions.
func (s *manifestIntegrityDecisionLister) ManifestIntegrityDecisions(namespace string) ManifestIntegrityDecisionNamespaceLister {
	return manifestIntegrityDecisionNamespaceLister{indexer: s.indexer, namespace: namespace}
}

// ManifestIntegrityDecisionNamespaceLister helps list and get ManifestIntegrityDecisions.
// All objects returned here must be treated as read-only.
type ManifestIntegrityDecisionNamespaceLister interface {
	// List lists all ManifestIntegrityDecisions in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1.ManifestIntegrityDecision, err error)
	// Get retrieves the ManifestIntegrityDecision from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1.ManifestIntegrityDecision, error)
	ManifestIntegrityDecisionNamespaceListerExpansion
}

// manifestIntegrityDecisionNamespaceLister implements the ManifestIntegrityDecisionNamespaceLister
// interface.
type manifestIntegrityDecisionNamespaceLister struct {
	indexer   cache.Indexer
	namespace string
}

// List lists all ManifestIntegrityDecisions in the indexer for a given namespace.
func (s manifestIntegrityDecisionNamespaceLister) List(selector labels.Selector) (ret []*v1.ManifestIntegrityDecision, err error) {
	err = cache.ListAllByNamespace(s.indexer, s.namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v1.ManifestIntegrityDecision))
	})
	return ret, err
}

// Get retrieves the ManifestIntegrityDecision from the indexer for a given namespace and name.
func (s manifestIntegrityDecisionNamespaceLister) Get(name string) (*v1.ManifestIntegrityDecision, error) {
	obj, exists, err := s.indexer.GetByKey(s.namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1.Resource("manifestintegritydecision"), name)
	}
	return obj.(*v1.ManifestIntegrityDecision), nil
}
