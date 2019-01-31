package gitlab

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"testing"

	"github.com/sourcegraph/sourcegraph/cmd/frontend/auth"
	"github.com/sourcegraph/sourcegraph/cmd/frontend/authz"
	"github.com/sourcegraph/sourcegraph/pkg/api"
	"github.com/sourcegraph/sourcegraph/pkg/extsvc"
	"github.com/sourcegraph/sourcegraph/pkg/extsvc/gitlab"
	"github.com/sourcegraph/sourcegraph/schema"
	"golang.org/x/oauth2"
)

// mockGitLab is a mock for the GitLab client that can be used by tests. Instantiating a mockGitLab
// instance itself does nothing, but its methods can be used to replace the mock functions (e.g.,
// MockListProjects).
//
// We prefer to do it this way, instead of defining an interface for the GitLab client, because this
// preserves the ability to jump-to-def around the actual implementation.
type mockGitLab struct {
	t *testing.T

	// projs is a map of all projects on the instance, keyed by project ID
	projs map[int]*gitlab.Project

	// privateRepo is a map from GitLab user ID to list of repo-content-accessible private project IDs on GitLab.
	// Projects in each list are also metadata-accessible.
	privateRepo map[string][]int

	// privateGuest is a map from GitLab user ID to list of metadata-accessible private project IDs on GitLab
	privateGuest map[string][]int

	// oauthToks is a map from OAuth token to GitLab user account ID
	oauthToks map[string]string

	// maxPerPage returns the max per_page value for the instance
	maxPerPage int

	// madeProjectReqs records how many ListProjects requests were made by url string and oauth
	// token
	madeProjectReqs map[string]map[string]int
}

// newMockGitLab returns a new mockGitLab instance
func newMockGitLab(
	t *testing.T, publicProjs []int, internalProjs []int, privateGuest, privateRepo map[int][]string,
	oauthToks map[string]string, maxPerPage int,
) mockGitLab {
	// NEXT

	projs := make(map[int]*gitlab.Project)
	privateACL := make(map[string][]int)
	for _, p := range publicProjs {
		projs[p] = &gitlab.Project{Visibility: gitlab.Public, ProjectCommon: gitlab.ProjectCommon{ID: p}}
	}
	for _, p := range internalProjs {
		projs[p] = &gitlab.Project{Visibility: gitlab.Internal, ProjectCommon: gitlab.ProjectCommon{ID: p}}
	}
	for p, userIDs := range privateProjs {
		projs[p] = &gitlab.Project{Visibility: gitlab.Private, ProjectCommon: gitlab.ProjectCommon{ID: p}}
		for _, u := range userIDs {
			privateACL[u] = append(privateACL[u], u)
		}
	}
	return mockGitLab{
		t:               t,
		projs:           projs,
		privateACL:      privateACL,
		oauthToks:       oauthToks,
		maxPerPage:      maxPerPage,
		madeProjectReqs: make(map[string]map[string]int),
	}
}

func (m *mockGitLab) GetProject(c *gitlab.Client, ctx context.Context, op gitlab.GetProjectOp) (*Project, error) {
	proj, ok := m.projs[op.ID]
	if !ok {
		return nil, gitlab.ErrNotFound
	}

	if proj.Visibility == gitlab.Public {
		return proj, nil
	}

	acctID := m.oauthToks[c.OAuthToken]
	for _, accessibleProjID := range m.privateACL[acctID] {
		if accessibleProjID == op.ID {
			return proj, nil
		}
	}
	return nil, gitlab.ErrNotFound
}

func (m *mockGitLab) ListTree(ctx context.Context, op gitlab.ListTreeOp) ([]*Tree, error) {
	// TODO
}

// func (m *mockGitLab) ListProjects(c *gitlab.Client, ctx context.Context, urlStr string) (proj []*gitlab.Project, nextPageURL *string, err error) {
// 	if m.madeProjectReqs[urlStr] == nil {
// 		m.madeProjectReqs[urlStr] = make(map[string]int)
// 	}
// 	m.madeProjectReqs[urlStr][c.OAuthToken]++

// 	u, err := url.Parse(urlStr)
// 	if err != nil {
// 		m.t.Fatalf("could not parse ListProjects urlStr %q: %s", urlStr, err)
// 	}
// 	acceptedQ := map[string]struct{}{"page": {}, "per_page": {}}
// 	for k := range u.Query() {
// 		if _, ok := acceptedQ[k]; !ok {
// 			m.t.Fatalf("mockGitLab unable to handle urlStr %q", urlStr)
// 		}
// 	}

// 	acctID := m.oauthToks[c.OAuthToken]
// 	var repoIDs []int
// 	if acctID == "" {
// 		repoIDs = m.acls["PUBLIC"]
// 	} else {
// 		repoIDs = m.acls[acctID]
// 	}

// 	allProjs := make([]*gitlab.Project, len(repoIDs))
// 	for i, repoID := range repoIDs {
// 		proj, ok := m.projs[repoID]
// 		if !ok {
// 			m.t.Fatalf("Dangling project reference in mockGitLab: %d", repoID)
// 		}
// 		allProjs[i] = proj
// 	}

// 	// pagination
// 	perPage, err := getIntOrDefault(u.Query().Get("per_page"), m.maxPerPage)
// 	if err != nil {
// 		return nil, nil, err
// 	}
// 	if perPage > m.maxPerPage {
// 		perPage = m.maxPerPage
// 	}
// 	page, err := getIntOrDefault(u.Query().Get("page"), 1)
// 	if err != nil {
// 		return nil, nil, err
// 	}
// 	p := page - 1
// 	var (
// 		pagedProjs []*gitlab.Project
// 	)
// 	if perPage*p > len(allProjs)-1 {
// 		pagedProjs = nil
// 	} else if perPage*(p+1) > len(allProjs)-1 {
// 		pagedProjs = allProjs[perPage*p:]
// 	} else {
// 		pagedProjs = allProjs[perPage*p : perPage*(p+1)]
// 		if perPage*(p+1) <= len(allProjs)-1 {
// 			newU := *u
// 			q := u.Query()
// 			q.Set("page", strconv.Itoa(page+1))
// 			newU.RawQuery = q.Encode()
// 			s := newU.String()
// 			nextPageURL = &s
// 		}
// 	}
// 	return pagedProjs, nextPageURL, nil
// }

type mockCache map[string]string

func (m mockCache) Get(key string) ([]byte, bool) {
	v, ok := m[key]
	return []byte(v), ok
}
func (m mockCache) Set(key string, b []byte) {
	m[key] = string(b)
}
func (m mockCache) Delete(key string) {
	delete(m, key)
}

func getIntOrDefault(str string, def int) (int, error) {
	if str == "" {
		return def, nil
	}
	return strconv.Atoi(str)
}

func acct(userID int32, serviceType, serviceID, accountID, oauthTok string) *extsvc.ExternalAccount {
	var data extsvc.ExternalAccountData
	gitlab.SetExternalAccountData(&data, &gitlab.User{
		ID: userID,
	}, &oauth2.Token{
		AccessToken: oauthTok,
	})
	return &extsvc.ExternalAccount{
		UserID: userID,
		ExternalAccountSpec: extsvc.ExternalAccountSpec{
			ServiceType: serviceType,
			ServiceID:   serviceID,
			AccountID:   accountID,
		},
		ExternalAccountData: data,
	}
}

func repo(uri, serviceType, serviceID, id string) authz.Repo {
	return authz.Repo{
		RepoName: api.RepoName(uri),
		ExternalRepoSpec: api.ExternalRepoSpec{
			ID:          id,
			ServiceType: serviceType,
			ServiceID:   serviceID,
		},
	}
}

type mockAuthnProvider struct {
	configID  auth.ProviderConfigID
	serviceID string
}

func (m mockAuthnProvider) ConfigID() auth.ProviderConfigID {
	return m.configID
}

func (m mockAuthnProvider) Config() schema.AuthProviders {
	return schema.AuthProviders{
		Gitlab: &schema.GitLabAuthProvider{
			Type: m.configID.Type,
			Url:  m.configID.ID,
		},
	}
}

func (m mockAuthnProvider) CachedInfo() *auth.ProviderInfo {
	return &auth.ProviderInfo{ServiceID: m.serviceID}
}

func (m mockAuthnProvider) Refresh(ctx context.Context) error {
	panic("should not be called")
}

func mustURL(t *testing.T, u string) *url.URL {
	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func asJSON(t *testing.T, v interface{}) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
