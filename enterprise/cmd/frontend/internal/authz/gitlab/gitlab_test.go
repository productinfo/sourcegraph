package gitlab

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/sourcegraph/sourcegraph/cmd/frontend/authz"
	"github.com/sourcegraph/sourcegraph/pkg/api"
	"github.com/sourcegraph/sourcegraph/pkg/extsvc"
	"github.com/sourcegraph/sourcegraph/pkg/extsvc/gitlab"
)

func Test_GitLab_RepoPerms(t *testing.T) {
	// Mock the following scenario:
	// - public projects begin with 99
	// - internal projects begin with 98
	// - private projects begin with the digit of the user that owns them (other users may have access)
	// - u1 owns its own repositories and nothing else
	// - u2 owns its own repos and has guest access to u1's
	// - u3 owns its own repos and has full access to u1's and guest access to u2's
	gitlabMock := newMockGitLab(t,
		[]int{ // public projects
			991,
		},
		[]int{ // internal projects
			981,
		},
		map[int][2][]string{ // private projects
			10: [2][]string{
				[]string{ // guests
					"u2",
				},
				[]string{ // content ("full access")
					"u1",
					"u3",
				},
			},
			20: [2][]string{
				[]string{
					"u3",
				},
				[]string{
					"u2",
				},
			},
			30: [2][]string{
				[]string{},
				[]string{"u3"},
			},
		},
		map[string]string{
			"oauth-u1": "u1",
			"oauth-u2": "u2",
			"oauth-u3": "u3",
		},
	)
	gitlab.MockGetProject = gitlabMock.GetProject
	gitlab.MockListTree = gitlabMock.ListTree

	tests := []GitLab_RepoPerms_Test{
		{
			description: "standard config",
			op: GitLabOAuthAuthzProviderOp{
				BaseURL: mustURL(t, "https://gitlab.mine"),
			},
			calls: []GitLab_RepoPerms_call{
				{
					description: "u1 user has expected perms",
					account:     acct(1, "gitlab", "https://gitlab.mine/", "u1", "oauth-u1"),
					repos: map[authz.Repo]struct{}{
						repo("u1/repo1", gitlab.ServiceType, "https://gitlab.mine/", "10"):        {},
						repo("u2/repo1", gitlab.ServiceType, "https://gitlab.mine/", "20"):        {},
						repo("u3/repo1", gitlab.ServiceType, "https://gitlab.mine/", "30"):        {},
						repo("internal/repo1", gitlab.ServiceType, "https://gitlab.mine/", "981"): {},
						repo("public/repo1", gitlab.ServiceType, "https://gitlab.mine/", "991"):   {},
					},
					expPerms: map[api.RepoName]map[authz.Perm]bool{
						"u1/repo1":       {authz.Read: true},
						"internal/repo1": {authz.Read: true},
						"public/repo1":   {authz.Read: true},
					},
				},
				{
					description: "u2 user has expected perms",
					account:     acct(2, "gitlab", "https://gitlab.mine/", "u2", "oauth-u2"),
					repos: map[authz.Repo]struct{}{
						repo("u1/repo1", gitlab.ServiceType, "https://gitlab.mine/", "10"):        {},
						repo("u2/repo1", gitlab.ServiceType, "https://gitlab.mine/", "20"):        {},
						repo("u3/repo1", gitlab.ServiceType, "https://gitlab.mine/", "30"):        {},
						repo("internal/repo1", gitlab.ServiceType, "https://gitlab.mine/", "981"): {},
						repo("public/repo1", gitlab.ServiceType, "https://gitlab.mine/", "991"):   {},
					},
					expPerms: map[api.RepoName]map[authz.Perm]bool{
						"u2/repo1":       {authz.Read: true},
						"internal/repo1": {authz.Read: true},
						"public/repo1":   {authz.Read: true},
					},
				},
				{
					description: "other user has expected perms (internal and public)",
					account:     acct(4, "gitlab", "https://gitlab.mine/", "other", "oauth-other"),
					repos: map[authz.Repo]struct{}{
						repo("u1/repo1", gitlab.ServiceType, "https://gitlab.mine/", "10"):        {},
						repo("u2/repo1", gitlab.ServiceType, "https://gitlab.mine/", "20"):        {},
						repo("u3/repo1", gitlab.ServiceType, "https://gitlab.mine/", "30"):        {},
						repo("internal/repo1", gitlab.ServiceType, "https://gitlab.mine/", "981"): {},
						repo("public/repo1", gitlab.ServiceType, "https://gitlab.mine/", "991"):   {},
					},
					expPerms: map[api.RepoName]map[authz.Perm]bool{
						"internal/repo1": {authz.Read: true},
						"public/repo1":   {authz.Read: true},
					},
				},
				{
					description: "no token means only public repos",
					account:     acct(4, "gitlab", "https://gitlab.mine/", "no-token", ""),
					repos: map[authz.Repo]struct{}{
						repo("u1/repo1", gitlab.ServiceType, "https://gitlab.mine/", "10"):        {},
						repo("u2/repo1", gitlab.ServiceType, "https://gitlab.mine/", "20"):        {},
						repo("u3/repo1", gitlab.ServiceType, "https://gitlab.mine/", "30"):        {},
						repo("internal/repo1", gitlab.ServiceType, "https://gitlab.mine/", "981"): {},
						repo("public/repo1", gitlab.ServiceType, "https://gitlab.mine/", "991"):   {},
					},
					expPerms: map[api.RepoName]map[authz.Perm]bool{
						"public/repo1": {authz.Read: true},
					},
				},
				{
					description: "unauthenticated means only public repos",
					account:     nil,
					repos: map[authz.Repo]struct{}{
						repo("u1/repo1", gitlab.ServiceType, "https://gitlab.mine/", "10"):        {},
						repo("u2/repo1", gitlab.ServiceType, "https://gitlab.mine/", "20"):        {},
						repo("u3/repo1", gitlab.ServiceType, "https://gitlab.mine/", "30"):        {},
						repo("internal/repo1", gitlab.ServiceType, "https://gitlab.mine/", "981"): {},
						repo("public/repo1", gitlab.ServiceType, "https://gitlab.mine/", "991"):   {},
					},
					expPerms: map[api.RepoName]map[authz.Perm]bool{
						"public/repo1": {authz.Read: true},
					},
				},
			},
		},
	}
	for _, test := range tests {
		test.run(t)
	}
}

func Test_GitLab_RepoPerms_cache(t *testing.T) {
	gitlabMock := newMockGitLab(t,
		[]int{ // public projects
			991,
		},
		[]int{ // internal projects
			981,
		},
		map[int][2][]string{ // private projects
			10: [2][]string{
				[]string{ // guests
					"u2",
				},
				[]string{ // content ("full access")
					"u1",
				},
			},
		},
		map[string]string{
			"oauth-u1": "u1",
			"oauth-u2": "u2",
			"oauth-u3": "u3",
		},
	)
	gitlab.MockGetProject = gitlabMock.GetProject
	gitlab.MockListTree = gitlabMock.ListTree

	ctx := context.Background()
	authzProvider := NewProvider(GitLabOAuthAuthzProviderOp{
		BaseURL:   mustURL(t, "https://gitlab.mine"),
		MockCache: make(mockCache),
		CacheTTL:  3 * time.Hour,
	})
	if _, err := authzProvider.RepoPerms(ctx,
		acct(1, gitlab.ServiceType, "https://gitlab.mine/", "u1", "oauth-u1"),
		map[authz.Repo]struct{}{
			repo("10", "gitlab", "https://gitlab.mine", "10"): {},
		},
	); err != nil {
		t.Fatal(err)
	}
	if actual, exp := gitlabMock.madeGetProject, map[string]map[gitlab.GetProjectOp]int{}; !reflect.DeepEqual(exp, actual) {
		t.Errorf("Unexpected cache behavior. Expected %v, but got %v", exp, actual)
	}
	t.Errorf("# HERE")
}

type GitLab_RepoPerms_Test struct {
	description string

	op GitLabOAuthAuthzProviderOp

	calls []GitLab_RepoPerms_call
}

type GitLab_RepoPerms_call struct {
	description string
	account     *extsvc.ExternalAccount
	repos       map[authz.Repo]struct{}
	expPerms    map[api.RepoName]map[authz.Perm]bool
}

func (g GitLab_RepoPerms_Test) run(t *testing.T) {
	t.Logf("Test case %q", g.description)

	for _, c := range g.calls {
		t.Logf("Call %q", c.description)

		// Recreate the authz provider cache every time, before running twice (once uncached, once cached)
		ctx := context.Background()
		op := g.op
		op.MockCache = make(mockCache)
		authzProvider := NewProvider(op)

		for i := 0; i < 2; i++ {
			t.Logf("iter %d", i)
			perms, err := authzProvider.RepoPerms(ctx, c.account, c.repos)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				continue
			}
			if !reflect.DeepEqual(perms, c.expPerms) {
				t.Errorf("expected %s, but got %s", asJSON(t, c.expPerms), asJSON(t, perms))
			}
		}
	}
}

// func Test_GitLab_RepoPerms_cache(t *testing.T) {
// 	gitlabMock := newMockGitLab(t, []int{}, map[string][]int{}, map[string]string{}, 1)
// 	gitlab.MockListProjects = gitlabMock.ListProjects

// 	ctx := context.Background()
// 	authzProvider := NewProvider(GitLabOAuthAuthzProviderOp{
// 		BaseURL:   mustURL(t, "https://gitlab.mine"),
// 		MockCache: make(mockCache),
// 		CacheTTL:  3 * time.Hour,
// 	})
// 	if _, err := authzProvider.RepoPerms(ctx, acct(1, gitlab.ServiceType, "https://gitlab.mine/", "bl", "oauth_bl"), nil); err != nil {
// 		t.Fatal(err)
// 	}
// 	if exp := map[string]map[string]int{
// 		"projects?per_page=100": {"oauth_bl": 1},
// 	}; !reflect.DeepEqual(gitlabMock.madeProjectReqs, exp) {
// 		t.Errorf("Unexpected cache behavior. Expected underying requests to be %v, but got %v", exp, gitlabMock.madeProjectReqs)
// 	}

// 	if _, err := authzProvider.RepoPerms(ctx, acct(1, gitlab.ServiceType, "https://gitlab.mine/", "bl", "oauth_bl"), nil); err != nil {
// 		t.Fatal(err)
// 	}
// 	if exp := map[string]map[string]int{
// 		"projects?per_page=100": {"oauth_bl": 1},
// 	}; !reflect.DeepEqual(gitlabMock.madeProjectReqs, exp) {
// 		t.Errorf("Unexpected cache behavior. Expected underying requests to be %v, but got %v", exp, gitlabMock.madeProjectReqs)
// 	}

// 	if _, err := authzProvider.RepoPerms(ctx, acct(1, gitlab.ServiceType, "https://gitlab.mine/", "kl", "oauth_kl"), nil); err != nil {
// 		t.Fatal(err)
// 	}
// 	if exp := map[string]map[string]int{
// 		"projects?per_page=100": {"oauth_bl": 1, "oauth_kl": 1},
// 	}; !reflect.DeepEqual(gitlabMock.madeProjectReqs, exp) {
// 		t.Errorf("Unexpected cache behavior. Expected underying requests to be %v, but got %v", exp, gitlabMock.madeProjectReqs)
// 	}

// 	if _, err := authzProvider.RepoPerms(ctx, acct(1, gitlab.ServiceType, "https://gitlab.mine/", "kl", "oauth_kl"), nil); err != nil {
// 		t.Fatal(err)
// 	}
// 	if exp := map[string]map[string]int{
// 		"projects?per_page=100": {"oauth_bl": 1, "oauth_kl": 1},
// 	}; !reflect.DeepEqual(gitlabMock.madeProjectReqs, exp) {
// 		t.Errorf("Unexpected cache behavior. Expected underying requests to be %v, but got %v", exp, gitlabMock.madeProjectReqs)
// 	}
// }

// // Test_GitLab_RepoPerms_cache_ttl tests the behavior of overwriting cache entries when the TTL changes
// func Test_GitLab_RepoPerms_cache_ttl(t *testing.T) {
// 	gitlabMock := newMockGitLab(t,
// 		[]int{
// 			11, // gitlab.mine/bl/repo-1
// 		},
// 		map[string][]int{
// 			"101": {11},
// 		},
// 		map[string]string{
// 			"oauth101": "101",
// 		}, 1)
// 	gitlab.MockListProjects = gitlabMock.ListProjects

// 	cache := make(mockCache)
// 	ctx := context.Background()
// 	authzProvider := NewProvider(GitLabOAuthAuthzProviderOp{
// 		BaseURL:   mustURL(t, "https://gitlab.mine"),
// 		MockCache: cache,
// 	})
// 	if expCache := mockCache(map[string]string{}); !reflect.DeepEqual(cache, expCache) {
// 		t.Errorf("expected cache to be %+v, but was %+v", expCache, cache)
// 	}

// 	if _, err := authzProvider.RepoPerms(ctx, acct(1, gitlab.ServiceType, "https://gitlab.mine/", "101", "oauth101"), nil); err != nil {
// 		t.Fatal(err)
// 	}
// 	if expCache := mockCache(map[string]string{"101": `{"repos":{"11":{}},"ttl":0}`}); !reflect.DeepEqual(cache, expCache) {
// 		t.Errorf("expected cache to be %+v, but was %+v", expCache, cache)
// 	}

// 	if _, err := authzProvider.RepoPerms(ctx, acct(1, gitlab.ServiceType, "https://gitlab.mine/", "101", "oauth101"), nil); err != nil {
// 		t.Fatal(err)
// 	}
// 	if expCache := mockCache(map[string]string{"101": `{"repos":{"11":{}},"ttl":0}`}); !reflect.DeepEqual(cache, expCache) {
// 		t.Errorf("expected cache to be %+v, but was %+v", expCache, cache)
// 	}

// 	authzProvider.cacheTTL = time.Hour * 5

// 	if _, err := authzProvider.RepoPerms(ctx, acct(1, gitlab.ServiceType, "https://gitlab.mine/", "101", "oauth101"), nil); err != nil {
// 		t.Fatal(err)
// 	}
// 	if expCache := mockCache(map[string]string{"101": `{"repos":{"11":{}},"ttl":18000000000000}`}); !reflect.DeepEqual(cache, expCache) {
// 		t.Errorf("expected cache to be %+v, but was %+v", expCache, cache)
// 	}

// 	authzProvider.cacheTTL = time.Second * 5

// 	// Use lower TTL
// 	if _, err := authzProvider.RepoPerms(ctx, acct(1, gitlab.ServiceType, "https://gitlab.mine/", "101", "oauth101"), nil); err != nil {
// 		t.Fatal(err)
// 	}
// 	if expCache := mockCache(map[string]string{"101": `{"repos":{"11":{}},"ttl":5000000000}`}); !reflect.DeepEqual(cache, expCache) {
// 		t.Errorf("expected cache to be %+v, but was %+v", expCache, cache)
// 	}

// 	authzProvider.cacheTTL = time.Second * 60

// 	// Increase in TTL doesn't overwrite cache entry
// 	if _, err := authzProvider.RepoPerms(ctx, acct(1, gitlab.ServiceType, "https://gitlab.mine/", "101", "oauth101"), nil); err != nil {
// 		t.Fatal(err)
// 	}
// 	if expCache := mockCache(map[string]string{"101": `{"repos":{"11":{}},"ttl":5000000000}`}); !reflect.DeepEqual(cache, expCache) {
// 		t.Errorf("expected cache to be %+v, but was %+v", expCache, cache)
// 	}
// }

func Test_GitLab_Repos(t *testing.T) {
	tests := []GitLab_Repos_Test{
		{
			description: "standard config",
			op: GitLabOAuthAuthzProviderOp{
				BaseURL: mustURL(t, "https://gitlab.mine"),
			},
			calls: []GitLab_Repos_call{
				{
					repos: map[authz.Repo]struct{}{
						repo("gitlab.mine/bl/repo-1", "", "", ""):                   {},
						repo("gitlab.mine/kl/repo-1", "", "", ""):                   {},
						repo("another.host/bl/repo-1", "", "", ""):                  {},
						repo("a", gitlab.ServiceType, "https://gitlab.mine/", "23"): {},
						repo("b", gitlab.ServiceType, "https://not-mine/", "34"):    {},
						repo("c", "not-gitlab", "https://gitlab.mine/", "45"):       {},
					},
					expMine: map[authz.Repo]struct{}{
						repo("a", gitlab.ServiceType, "https://gitlab.mine/", "23"): {},
					},
					expOthers: map[authz.Repo]struct{}{
						repo("gitlab.mine/bl/repo-1", "", "", ""):                {},
						repo("gitlab.mine/kl/repo-1", "", "", ""):                {},
						repo("another.host/bl/repo-1", "", "", ""):               {},
						repo("b", gitlab.ServiceType, "https://not-mine/", "34"): {},
						repo("c", "not-gitlab", "https://gitlab.mine/", "45"):    {},
					},
				},
			},
		},
	}
	for _, test := range tests {
		test.run(t)
	}
}

type GitLab_Repos_Test struct {
	description string
	op          GitLabOAuthAuthzProviderOp
	calls       []GitLab_Repos_call
}

type GitLab_Repos_call struct {
	repos     map[authz.Repo]struct{}
	expMine   map[authz.Repo]struct{}
	expOthers map[authz.Repo]struct{}
}

func (g GitLab_Repos_Test) run(t *testing.T) {
	t.Logf("Test case %q", g.description)
	for _, c := range g.calls {
		ctx := context.Background()
		op := g.op
		op.MockCache = make(mockCache)
		authzProvider := NewProvider(op)

		mine, others := authzProvider.Repos(ctx, c.repos)
		if !reflect.DeepEqual(mine, c.expMine) {
			t.Errorf("For input %v, expected mine to be %v, but got %v", c.repos, c.expMine, mine)
		}
		if !reflect.DeepEqual(others, c.expOthers) {
			t.Errorf("For input %v, expected others to be %v, but got %v", c.repos, c.expOthers, others)
		}
	}
}
