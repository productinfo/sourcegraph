package gitlab

import (
	"context"
	"reflect"
	"testing"

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
					repos:       map[authz.Repo]struct{}{
						// repo("u1/repo1", gitlab.ServiceType, "https://gitlab.mine/", "10"):        {},
						// repo("u2/repo1", gitlab.ServiceType, "https://gitlab.mine/", "20"):        {},
						// repo("u3/repo1", gitlab.ServiceType, "https://gitlab.mine/", "30"):        {},
						// repo("internal/repo1", gitlab.ServiceType, "https://gitlab.mine/", "981"): {},
						// repo("public/repo1", gitlab.ServiceType, "https://gitlab.mine/", "991"):   {},
					},
					expPerms: map[api.RepoName]map[authz.Perm]bool{
						// "u1/repo1":       {authz.Read: true},
						// "internal/repo1": {authz.Read: true},
						// "public/repo1":   {authz.Read: true},
					},
				},
				{
					description: "u3 user has expected perms",
					account:     acct(3, "gitlab", "https://gitlab.mine/", "u3", "oauth-u3"),
					repos:       map[authz.Repo]struct{}{
						// repo("u1/repo1", gitlab.ServiceType, "https://gitlab.mine/", "10"):        {},
						// repo("u2/repo1", gitlab.ServiceType, "https://gitlab.mine/", "20"):        {},
						// repo("u3/repo1", gitlab.ServiceType, "https://gitlab.mine/", "30"):        {},
						// repo("internal/repo1", gitlab.ServiceType, "https://gitlab.mine/", "981"): {},
						// repo("public/repo1", gitlab.ServiceType, "https://gitlab.mine/", "991"):   {},
					},
					expPerms: map[api.RepoName]map[authz.Perm]bool{
						// "u1/repo1":       {authz.Read: true},
						// "internal/repo1": {authz.Read: true},
						// "public/repo1":   {authz.Read: true},
					},
				},
			},
		},
	}
	for _, test := range tests {
		test.run(t)
	}
}

// func Test_GitLab_RepoPerms(t *testing.T) {
// 	gitlabMock := newMockGitLab(t,
// 		[]int{ // Repos
// 			11, // gitlab.mine/bl/repo-1
// 			12, // gitlab.mine/bl/repo-2
// 			13, // gitlab.mine/bl/repo-3
// 			21, // gitlab.mine/kl/repo-1
// 			22, // gitlab.mine/kl/repo-2
// 			23, // gitlab.mine/kl/repo-3
// 			31, // gitlab.mine/org/repo-1
// 			32, // gitlab.mine/org/repo-2
// 			33, // gitlab.mine/org/repo-3
// 			41, // gitlab.mine/public/repo-1
// 		},
// 		map[string][]int{ // GitLab user IDs to repo IDs
// 			"101":    {11, 12, 13, 31, 32, 33, 41},
// 			"201":    {21, 22, 23, 31, 32, 33, 41},
// 			"PUBLIC": {41},
// 		},
// 		map[string]string{ // GitLab OAuth tokens to GitLab user IDs
// 			"oauth101": "101",
// 			"oauth201": "201",
// 		},
// 		1)
// 	gitlab.MockListProjects = gitlabMock.ListProjects

// 	tests := []GitLab_RepoPerms_Test{
// 		{
// 			description: "standard config",
// 			op: GitLabOAuthAuthzProviderOp{
// 				BaseURL: mustURL(t, "https://gitlab.mine"),
// 			},
// 			calls: []GitLab_RepoPerms_call{
// 				{
// 					description: "bl user has expected perms",
// 					account:     acct(1, "gitlab", "https://gitlab.mine/", "101", "oauth101"),
// 					repos: map[authz.Repo]struct{}{
// 						repo("bl/repo-1", gitlab.ServiceType, "https://gitlab.mine/", "11"):                 {},
// 						repo("bl/repo-2", gitlab.ServiceType, "other", "12"):                                {},
// 						repo("gitlab.mine/bl/repo-3", gitlab.ServiceType, "https://gitlab.mine/", "999"):    {},
// 						repo("kl/repo-1", gitlab.ServiceType, "https://gitlab.mine/", "21"):                 {},
// 						repo("kl/repo-2", gitlab.ServiceType, "other", "22"):                                {},
// 						repo("gitlab.mine/kl/repo-3", gitlab.ServiceType, "https://gitlab.mine/", "998"):    {},
// 						repo("org/repo-1", gitlab.ServiceType, "https://gitlab.mine/", "31"):                {},
// 						repo("org/repo-2", gitlab.ServiceType, "other", "32"):                               {},
// 						repo("gitlab.mine/org/repo-3", gitlab.ServiceType, "https://gitlab.mine/", "997"):   {},
// 						repo("gitlab.mine/public/repo-1", gitlab.ServiceType, "https://gitlab.mine/", "41"): {},
// 					},
// 					expPerms: map[api.RepoName]map[authz.Perm]bool{
// 						"bl/repo-1":                 {authz.Read: true},
// 						"gitlab.mine/bl/repo-3":     {},
// 						"kl/repo-1":                 {},
// 						"gitlab.mine/kl/repo-3":     {},
// 						"org/repo-1":                {authz.Read: true},
// 						"gitlab.mine/org/repo-3":    {},
// 						"gitlab.mine/public/repo-1": {authz.Read: true},
// 					},
// 				},
// 				{
// 					description: "kl user has expected perms",
// 					account:     acct(2, "gitlab", "https://gitlab.mine/", "201", "oauth201"),
// 					repos: map[authz.Repo]struct{}{
// 						repo("bl/repo-1", gitlab.ServiceType, "https://gitlab.mine/", "11"):                 {},
// 						repo("bl/repo-2", gitlab.ServiceType, "other", "12"):                                {},
// 						repo("gitlab.mine/bl/repo-3", gitlab.ServiceType, "https://gitlab.mine/", "999"):    {},
// 						repo("kl/repo-1", gitlab.ServiceType, "https://gitlab.mine/", "21"):                 {},
// 						repo("kl/repo-2", gitlab.ServiceType, "other", "22"):                                {},
// 						repo("gitlab.mine/kl/repo-3", gitlab.ServiceType, "https://gitlab.mine/", "998"):    {},
// 						repo("org/repo-1", gitlab.ServiceType, "https://gitlab.mine/", "31"):                {},
// 						repo("org/repo-2", gitlab.ServiceType, "other", "32"):                               {},
// 						repo("gitlab.mine/org/repo-3", gitlab.ServiceType, "https://gitlab.mine/", "997"):   {},
// 						repo("gitlab.mine/public/repo-1", gitlab.ServiceType, "https://gitlab.mine/", "41"): {},
// 					},
// 					expPerms: map[api.RepoName]map[authz.Perm]bool{
// 						"bl/repo-1":                 {},
// 						"gitlab.mine/bl/repo-3":     {},
// 						"kl/repo-1":                 {authz.Read: true},
// 						"gitlab.mine/kl/repo-3":     {},
// 						"org/repo-1":                {authz.Read: true},
// 						"gitlab.mine/org/repo-3":    {},
// 						"gitlab.mine/public/repo-1": {authz.Read: true},
// 					},
// 				},
// 				{
// 					description: "unknown user has access to public only",
// 					account:     acct(3, "gitlab", "https://gitlab.mine/", "999", "oauth999"),
// 					repos: map[authz.Repo]struct{}{
// 						repo("bl/repo-1", gitlab.ServiceType, "https://gitlab.mine/", "11"):                 {},
// 						repo("bl/repo-2", gitlab.ServiceType, "other", "12"):                                {},
// 						repo("gitlab.mine/bl/repo-3", gitlab.ServiceType, "https://gitlab.mine/", "999"):    {},
// 						repo("kl/repo-1", gitlab.ServiceType, "https://gitlab.mine/", "21"):                 {},
// 						repo("kl/repo-2", gitlab.ServiceType, "other", "22"):                                {},
// 						repo("gitlab.mine/kl/repo-3", gitlab.ServiceType, "https://gitlab.mine/", "998"):    {},
// 						repo("org/repo-1", gitlab.ServiceType, "https://gitlab.mine/", "31"):                {},
// 						repo("org/repo-2", gitlab.ServiceType, "other", "32"):                               {},
// 						repo("gitlab.mine/org/repo-3", gitlab.ServiceType, "https://gitlab.mine/", "997"):   {},
// 						repo("gitlab.mine/public/repo-1", gitlab.ServiceType, "https://gitlab.mine/", "41"): {},
// 					},
// 					expPerms: map[api.RepoName]map[authz.Perm]bool{
// 						"bl/repo-1":                 {},
// 						"gitlab.mine/bl/repo-3":     {},
// 						"kl/repo-1":                 {},
// 						"gitlab.mine/kl/repo-3":     {},
// 						"org/repo-1":                {},
// 						"gitlab.mine/org/repo-3":    {},
// 						"gitlab.mine/public/repo-1": {authz.Read: true},
// 					},
// 				},
// 				{
// 					description: "unauthenticated user has access to public only",
// 					account:     nil,
// 					repos: map[authz.Repo]struct{}{
// 						repo("bl/repo-1", gitlab.ServiceType, "https://gitlab.mine/", "11"):                 {},
// 						repo("bl/repo-2", gitlab.ServiceType, "other", "12"):                                {},
// 						repo("gitlab.mine/bl/repo-3", gitlab.ServiceType, "https://gitlab.mine/", "999"):    {},
// 						repo("kl/repo-1", gitlab.ServiceType, "https://gitlab.mine/", "21"):                 {},
// 						repo("kl/repo-2", gitlab.ServiceType, "other", "22"):                                {},
// 						repo("gitlab.mine/kl/repo-3", gitlab.ServiceType, "https://gitlab.mine/", "998"):    {},
// 						repo("org/repo-1", gitlab.ServiceType, "https://gitlab.mine/", "31"):                {},
// 						repo("org/repo-2", gitlab.ServiceType, "other", "32"):                               {},
// 						repo("gitlab.mine/org/repo-3", gitlab.ServiceType, "https://gitlab.mine/", "997"):   {},
// 						repo("gitlab.mine/public/repo-1", gitlab.ServiceType, "https://gitlab.mine/", "41"): {},
// 					},
// 					expPerms: map[api.RepoName]map[authz.Perm]bool{
// 						"bl/repo-1":                 {},
// 						"gitlab.mine/bl/repo-3":     {},
// 						"kl/repo-1":                 {},
// 						"gitlab.mine/kl/repo-3":     {},
// 						"org/repo-1":                {},
// 						"gitlab.mine/org/repo-3":    {},
// 						"gitlab.mine/public/repo-1": {authz.Read: true},
// 					},
// 				},
// 				{
// 					description: "user with no oauth token has access to public only",
// 					account:     acct(2, "gitlab", "https://gitlab.mine/", "201", ""),
// 					repos: map[authz.Repo]struct{}{
// 						repo("bl/repo-1", gitlab.ServiceType, "https://gitlab.mine/", "11"):                 {},
// 						repo("bl/repo-2", gitlab.ServiceType, "other", "12"):                                {},
// 						repo("gitlab.mine/bl/repo-3", gitlab.ServiceType, "https://gitlab.mine/", "999"):    {},
// 						repo("kl/repo-1", gitlab.ServiceType, "https://gitlab.mine/", "21"):                 {},
// 						repo("kl/repo-2", gitlab.ServiceType, "other", "22"):                                {},
// 						repo("gitlab.mine/kl/repo-3", gitlab.ServiceType, "https://gitlab.mine/", "998"):    {},
// 						repo("org/repo-1", gitlab.ServiceType, "https://gitlab.mine/", "31"):                {},
// 						repo("org/repo-2", gitlab.ServiceType, "other", "32"):                               {},
// 						repo("gitlab.mine/org/repo-3", gitlab.ServiceType, "https://gitlab.mine/", "997"):   {},
// 						repo("gitlab.mine/public/repo-1", gitlab.ServiceType, "https://gitlab.mine/", "41"): {},
// 					},
// 					expPerms: map[api.RepoName]map[authz.Perm]bool{
// 						"bl/repo-1":                 {},
// 						"gitlab.mine/bl/repo-3":     {},
// 						"kl/repo-1":                 {},
// 						"gitlab.mine/kl/repo-3":     {},
// 						"org/repo-1":                {},
// 						"gitlab.mine/org/repo-3":    {},
// 						"gitlab.mine/public/repo-1": {authz.Read: true},
// 					},
// 				},
// 			},
// 		},
// 	}
// 	for _, test := range tests {
// 		test.run(t)
// 	}
// }

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
