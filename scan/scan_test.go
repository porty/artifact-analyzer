package scan

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScanGitConfig(t *testing.T) {
	const gitConfig = `[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
	ignorecase = true
	precomposeunicode = true
[remote "origin"]
	url = git@github.com:porty/artifact-analyzer.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
[gui]
	wmstate = zoomed
	geometry = 888x451+5+43 590 307
`

	reader := strings.NewReader(gitConfig)
	var result Result
	err := scanGitConfig(&result, reader, "some/project/.git/config")

	require.NoError(t, err)
	require.Equal(t, result.GitRepos, []GitRepo{
		{
			Root: "some/project",
			Remotes: []GitRepoRemote{
				{
					Name: "origin",
					URL:  "git@github.com:porty/artifact-analyzer.git",
				},
			},
		},
	})
}
