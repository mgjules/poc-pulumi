package main

import (
	"bytes"
	"fmt"
	"net/http"
	"time"
)

func fetchFileFromGithubRepo(owner, repoName, branch, fileName, personalAccessToken string) (string, error) {
	httpClient := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s?ref=%s", owner, repoName, fileName, branch), bytes.NewBuffer(nil))
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", fmt.Sprintf("token %s", personalAccessToken))
	req.Header.Set("Accept", "application/vnd.github.v3.raw")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("File %s does not exist in repo %s on branch %s", fileName, repoName, branch)
	}

	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return "", err
	}

	return buf.String(), nil
}
