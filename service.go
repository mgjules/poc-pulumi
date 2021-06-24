package main

type RsbService struct {
	Name         string `json:"name"`
	SourceBranch string `json:"source_branch"`
	SourceCommit string `json:"source_commit"`
}
