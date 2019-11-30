#!/bin/bash

if echo "$1" | grep -Eq 'https?:\/\/([a-zA-Z0-9-]*\.)?(github\.com).*'; then
	UseGitHubRegex='true'
fi
