#!/bin/bash

if echo "$1" | grep -Eq '(https:\/\/|http:\/\/)([a-zA-Z0-9-]*\.)?(youtube)(\.[a-zA-Z]{2,}).*'; then
	UseYouTubeRegex='true'
fi
