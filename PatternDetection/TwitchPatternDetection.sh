#!/bin/bash

if echo "$1" | grep -Eq '(https:\/\/|http:\/\/)([a-zA-Z0-9-]*\.)?(twitch)(\.[a-zA-Z]{2,}).*'; then
	UseTwitchRegex='true'
fi
