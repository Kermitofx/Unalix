#!/bin/bash

if echo "$1" | grep -Eq 'https?:\/\/([a-zA-Z0-9_-]*\.)?(blogger|blogspot)\.\w{2,}.*'; then
	UseBloggerRegex='true'
fi
