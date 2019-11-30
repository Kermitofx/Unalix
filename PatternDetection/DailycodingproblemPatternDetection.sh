#!/bin/bash

if echo "$1" | grep -Eq 'https?:\/\/([a-zA-Z0-9-]*\.)?(dailycodingproblem\.com).*'; then
	UseDailycodingproblemRegex='true'
fi
