#!/bin/bash

if echo "$1" | grep -Eq 'https?:\/\/outgoing\.prod\.mozaws\.net/.*'; then
	UseMozawsRegex='true'
fi
