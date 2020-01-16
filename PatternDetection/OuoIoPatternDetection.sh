#!/bin/bash

if echo "$1" | grep -Eq 'https?:\/\/.*ouo\.io.*'; then
	UseOuoIoRegex='true'
fi
