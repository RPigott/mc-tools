#!/bin/sh

# Get args
TEMP=$(getopt -o 'lsv:o:' --long 'list,snapshot,version:,output:' -n "${0##*/}" -- "$@")

if [ $? -ne 0 ]; then
	cat <<-HERE
	Usage:
	  ${0##*/} --list
	  ${0##*/} [--snapshot] [--output]
	  ${0##*/} --version <version>

	Options:
	  -l --list      List the available versions instead of downloading.
	  -s --snapshot  Get the latest snapshot instead of stable version.
	  -o --output    Choose file to place server.jar. [default: "server.jar"]
	  -v --version   Get the specified version.
	HERE
	exit 1
fi

eval set -- "$TEMP"
unset TEMP

# Get server
version_manifest="https://launchermeta.mojang.com/mc/game/version_manifest.json"
versions=$(mktemp)

curl -s $version_manifest > $versions

while true; do
	case "$1" in
		'-l' | '--list')
			jq -r '.versions[] | "\(.releaseTime[:19] | strptime("%FT%T") | strftime("%x %H:%M")) \(.id)"' "$versions" 
			exit
		;;
		'-s' | '--snapshot')
			echo 'Finding latest snapshot'
			release=$(jq -r '.latest.snapshot' "$versions")
			shift
		;;
		'-v' | '--version')
			release="$2"
			shift 2
		;;
		'-o' | '--output')
			OUTPUT="$2"
			shift 2
		;;
		'--')
			shift
			break
		;;
		*)
			exit 1
		;;
	esac
done

if [ -z "$release" ]; then
	echo 'Finding latest release'
	release=$(jq -r '.latest.release' "$versions")
fi

echo "Retrieving Minecraft $release"
target=$(jq -r ".versions[] | select(.id == \"$release\") | .url" $versions)
download=$(curl -s $target | jq -r '.downloads.server.url')

curl -# $download -o "${OUTPUT:-server.jar}"

rm $versions
