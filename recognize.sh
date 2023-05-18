#!/bin/bash

BIN_NAME=$(basename $0);
TARGET=;
OUTPUT_DIR=;

function help() {
	echo Usage: $BIN_NAME [URL] [OUTPUT DIRECTORY]
	echo Synopsis: Takes a URL and an output directory, then does the following:
	echo 1. Checks for the existence of, and or creates the output directory.
	echo 2. Runs subfinder on the target URL with the following switches:
	printf "\t-d [URL]\n\t-all (uses all sources for enumeration)\n\t-cs (includes sources in the output file)\n"
	printf "and stores the subdirectory list in subdomains/domains.txt\n"
	echo 3. Strips the sources and stores the new list in subdomains/domains_stripped.txt
	echo 4. Breaks stripped domain list into smaller chunks under subdomains/chunks/chunk[1...].txt
	echo 5. Runs nuclei on each chunk with the following switches:
	printf "\t-l [CHUNK[1...].TXT]\n\t-rate-limit 5\n"
	printf "and stores the output in [OUTPUT DIR]/raw-vulns.txt\n"
	echo 6. Categorizes each entry in raw-vulns.txt and stores it in
	printf "\t[OUTPUT_DIR]/vuln-classes/[VULNERABILITY CLASS].txt\n"
	echo
	echo After each action, a dmail will be sent using dmail-send.
	echo
	exit 1;
};
function handle_exception() {
	echo $2 exception occurred!
	case $1 in
		INVAL_ARGC)
			echo Invalid number of arguments: $3;
			echo;
			help;;
		INVAL_URL)
			echo Invalid URL format: $3;
			echo;
			help;;
		INVAL_HTTP)
			echo Invalid http type: $3;
			echo;
			help;;
		*)
			echo $1;
			help;;
	esac;
};
function validate_url() {
	TARGET=$1;
	local domain=;
	local http_type_valid=;
	local http_type= \
	 $(echo $TARGET|gawk -v FS=":" '{if(NF>1) print $1}');
	if [ -n "$http_type" ]; then
		domain=$(echo $TARGET|cut -d"/" -f3)
		[ -z "$domain" ] && handle_exception INVAL_URL FATAL $TARGET;
	else 
		domain=$TARGET;
	fi;
	local domain_valid=$(echo $domain|gawk -v FS="." '{if(NF<2) print "false"; else print "true";}');
	if [ -n "$http_type" ]; then
		case $http_type in
			http) http_type_valid=true;;
			https) http_type_valid=true;;
			*) http_type_valid=false;;
		esac;
	fi;
	[ "$http_type_valid" == false ] && handle_exception INVAL_HTTP FATAL $http_type;
	[ "$domain_valid" == false ] && handle_exception INVAL_URL FATAL $TARGET;

	return 0;
};
function check_out_dir() {
	if [ ! -d $1 ]; then
		local response="";
		while [ -z "$response" ]; do
			printf "Create directory $1?\n:"
			read response && response=${response,,};
			case $response in
				y|ye|yes);;
				n|no)
					echo Exiting.;
					exit;;
				*)
					echo Invalid response. Try again.;
					response="";;
			esac;
		done;
	fi;
	mkdir -vp $1/{vuln-classes,subdomains/chunks};

	OUTPUT_DIR=$1
	return 0;
};
function parseArgs() {
	if [ $# -ne 2 ]; then
		handle_exception INVAL_ARGC FATAL $#;
	fi
	validate_url $1;
	check_out_dir $2;

	return 0;
};
function chunkDomains() {
	local list_len=$(cat subdomains/domains_stripped.txt);
	local chunk_len=10
	local chunk_line_count=0;
	local chunk_number=1

	while read record; do
		(( chunk_line_count++ ));
		echo $record >> subdomains/chunks/chunk_${chunk_number}.txt

		if [ $chunk_line_count == $chunk_len ]; then
			chunk_line_count=0;
			(( chunk_number++ ));
		fi;
	done <subdomains/domains_stripped.txt;

	return 0;
};
function nukeChunks() {
	local chunk_count=$(ls -1 subdomains/chunks | wc -l);
	local current_chunk=0;
	for chunk in subdomains/chunks/*; do
		(( current_chunk++ ));
		nuclei -l $chunk -rate-limit 5 | tee -a nuclei_results.txt
		dmail-send "Chunk $current_chunk of $chunk_count processed by nuclei."
	done;

	return 0;
};
function classifyVulns() {
	debracket() { echo $1 | sed -e 's/\[//' -e 's/\]//'; };
	field_break() { echo $1 | awk ' { for(i=1;i<=NF;i++) print $i } '; };
	local odir=vuln-classes;
	local f_nm=${odir}/$class_type;
	declare -a fields;
	local vuln_type;
	local tech_type;
	local class_type;
	local _url;
	local src;
	local output_record;

	while read record; do
		fields=($(field_break "${record[@]}"));
		vuln_type=$(debracket ${fields[0]});
		tech_type=$(debracket ${fields[1]});
		class_type=$(debracket ${fields[2]});
		_url=${fields[3]};
		src=${fields[@]:4};

		output_record="$vuln_type $tech_type $src"
		echo $_url >> $odir/$class_type.txt
		echo $output_record >> $odir/$class_type.txt
		echo >> $odir/$class_type.txt
	done <nuclei_results.txt

	return 0;
};
function main() {
	pushd $OUTPUT_DIR

	subfinder -d $TARGET -all -cs >> subdomains/domains.txt
	dmail-send "Subfinder finished enumerating $TARGET";
	cat subdomains/domains.txt | cut -d"," -f1 > subdomains/domains_stripped.txt
	chunkDomains;

	nukeChunks;

	classifyVulns;

	dmail-send "recognize.sh $TARGET exited."
	return 0;
};

parseArgs $@;
main;
exit 0;
