#!/bin/bash

# set -euo pipefail

export AMSTER_SCRIPTS=${AMSTER_SCRIPTS:-"${PWD}/scripts"}
export POST_INSTALL_SCRIPTS=${POST_INSTALL_SCRIPTS:-"${AMSTER_SCRIPTS}"}
export SERVER_URL=${OPENAM_INSTANCE:-http://openam:8080}
export URI=${SERVER_URI:-/}
export INSTANCE="${SERVER_URL}${URI}"
export CHECK_AM_ALREADY_CONFIGURED="${CHECK_AM_ALREADY_CONFIGURED-"false"}"

ALIVE="${INSTANCE}/isAlive.jsp"
CONFIG_URL="${INSTANCE}/config/options.htm"

wait_for_openam()
{
    sleep 5
    local response="000"

    while true; do
        response=$(curl --write-out %{http_code} --silent --connect-timeout 30 --output /dev/null ${CONFIG_URL} )

        echo "Got Response code $response and CHECK_AM_ALREADY_CONFIGURED=${CHECK_AM_ALREADY_CONFIGURED}"
        if [ ${response} = "302" ] || [ ${response} = "301" ]; then
            if [ ${CHECK_AM_ALREADY_CONFIGURED} = "true" ]; then
                echo "Checking to see if AM is already configured. Will not reconfigure"

                if curl ${CONFIG_URL} | grep -q "Configuration"; then
                    break
                fi
                echo "It looks like AM is already configured . Exiting"
                exit 0
            else
                echo "AM web app is up and already configured. Although we are forcing the configuration."
                break 
            fi
        fi
        if [ ${response} = "200" ]; then
            echo "AM web app is up and ready to be configured"
            break
        fi

      echo "response code ${response}. Will continue to wait"
      sleep 5
    done

    echo "About to begin configuration"
}

echo "Waiting for AM..."
wait_for_openam

# Extract amster version for commons parameter to modify configs
echo "Extracting amster version"
./amster --version
VER=$(./amster --version)
[[ "$VER" =~ ([0-9].[0-9].[0-9]-([a-zA-Z][0-9]+|SNAPSHOT|RC[0-9]+)|[0-9].[0-9].[0-9].[0-9]|[0-9].[0-9].[0-9]) ]]
export VERSION=${BASH_REMATCH[1]}
echo "Amster version is: " $VERSION

# Execute Amster if the configuration is found.
echo "AMSTER_SCRIPTS is ${AMSTER_SCRIPTS}"
ls -l ${AMSTER_SCRIPTS}
if [ -d  ${AMSTER_SCRIPTS} ]; then
    if [ ! -r /var/run/secrets/amster/id_rsa ]; then
        echo "ERROR: Can not find the Amster private key"
        exit 1
    fi

    echo "Executing Amster to configure AM"


    for file in ${AMSTER_SCRIPTS}/*.*
    do
        case "${file##*.}" in
        'amster')
            echo "Executing Amster script $file"
            bash ./amster -q ${file}
        ;;
        'sh')
            echo "Executing shell script $file"
            bash ${file}
        ;;
        esac
    done
fi


echo "Configuration script finished"
echo "Completed in ${SECONDS} seconds."