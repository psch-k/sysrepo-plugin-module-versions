#!/bin/bash

set -eu -o pipefail

shopt -s failglob

local_path=$(dirname $0)

[ -n "{${1}" ] && SYSREPOCTL="${1}"
[ -n "{${2}" ] && SYSREPOCTL_ROOT_PERMS="${2}"
[ -n "{${3}" ] && YANG_SET_LOWER="${3}"

: ${SYSREPOCTL:=sysrepoctl}
: ${SYSREPOCTL_ROOT_PERMS:=-p 600}
: ${YANG_SET_LOWER:=ipsolutionref_1_6_0}
: ${YANG_DIR:=$local_path/../modules}

is_yang_module_installed() {
    module=$1

    $SYSREPOCTL -l | grep -c "^$module [^|]*|[^|]*| I .*$" > /dev/null
}

install_yang_module() {
    module=$1

    if ! is_yang_module_installed $module; then
        echo "- Installing module $module..."
        ${SYSREPOCTL} -i ${YANG_DIR}/${module}.yang
        ${SYSREPOCTL} -c ${module} ${SYSREPOCTL_ROOT_PERMS}
    else
        echo "- Module ${module} already installed."
    fi
}

if [ "${YANG_SET_LOWER}" == "ipsolutionref_1_6_0" ]; then
    install_yang_module module-versions
elif [ "${YANG_SET_LOWER}" == "ipsolutionref_2_1_0" ]; then
    install_yang_module sysrepo-module-versions
else
    echo "ERROR: Unexpected YANG_SET (\"${YANG_SET_LOWER}\""
    exit 1
fi
