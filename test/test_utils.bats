#!/usr/bin/env bats
# Tests for utils.sh

load 'libs/bats-support/load'
load 'libs/bats-assert/load'
load 'libs/bats-file/load'
load 'bats_helper.bash'

setup() {
    TEST_TEMP_DIR="$(temp_make)"
}

teardown() {
    temp_del "${TEST_TEMP_DIR}"
}


# ---------------------------------------------------------------------------

@test "addOrEditKeyValPair adds and replaces key-value pairs correctly" {
    local outfile="${TEST_TEMP_DIR}/testoutput"
    bash -c "
        source /opt/pihole/utils.sh
        addOrEditKeyValPair '${outfile}' 'KEY_ONE' 'value1'
        addOrEditKeyValPair '${outfile}' 'KEY_TWO' 'value2'
        addOrEditKeyValPair '${outfile}' 'KEY_ONE' 'value3'
        addOrEditKeyValPair '${outfile}' 'KEY_FOUR' 'value4'
    "
    assert_file_exists "${outfile}"
    assert_file_contains "${outfile}" "KEY_ONE=value3"
    assert_file_contains "${outfile}" "KEY_TWO=value2"
    assert_file_contains "${outfile}" "KEY_FOUR=value4"
    assert_file_not_contains "${outfile}" "KEY_ONE=value1"
}

@test "getFTLPID returns -1 when FTL is not running" {
    run bash -c "
        source /opt/pihole/utils.sh
        getFTLPID
    "
    assert_output "-1"
}

@test "getFTLPID rejects non-numeric and injected PID content" {
    run bash -c '
        source /opt/pihole/utils.sh
        printf "%s\n" "123 -KILL 1" > /run/pihole-FTL.pid
        getFTLPID
    '
    assert_output "-1"

    run bash -c '
        source /opt/pihole/utils.sh
        printf "%s\n" "12a" > /run/pihole-FTL.pid
        getFTLPID
    '
    assert_output "-1"

    run bash -c '
        source /opt/pihole/utils.sh
        printf "%s\n" "4242" > /run/pihole-FTL.pid
        getFTLPID
    '
    assert_output "4242"
}

@test "setFTLConfigValue and getFTLConfigValue round-trip" {
    # FTL must be installed for this test
    bash -c "
        source /opt/pihole/basic-install.sh
        create_pihole_user
        funcOutput=\$(get_binary_name)
        echo 'development' > /etc/pihole/ftlbranch
        binary=\"pihole-FTL\${funcOutput##*pihole-FTL}\"
        theRest=\"\${funcOutput%pihole-FTL*}\"
        FTLdetect \"\${binary}\" \"\${theRest}\"
    "
    run bash -c "
        source /opt/pihole/utils.sh
        setFTLConfigValue 'dns.upstreams' '[\"9.9.9.9\"]' > /dev/null
        getFTLConfigValue 'dns.upstreams'
    "
    assert_output --partial "[ 9.9.9.9 ]"
}

# ---------------------------------------------------------------------------
# validate_ftl_path() -- used by piholeLogFlush.sh and uninstall.sh to
# refuse to act on a files.log.*/files.database/etc. value from FTL's
# config unless it resolves inside the expected Pi-hole directory.

@test "validate_ftl_path accepts a path inside the required prefix" {
    run bash -c '
        source /opt/pihole/utils.sh
        validate_ftl_path "/var/log/pihole/pihole.log" "/var/log/pihole/"
    '
    assert_success
    assert_output "/var/log/pihole/pihole.log"
}

@test "validate_ftl_path rejects a path outside the required prefix" {
    run bash -c '
        source /opt/pihole/utils.sh
        validate_ftl_path "/etc/shadow" "/var/log/pihole/"
    '
    assert_failure
    assert_output ""
}

@test "validate_ftl_path rejects directory-traversal out of the prefix" {
    # Three ".." to actually reach root from /var/log/pihole/ (pihole -> log
    # -> var -> /), landing on the real /etc/shadow -- not two, which lands
    # on the non-existent /var/etc/shadow and would make readlink -f itself
    # fail before the prefix check is ever exercised.
    run bash -c '
        source /opt/pihole/utils.sh
        validate_ftl_path "/var/log/pihole/../../../etc/shadow" "/var/log/pihole/"
    '
    assert_failure
    assert_output ""
}

@test "validate_ftl_path rejects a symlink that escapes the prefix" {
    local evil_link="${TEST_TEMP_DIR}/evil.log"
    ln -s /etc/shadow "${evil_link}"
    run bash -c "
        source /opt/pihole/utils.sh
        validate_ftl_path '${evil_link}' '/var/log/pihole/'
    "
    assert_failure
    assert_output ""
}

@test "validate_ftl_path rejects an empty path" {
    run bash -c '
        source /opt/pihole/utils.sh
        validate_ftl_path "" "/var/log/pihole/"
    '
    assert_failure
}

# ---------------------------------------------------------------------------
# addOrEditKeyValPair() sed-injection guard -- updatecheck.sh feeds this
# function GitHub release tag_name values fetched over the network, which
# are interpolated into a `sed "c\"` replacement script.

@test "addOrEditKeyValPair rejects a value containing a newline (sed injection)" {
    local outfile="${TEST_TEMP_DIR}/testoutput"
    run bash -c "
        source /opt/pihole/utils.sh
        addOrEditKeyValPair '${outfile}' 'GITHUB_FTL_VERSION' \$'v1.0\ne s/root:.*/pwned/'
    "
    assert_failure
    assert_file_not_exists "${outfile}"
}

@test "addOrEditKeyValPair rejects a value containing a backslash" {
    local outfile="${TEST_TEMP_DIR}/testoutput"
    run bash -c "
        source /opt/pihole/utils.sh
        addOrEditKeyValPair '${outfile}' 'GITHUB_FTL_VERSION' 'v1.0\\\\evil'
    "
    assert_failure
}

@test "addOrEditKeyValPair still accepts a normal GitHub release tag" {
    local outfile="${TEST_TEMP_DIR}/testoutput"
    run bash -c "
        source /opt/pihole/utils.sh
        addOrEditKeyValPair '${outfile}' 'GITHUB_FTL_VERSION' 'v6.4.3'
    "
    assert_success
    assert_file_contains "${outfile}" "GITHUB_FTL_VERSION=v6.4.3"
}
