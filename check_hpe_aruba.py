#!/usr/bin/env python

# Copyright (C) 2016 - 2018 rsmuc <rsmuc@mailbox.org>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with check_snmp_ilo4.py.  If not, see <http://www.gnu.org/licenses/>.

# Import PluginHelper and some utility constants from the Plugins module
from pynag.Plugins import PluginHelper,ok,critical,unknown
import netsnmp
import sys
import os
sys.path.insert(1, os.path.join(sys.path[0], os.pardir))
from snmpSessionBaseClass import add_common_options, verify_seclevel, add_snmpv3_options, get_common_options, verify_host, get_data, walk_data, attempt_walk_data, state_summary, add_output

# Create an instance of PluginHelper()
helper = PluginHelper()

# Define the command line options
add_common_options(helper)
add_snmpv3_options(helper)
helper.parse_arguments()

# Get the options
host, version, community = get_common_options(helper)
secname, seclevel, authproto, authpass, privproto, privpass, verbose = helper.options.secname, \
    helper.options.seclevel, \
    helper.options.authproto, \
    helper.options.authpass, \
    helper.options.privproto, \
    helper.options.privpass, \
    helper.options.verbose

if verbose != None:
    if verbose>3:
        verbose=3
    print "verbosity level = %i\n"%(verbose)

# States definitions
#https://www.circitor.fr/Mibs/Mib/H/HP-VSF-VC-MIB.mib

translate_hpicfVsfVCOperStatus = {
              0 : 'unAvailable',
              1 : 'disabled',
              2 : 'active',
              3 : 'fragmentInactive',
              4 : 'fragmentActive'
              }

# hpicfVsfVCAdminStatus
# DESCRIPTION
# "The administrative status of the VSF virtual chassis. When set to
# enable (1), this object enables VSF on the switch and on the
# discovered members. Setting this to disable (2) disables VSF
# only on the standalone switch. Enabling or disabling VSF triggers
# a reboot of the VSF switch."
translate_hpicfVsfVCAdminStatus = {
              1 : 'enable',
              2 : 'disable'
              }

translate_hpicfVsfVCMemberState = {
              0 : 'unusedId',
              1 : 'missing',
              2 : 'provision',
              3 : 'commander',
              4 : 'standby',
              5 : 'member',
              6 : 'shutdown',
              7 : 'booting',
              8 : 'communicationFailure',
              9 : 'incompatibleOS',
              10 : 'unknownState',
              11 : 'standbyBooting'
              }




normal_state = {
              1 : 'other',
              2 : 'ok',
              3 : 'degraded',
              4 : 'failed'
              }

server_power_state = {
              1 : 'unknown',
              2 : 'poweredOff',
              3 : 'poweredOn',
              4 : 'insufficientPowerOrPowerOnDenied'
              }

log_drv_state = {
              1 : 'other',
              2 : 'ok',
              3 : 'failed',
              4 : 'unconfigured',
              5 : 'recovering',
              6 : 'readyForRebuild',
              7 : 'rebuilding',
              8 : 'wrongDrive',
              9 : 'badConnect',
              10: 'overheating',
              11: 'shutdown',
              12: 'expanding',
              13: 'notAvailable',
              14: 'queuedForExpansion',
              15: 'multipathAccessDegraded',
              16: 'erasing',
              17: 'predictiveSpareRebuildReady',
              18: 'rapidParityInitInProgress',
              19: 'rapidParityInitPending',
              20: 'noAccessEncryptedNoCntlrKey',
              21: 'unencryptedToEncryptedInProgress',
              22: 'newLogDrvKeyRekeyInProgress',
              23: 'noAccessEncryptedCntlrEncryptnNotEnbld',
              24: 'unencryptedToEncryptedNotStarted',
              25: 'newLogDrvKeyRekeyRequestReceived'
              }

phy_drv_state = {
              1 : 'other',
              2 : 'ok',
              3 : 'failed',
              4 : 'predictiveFailure',
              5 : 'erasing',
              6 : 'eraseDone',
              7 : 'eraseQueued',
              8 : 'ssdWearOut',
              9 : 'notAuthenticated'
              }

phy_drv_smrt_state = {
              1 : 'other',
              2 : 'ok',
              3 : 'replaceDrive',
              4 : 'replaceDriveSSDWearOut'
              }

ps_redundant_state = {
              1 : 'other',
              2 : 'notRedundant',
              3 : 'redundant'
              }


oid_hpicfVsfVCOperStatus = '.1.3.6.1.4.1.11.2.14.11.5.1.116.1.1.2.0'
oid_hpicfVsfVCAdminStatus = '.1.3.6.1.4.1.11.2.14.11.5.1.116.1.1.3.0'
oid_hpicfVsfVCMemberState = '.1.3.6.1.4.1.11.2.14.11.5.1.116.1.3.1.9.0'

### from CPQSINFO-MIB
oid_product_name = '.1.3.6.1.4.1.232.2.2.4.2.0'
oid_serial_numb = '.1.3.6.1.4.1.232.2.2.2.1.0'

### from CPQIDA-MIB
# for global state
oid_storage = '.1.3.6.1.4.1.232.3.1.3.0'
oid_system = '.1.3.6.1.4.1.232.6.1.3.0'
oid_glob_power_supply = '.1.3.6.1.4.1.232.6.2.9.1.0'
oid_power_state = '.1.3.6.1.4.1.232.9.2.2.32.0'
oid_glob_temp = '.1.3.6.1.4.1.232.6.2.6.1.0'
oid_glob_temp_sens = '.1.3.6.1.4.1.232.6.2.6.3.0'
oid_glob_fan = '.1.3.6.1.4.1.232.6.2.6.4.0'
oid_mem = '.1.3.6.1.4.1.232.6.2.14.4.0'
oid_ctrl = '.1.3.6.1.4.1.232.3.2.2.1.1.6'

# for physical drive(s)
oid_phy_drv_status = '.1.3.6.1.4.1.232.3.2.5.1.1.6'
oid_phy_drv_smrt = '.1.3.6.1.4.1.232.3.2.5.1.1.57'
oid_phy_drv_temp = '.1.3.6.1.4.1.232.3.2.5.1.1.70'
oid_phy_drv_temp_thres = '.1.3.6.1.4.1.232.3.2.5.1.1.71'

# for logical drive(s)
oid_log_drv = '.1.3.6.1.4.1.232.3.2.3.1.1.4'

# for environment temperature
oid_env_temp = '.1.3.6.1.4.1.232.6.2.6.8.1.4'
oid_env_temp_thres = '.1.3.6.1.4.1.232.6.2.6.8.1.5'

# for fan(s)
oid_fan = '.1.3.6.1.4.1.232.6.2.6.7.1.9'

# for power supply
oid_ps = '.1.3.6.1.4.1.232.6.2.9.3.1.4'
oid_ps_redundant = '.1.3.6.1.4.1.232.6.2.9.3.1.9'


# scan function. Show all Power supplies, fans and pyhsical drives
def scan_ilo():
    helper.status(critical)
    ps_data = walk_data(sess, oid_ps, helper)[0]
    fan_data = walk_data(sess, oid_fan, helper)[0]

    # we don't receive a result, if no physical drives are available.
    phy_drv_status = attempt_walk_data(sess, oid_phy_drv_status)[0]

    helper.add_long_output('Available devices:')
    helper.add_long_output('')

    # show the physical drives
    if phy_drv_status:
        for x, data in enumerate(phy_drv_status, 1):
            helper.add_long_output('Physical drive %d: %s' % (x, phy_drv_state[int(data)]))
    else:
        helper.add_long_output("No physical drives detected")
    # add a empty line after the pyhsical drives
    helper.add_long_output('')

    # show the power supplies
    for x, data in enumerate(ps_data, 1):
        helper.add_long_output('Power supply %d: %s'  % (x, normal_state[int(data)]))
    helper.add_long_output('')

    # show the fans
    for x, data in enumerate(fan_data, 1):
        helper.add_long_output('Fan %d: %s'  % (x, normal_state[int(data)]))

    helper.exit(exit_code=ok, perfdata='')


def check_global_status(flag, name, oid):
    """
    check a global status
    check_global_status(True, "Global Storage", '.1.3.6.1.4.1.232.3.1.3.0')
    """
    # only check the status, if the "no" flag is not set
    if flag:
        # get the data via snmp
        myData = get_data(sess, oid, helper)
        data_summary_output, data_long_output = state_summary(myData, name, normal_state, helper)
        add_output(data_summary_output, data_long_output, helper)

def check_server_power():
    """
    Check if the server is powered on
    Skip this check, if the --noPowerState is set
    """
    if power_state_flag:
        power_state = get_data(sess, oid_power_state, helper)
        power_state_summary_output, power_state_long_output = state_summary(power_state, 'Server power', server_power_state, helper, server_power_state[3])
        add_output(power_state_summary_output, power_state_long_output, helper)

def check_storage_controllers():
    """
    Check the status of the storage controllers
    Skip this check, if --noController is set
    """
    if ctrl_flag:
        ctrl = walk_data(sess, oid_ctrl, helper)[0]
        for x, data in enumerate(ctrl, 1):
            ctrl_summary_output, ctrl_long_output = state_summary(data, 'Controller %d' % x, normal_state, helper)
            add_output(ctrl_summary_output, ctrl_long_output, helper)

def check_temperature_sensors():
    """
    Check all temperature sensors of the server
    All sensors with the value or threshold is -99 or 0 are ignored
    """
    # walk all temperature sensor values and thresholds
    env_temp = walk_data(sess, oid_env_temp, helper)[0]
    env_temp_thresh = walk_data(sess, oid_env_temp_thres, helper)[0]
    env_temp_zipped = zip(env_temp, env_temp_thresh)

    for x, data in enumerate(env_temp_zipped, 1):
        # skip the check if -99 or 0 is in the value or threshold, because these data we can not use
        if '-99' not  in data and '0' not in data:
            #check if the value is over the treshold
            if int(data[0]) > int(data[1]):
                helper.add_summary('Temperature at sensor %d above threshold (%s / %s)' % (x, data[0], data[1]))
                helper.status(critical)
            # always add the sensor to the output
            helper.add_long_output('Temperature %d: %s Celsius (threshold: %s Celsius)' % (x, data[0], data[1]))
            # for the first sensor (envirnoment temperature, we add performance data)
            if x == 1:
                helper.add_metric("Environment Temperature", data[0], '', ":" + data[1], "", "", "Celsius")


# physical drive check
def check_phy_drv(temp_drive_flag, input_phy_drv):
    physical_drive_status = walk_data(sess, oid_phy_drv_status, helper)[0]
    physical_drive_smart = walk_data(sess, oid_phy_drv_smrt, helper)[0]
    physical_drive_temp = walk_data(sess, oid_phy_drv_temp, helper)[0]
    physical_drive_temp_thres = walk_data(sess, oid_phy_drv_temp_thres, helper)[0]
    phy_drv_count_ok = 0
    summary_output = ''
    long_output = ''

    for x, data in enumerate(physical_drive_status, 0):
        if phy_drv_state[int(physical_drive_status[x])] == 'ok' and phy_drv_smrt_state[int(physical_drive_smart[x])] == 'ok':
            # check how many drives in OK state we find
            phy_drv_count_ok += 1
        else:
            # status is not ok
            helper.status(critical)
            summary_output += ('Physical drive %d status: %s ' % (x+1, phy_drv_state[int(physical_drive_status[x])]))
            summary_output += ('Physical drive %d smart status: %s ' % (x+1, phy_drv_smrt_state[int(physical_drive_smart[x])]))

        # we always want to show the drive status in the long output, independend from the status
        long_output += ('Physical drive %d status: %s\n' % (x+1, phy_drv_state[int(physical_drive_status[x])]))
        long_output += ('Physical drive %d smart status: %s\n' % (x+1, phy_drv_state[int(physical_drive_smart[x])]))

        # check of the harddrive temperatures
        if temp_drive_flag:
            # only evaluate the temperatures if temp_drive_flag is not set (--noDriveTemp). We need that for our 15k SAS drives.
            if int(physical_drive_temp[x]) != -1:
                # OID returns -1 if the drive temperature (threshold) cannot be calculated or if the controller does not support reporting drive temperature threshold
                if int(physical_drive_temp_thres[x]) != -1:
                    if int(physical_drive_temp[x]) > int(physical_drive_temp_thres[x]):
                        summary_output += ('Physical drive %d temperature above threshold (%s / %s) ' % (x+1, physical_drive_temp[x], physical_drive_temp_thres[x]))
                        helper.status(critical)
                    long_output += ('Physical drive %d temperature: %s Celsius (threshold: %s Celsius)\n' % (x+1, physical_drive_temp[x], physical_drive_temp_thres[x]))
                else:
                    long_output += ('Physical drive %d temperature: %s Celsius (no threshold given)\n' % (x+1, physical_drive_temp[x]))

    # if the count of the found OK drives does not match the amount of configured drives (--drives parameter)
    if int(phy_drv_count_ok) != int(input_phy_drv):
        summary_output += ('%s physical drive(s) expected - %s physical drive(s) in ok state! ' % (input_phy_drv, phy_drv_count_ok))
        helper.status(critical)

    # Check Logical drive
    logical_drive = walk_data(sess, oid_log_drv, helper)[0]

    for x, data in enumerate(logical_drive, 1):
        log_drv_summary_output, log_drv_long_output = state_summary(data, 'Logical drive %d' % x, log_drv_state, helper)
        summary_output += log_drv_summary_output
        long_output += log_drv_long_output
    return (summary_output, long_output)

# Check power supply
def check_ps():
    """
    Check if the power supplies are ok, and we have the configured amount
    The check is skipped if --ps=0
    """
    if int(input_pwr_sply) != 0:
        ps_data = walk_data(sess, oid_ps, helper)[0]
        ps_ok_count = 0

        for x, state in enumerate(ps_data, 1):
            # human readable status
            hr_status = normal_state[int(state)]
            if  hr_status != "ok":
                # if the power supply is ok, we will set a critical status and add it to the summary
                helper.add_summary('Power supply status %s: %s' % (x, hr_status))
                helper.status(critical)
            else:
                # if everything is ok, we increase the ps_ok_count
                ps_ok_count += 1

            # we always want to see the status in the long output
            helper.add_long_output('Power supply status %s: %s' % (x, hr_status))
        helper.add_long_output('')

        if int(input_pwr_sply) != ps_ok_count:
            # if the confiugred power supplies and power supplies in ok state are different
            helper.add_summary('%s power supplies expected - %s power supplies ok ' % (input_pwr_sply, ps_ok_count))
            helper.status(critical)

def check_power_redundancy():
    """
    Check if the power supplies are redundant
    The check is skipped if --noPowerRedundancy is set
    """
    # skip the check if --noPowerRedundancy is set
    if power_redundancy_flag:
        # walk the data
        ps_redundant_data = walk_data(sess, oid_ps_redundant, helper)[0]

        for x, state in enumerate(ps_redundant_data, 1):
            # human readable status
            hr_status = ps_redundant_state[int(state)]
            if  hr_status != "redundant":
                # if the power supply is not redundant, we will set a critical status and add it to the summary
                helper.add_summary('Power supply %s: %s' % (x, hr_status))
                helper.status(critical)
            # we always want to see the redundancy status in the long output
            helper.add_long_output('Power supply %s: %s' % (x, hr_status))
        helper.add_long_output('')

def check_fan(input_fan):
    """
    check the fans
    """
    # get a list of all fans
    fan_data = walk_data(sess, oid_fan, helper)[0]

    fan_count = 0
    summary_output = ''
    long_output = ''

    for x, fan in enumerate(fan_data, 1):
        fan = int(fan)
        if normal_state[fan] == 'ok':
            # if the fan is ok, we increase the fan_count varaible
            fan_count += 1
        # we always want to the the status in the long output
        long_output += 'Fan %d: %s.\n' % (x, normal_state[fan])

    # check we have the correct amount ok fans in OK state, otherwise set status to critical and print the fan in the summary
    if int(fan_count) != int(input_fan):
        summary_output += '%s fan(s) expected - %s fan(s) ok. ' % (input_fan, fan_count)
        helper.status(critical)
    return (summary_output, long_output)

if __name__ == '__main__':
    # Create default parameter list for snmp classes
    parameter_list = [host, version, community, helper]

    # The default return value should be always OK
    helper.status(ok)

    # verify that a hostname is set
    verify_host(host, helper)

    # verify that seclevel is correctly used, otherwise there will be an exception
    verify_seclevel(seclevel, helper)

    sess = netsnmp.Session(Version=version, DestHost=host, SecLevel=seclevel,  SecName=secname, AuthProto=authproto,
                           AuthPass=authpass, PrivProto=privproto, PrivPass=privpass, Community=community)

    # Show always the product name and the serial number in the summary
    #product_name = get_data(sess, oid_product_name, helper)
    #serial_number = get_data(sess, oid_serial_numb, helper)
    #helper.add_summary('%s - Serial number:%s' % (product_name, serial_number))

    # Check the global status
    #check_global_status(storage_flag, 'Global storage', oid_storage)
    #check_global_status(system_flag,'Global system',oid_system)
    #check_global_status(power_supply_flag,'Global power supply',oid_glob_power_supply)
    #check_global_status(temp_flag,'Overall thermal environment',oid_glob_temp)
    #check_global_status(temp_sens_flag,'Temperature sensors',oid_glob_temp_sens)
    #check_global_status(fan_flag,'Fan(s)',oid_glob_fan)
    #check_global_status(mem_flag,'Memory',oid_mem)
    check_global_status(True, 'VSF VC Operational', oid_hpicfVsfVCOperStatus)
    check_global_status(True, 'VSF 2', oid_hpicfVsfVCAdminStatus)
    check_global_status(True, 'VSF 3', oid_hpicfVsfVCMemberState)

    # Print out plugin information and exit nagios-style
    helper.exit()
