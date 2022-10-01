# coding=utf-8
import os
import re
import string
import sys
import time

from appilog.common.system.types.vectors import ObjectStateHolderVector
from appilog.common.system.types import ObjectStateHolder

from com.hp.ucmdb.discovery.library.clients import ClientsConsts
from com.hp.ucmdb.discovery.library.common import CollectorsParameters
# from com.hp.ucmdb.discovery.library.communication.downloader import ConfigFilesManagerImpl
# from xml.dom.minidom import parse
# Java imports
from java.io import File
from java.io import FileOutputStream
from java.lang import Exception, Boolean
from org.jdom.input import SAXBuilder


import WMI_Connection_Utils
import errormessages
import logger
import modeling
import netutils
import nmap
# from modeling import finalizeHostOsh
from shellutils import ShellFactory

PORT_TYPE_NAMES_DICT = {'tcp': modeling.SERVICEADDRESS_TYPE_TCP, 'udp': modeling.SERVICEADDRESS_TYPE_UDP}

HOST_CLASS_DICT = {
    "Windows": "nt",
    "HP-UX": "unix",
    "SunOS": "unix",
    "Solaris": "unix",
    "OpenBSD": "unix",
    "NetWare": "netware",
    "NeXTStep": "host",
    "UX/4800": "host",
    "BSD-misc": "unix",
    "Minix": "host",
    "Windows Longhorn": "nt",
    "DOS": "nt",
    "VM/CMS": "mainframe",
    "OS/2": "host",
    "OS/390": "mainframe",
    "Linux": "unix",
    "Mac OS X": "unix",
    "OS/400": "as400",
    "FreeBSD": "unix",
    "NetBSD": "unix",
    "AIX": "unix",
    "Digital UNIX": "unix",
    "DragonFly BSD": "unix"}

SOFTWARE_NAMES_DICT = {
    "mysql": "MySQL DB",
    "tomcat": "Apache WebServer",
    "microsoft.*sql": "MSSQL DB",
    "ibm db2": "IBM DB2",
    "microsoft.*iis": "Microsoft IIS WebServer",
    "weblogic.*server": "WebLogic AS",
    "websphere.*server": "WebSphere AS",
    "vmware.*virtualcenter": "VMware VirtualCenter",
    "vmware esx": "Virtualization Layer Software",
    "microsoft exchange server": "Microsoft Exchange Server"}


def getDomain(dns, defaultValue=None):
    if not dns.replace('.', '').isdigit() and '.' in dns:
        return dns[dns.find('.')+1:]
    else:
        return defaultValue

# ----------------------------------------НОВОЕ----------------------------------------
ip_dict = dict()
def dictionaryFilling(list_ip, list_id):
    for index in range(len(list_ip)):
        ip_dict[list_ip[index]] = list_id[index]



def syncNmapPortConfigFile(agentPath):
    '''
        Sync nmap port config with global probe's "port number to port name" mapping
    '''
    logger.debug('synchronizing nmap port config file')
    portConfigFilename = agentPath + CollectorsParameters.getDiscoveryConfigFolder() + CollectorsParameters.FILE_SEPARATOR + 'portNumberToPortName.xml'

    mamservice = File(portConfigFilename)
    nmapservice = File(
        agentPath + CollectorsParameters.getDiscoveryResourceFolder() + CollectorsParameters.FILE_SEPARATOR + 'nmap-services')

    if nmapservice.lastModified() > mamservice.lastModified():
        return
    nmapFile = FileOutputStream(nmapservice)
    document = SAXBuilder(0).build(mamservice)
    #    document = parse(portConfigFilename)

    ports = XmlWrapper(document.getRootElement().getChildren('portInfo'))
    for port in ports:
        if int(port.getAttributeValue("discover")):
            portNumber = port.getAttributeValue("portNumber")
            portName = port.getAttributeValue("portName")
            portProtocol = port.getAttributeValue("portProtocol")
            nmapFile.write("%s\t%s/%s\r\n" % (portName, portNumber, portProtocol))
    nmapFile.close()


class XmlWrapper:
    '''
    Due to bug in jython 2.1 we can't use xml.dom.minidom.
    Just a glue class for connecting Java and Jython XML Elements.
    '''

    def __init__(self, xmlElements):
        self.elements = []
        iterator = xmlElements.iterator()
        while iterator.hasNext():
            self.elements.append(iterator.next())
        self.len = len(self.elements)

    def __len__(self):
        return self.len

    def __getitem__(self, index):
        return self.elements[index]


def performNmapDiscover(client, ip, tmpFilename, timeout, agent_ext_dir, scanKnownPortsOnly, portstoscan,
                        doServiceFingerprints, discoverUdpPorts, nmapLocation=None):
    #    default port scaninng is -sS
    parametersList = ['-O', '-osscan-guess', '-sS']
    if doServiceFingerprints:
        parametersList.append('-sV')
    if discoverUdpPorts:
        parametersList.append('-sU')
    if portstoscan:
        parametersList.append('-p ' + portstoscan)
    if scanKnownPortsOnly:
        parametersList.append('-F')
    parametersList.append('--host-timeout ' + str(timeout) + 'ms')
    parametersList.append(ip)
    parametersList.append('-oX ' + tmpFilename)
    logger.debug('start executing nmap')
    shell = ShellFactory().createShell(client)
    nmapLocation = nmap.getNmapLocation(shell, nmapLocation)

    if nmapLocation:
        nmapLocation = '"' + nmapLocation + '"'
    else:
        nmapLocation = nmap.NMAP_EXECUTABLES[0]
    command = ' '.join([nmapLocation] + parametersList)
    if not shell.isWinOs():
        command = "sudo " + command

    output = client.executeCmd(command, timeout)

    if output.find('is not recognized') != -1:
        errormsg = "NMAP is not installed on Probe machine, or please check the nmap location is configured correctly."
        logger.error(errormsg)
        raise ValueError, errormsg

    logger.debug('end executing nmap')

def processNmapResult(fileName, OSHVResult, discoverOsName, doServiceFingerprints, global_id, Framework):
    try:
        document = SAXBuilder(0).build(fileName)
    except:
        raise ValueError, "Can't parse XML document with nmap results. Skipped."

    hosts = XmlWrapper(document.getRootElement().getChildren('host'))

    location = "Nmap"

    for host in hosts:
        hostOsh = None
        hostOshMy = None
        ip = None
        macs = []
        addresses = XmlWrapper(host.getChildren('address'))
        for address in addresses:
            type = address.getAttributeValue('addrtype')
            addr = address.getAttributeValue('addr')

            if type == 'ipv4':
                ip = addr
            elif type == 'mac':
                macs.append(addr)

        hostnames = host.getChild('hostnames')
        if (hostnames is not None) and netutils.isValidIp(ip):
            hostnames = map(lambda elem: elem.getAttributeValue('name'), XmlWrapper(hostnames.getChildren('hostname')))
            hostname = hostnames and hostnames[0] or None  # using only first dnsname

            os = host.getChild('os')
            if os and discoverOsName:
                osClass = os.getChild('osclass')
                if not osClass:
                    osMatch = os.getChild('osmatch')
                    if osMatch is not None:
                        osClass = osMatch.getChild('osclass')
                if osClass:
                    osType = osClass.getAttributeValue("type")
                    osFamily = osClass.getAttributeValue("osfamily")
                    osVendor = osClass.getAttributeValue("vendor")

                    hostClass = getHostClass(osType, osFamily)
                    if not hostClass:
                        Framework.reportWarning("Unknown OS detected. Vendor '%s', family '%s'" % (osVendor, osFamily))
                        hostClass = "host"


                    hostOsh = modeling.createHostOSH(ip, hostClass)
                    hostOshMy = ObjectStateHolder("ip_address")
                    hostOshMy.setStringAttribute("name", ip) # Ключ
                    hostOshMy.setStringAttribute("global_id", global_id)

                    hostOshMy.setStringAttribute("ca_node_type", hostClass)
                    hostOshMy.setStringAttribute("ca_node_os_vendor", osVendor)

                    hostOsh.setAttribute("host_vendor", osVendor)
                    osMatch = os.getChild('osmatch')
                    if osMatch:
                        separateCaption(hostOsh, osMatch.getAttributeValue("name"))
                        hostOsh.setAttribute("host_osaccuracy", osMatch.getAttributeValue("accuracy") + '%')

                        hostOshMy.setStringAttribute("ca_node_os_name", osMatch.getAttributeValue("name"))
                        hostOshMy.setStringAttribute("ca_node_os_accuracy", osMatch.getAttributeValue("accuracy") + '%')

            if not hostOsh and not hostOshMy:
                hostOsh = modeling.createHostOSH(ip)
                hostOshMy = ObjectStateHolder("ip_address")
                hostOshMy.setStringAttribute("name", ip)
                hostOshMy.setStringAttribute("global_id", global_id)

            hostname = None if hostname == ip else hostname

            if hostname:
                domain = getDomain(hostname)
                hostOshMy.setStringAttribute("ca_domain", domain)

            hostOshMy.setStringAttribute("ca_primary_dns_name", hostname)
            try:
                hostOshMy.setStringAttribute("ca_node_role", str(hostOsh.getAttribute('node_role').getValue()))
            except:
                hostOshMy.setStringAttribute("ca_node_role", None)

            for mac in macs:
                if netutils.isValidMac(mac):
                    hostOshMy.setStringAttribute("ca_interface", mac)

            portsAndServiceNameList = []
            if not host.getChild('ports'):
                return
            ports = XmlWrapper(host.getChild('ports').getChildren('port'))
            for port in ports:
                portNumber = port.getAttributeValue('portid')
                logger.debug(portNumber)
                protocol = port.getAttributeValue('protocol')
                serviceName = None
                if doServiceFingerprints:
                    if port.getChild("state").getAttributeValue("state").find('open') == -1:
                        continue
                    serviceNode = port.getChild("service")
                    if serviceNode:
                        serviceName = serviceNode.getAttributeValue("name")
                        portsAndServiceNameList.append("{}:{} ({})".format(str(ip),str(portNumber),serviceName))
            hostOshMy.setStringAttribute("ca_ip_service_endpoint_network_port_info", '; '.join(portsAndServiceNameList))
            hostOshMy.setStringAttribute("ca_location", location)

            OSHVResult.add(hostOshMy)

def getHostClass(osType, osFamily):
    if osType == "general purpose":
        hclass = HOST_CLASS_DICT.get(osFamily)
    elif osType == "router":
        hclass = "router"
    elif osType == "printer":
        hclass = "netprinter"
    else:
        hclass = "host"
    return hclass


def separateCaption(hostOSH, caption):
    if caption.find('Windows') > -1:
        spList = re.findall('SP(\\d)', caption)
        if len(spList) == 1:
            sp = spList[0]
            hostOSH.setAttribute('nt_servicepack', sp)
        else:
            logger.debug('Service pack cannot be identified, discovered value: \'%s\'; skipping SP attribute' % caption)
        caption = WMI_Connection_Utils.separateCaption(caption)[1]
    modeling.setHostOsName(hostOSH, caption)


def sendObjectsIntoUcmdb(Framework, OSHVResult, count_objects):
    for i in range(0, OSHVResult.size(), count_objects):
        limit = i + count_objects
        if limit >= OSHVResult.size():
            limit = OSHVResult.size()

        vector = OSHVResult.getSubVector(i, limit)
        Framework.sendObjects(vector)
        Framework.flushObjects()
        vector.clear()


def DiscoveryMain(Framework):
    OSHVResult = ObjectStateHolderVector()

    cc_ip_addresses = Framework.getTriggerCIDataAsList('cc_ip_addresses')

    ip_addresses = Framework.getTriggerCIDataAsList('ip_addresses')
    ip_ids = Framework.getTriggerCIDataAsList('ip_ids')
    dictionaryFilling(ip_addresses, ip_ids)

    timeout = Framework.getParameter('nmap_host_timeout')
    if not str(timeout).isdigit():
        msg = "Timeout parameter value must be a digit"
        logger.debug(msg)
        errormessages.resolveAndReport(msg, ClientsConsts.LOCAL_SHELL_PROTOCOL_NAME, Framework)
        return OSHVResult

    timeout = int(timeout) * 100
    scanKnownPortsOnly = Boolean.parseBoolean(Framework.getParameter('scan_known_ports_only'))
    portstoscan = Framework.getParameter('scan_these_ports_only')
    doServiceFingerprints = Boolean.parseBoolean(Framework.getParameter('Perform_Port_Fingerprints'))
    createApp = Boolean.parseBoolean(Framework.getParameter('Create_Application_CI'))
    discoverOsName = Boolean.parseBoolean(Framework.getParameter('discover_os_name'))
    count_objects = int(Framework.getParameter('count_objects'))
    nmapLocation = Framework.getParameter('nmap_location')
    # discover_UDP_Ports    = int(Framework.getParameter('Discover_UDP_Ports'))
    discoverUdpPorts = 0
    agent_root_dir = CollectorsParameters.BASE_PROBE_MGR_DIR
    agent_ext_dir = agent_root_dir + CollectorsParameters.getDiscoveryResourceFolder() + CollectorsParameters.FILE_SEPARATOR
    syncNmapPortConfigFile(agent_root_dir)


    try:
        client = Framework.createClient(ClientsConsts.LOCAL_SHELL_PROTOCOL_NAME)
        count = 0
        for ip in cc_ip_addresses:
            count += 1
            if count > 20:
                break
            try:
                tmp_file_name = agent_ext_dir + string.replace(ip, '.', '_') + time.strftime("%H%M%S", time.gmtime(
                    time.time())) + 'nmap.xml'
                logger.debug('temp file for storing nmap results: ', tmp_file_name)
                performNmapDiscover(client, ip, tmp_file_name, timeout, agent_ext_dir, scanKnownPortsOnly, portstoscan,
                                    doServiceFingerprints, discoverUdpPorts, nmapLocation)

                if os.path.exists(tmp_file_name):
                    processNmapResult(tmp_file_name, OSHVResult, discoverOsName, doServiceFingerprints, ip_dict[ip], Framework)
                else:
                    raise ValueError, 'Error nmap result file is missing: %s' % tmp_file_name
            finally:
                File(tmp_file_name).delete()
    except Exception, e:
        msg = str(e.getMessage())
        logger.debug(msg)
        errormessages.resolveAndReport(msg, ClientsConsts.LOCAL_SHELL_PROTOCOL_NAME, Framework)
    except ValueError:
        msg = str(sys.exc_info()[1])
        errormessages.resolveAndReport(msg, ClientsConsts.LOCAL_SHELL_PROTOCOL_NAME, Framework)
    except:
        msg = logger.prepareJythonStackTrace('')
        logger.debug(msg)
        errormessages.resolveAndReport(msg, ClientsConsts.LOCAL_SHELL_PROTOCOL_NAME, Framework)

    sendObjectsIntoUcmdb(Framework, OSHVResult, count_objects)
    client.close()
    return OSHVResult
