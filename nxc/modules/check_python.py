from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from nxc.helpers.misc import CATEGORY

class NXCModule:
    name = "check_python"
    description = "Enumerates Python installations via WMI (Win32_Product)"
    supported_protocols = ["wmi"]
    opsec_safe = True
    multiple_hosts = True
    category = CATEGORY.ENUMERATION

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options(self, context, module_options):
        """
        Module used to test and see if python is on a Windows system

        USAGE:
        nxc wmi <target> -u <user> -p <pass> -M check_python
        """

    def on_admin_login(self, context, connection):
        try:
            dcom = DCOMConnection(
                connection.host,
                connection.username,
                connection.password,
                connection.domain,
                connection.lmhash,
                connection.nthash,
                oxidResolver=True,
                doKerberos=connection.kerberos,
                kdcHost=connection.kdcHost
            )

            iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            namespace = "root\\CIMV2"
            iWbemServices = iWbemLevel1Login.NTLMLogin(namespace, NULL, NULL)
            iWbemServices.get_dce_rpc().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

            query = "SELECT Name, Version, InstallLocation FROM Win32_Product WHERE Name LIKE '%Python%'"
            enum = iWbemServices.ExecQuery(query)

            found = False
            try:
                while True:
                    obj = enum.Next(0xffffffff, 1)[0]
                    name = obj.Name
                    version = obj.Version
                    location = obj.InstallLocation

                    if location:
                        context.log.highlight(f"[+] Found: {name} (Version: {version}) in {location}")
                    else:
                        context.log.highlight(f"[+] Found: {name} (Version: {version}) — install path not reported")

                    found = True
            except Exception:
                pass

            if not found:
                context.log.highlight("[-] No Python installations found via WMI.")

            iWbemLevel1Login.RemRelease()
            iWbemServices.RemRelease()
            dcom.disconnect()

        except Exception as e:
            context.log.fail(f"Error during WMI Python check: {e}")
