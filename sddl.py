"""
sddl.py - Module for parsing and analyzing Security Descriptor Definition Language (SDDL) strings.

This module provides functions to:

- Parse SDDL strings into their components (owner, group, DACL, SACL).
- Parse individual Access Control Entries (ACEs) within DACLs and SACLs.
- Interpret ACE components (type, flags, rights, trustee).
- Map ACE components to human-readable descriptions using a lookup table from a CSV file (accessenums.csv).
- Generate a human-readable summary of an SDDL string, including an impact analysis.

Global Variables:
    _ACCESS_ENUMS_DATA: A list of dictionaries, where each dictionary represents a row from the accessenums.csv file.
                       This data is loaded once and used for lookups in various functions.

"""

import csv
import os
from typing import Dict, List, Tuple, Any
from enum import Enum
import re

def parse_sddl(sddl: str) -> Dict:
    """
    Parse SDDL string into components.

    Args:
        sddl: The SDDL string to parse.

    Returns:
        A dictionary representing the parsed SDDL components.
        Returns an empty dictionary if the SDDL string is invalid or empty.
    """
    sddl = sddl.strip()
    if not sddl:
        return {}

    parts = re.findall(r'([OGDS]):([^:]+?)(?=(?:[OGDS]:|$))', sddl)
    result = {}

    for tag, content in parts:
        content = content.strip('()')
        if content:
            result[tag] = content

    return result

_ACCESS_ENUMS_DATA = []

def _load_access_enums_data():
    """
    Parses the access enums CSV file and caches the results.

    The CSV file (accessenums.csv) is expected to be in the same directory as this script.
    It reads the CSV data into the global _ACCESS_ENUMS_DATA list.
    """
    global _ACCESS_ENUMS_DATA
    if not _ACCESS_ENUMS_DATA:
        csv_path = os.path.join(os.path.dirname(__file__), "accessenums.csv")
        try:
            with open(csv_path, "r") as f:
                reader = csv.DictReader(f)
                _ACCESS_ENUMS_DATA = list(reader)
        except FileNotFoundError:
            print(f"Error: accessenums.csv not found at {csv_path}")
            _ACCESS_ENUMS_DATA = [] 
        except Exception as e:
            print(f"Warning: Failed to load accessenums.csv: {e}")
            _ACCESS_ENUMS_DATA = []

class AceType(Enum):
    ACCESS_ALLOWED = "A"
    ACCESS_DENIED = "D"
    SYSTEM_AUDIT = "SA"
    SYSTEM_ALARM = "AL"
    ACCESS_ALLOWED_COMPOUND = "XA"
    ACCESS_ALLOWED_CALLBACK = "ZA"
    ACCESS_DENIED_CALLBACK = "XD"
    ACCESS_ALLOWED_OBJECT = "OA"
    ACCESS_DENIED_OBJECT = "OD"
    SYSTEM_AUDIT_OBJECT = "OU"
    SYSTEM_ALARM_OBJECT = "AU"
    ACCESS_ALLOWED_CALLBACK_OBJECT = "ZO"
    ACCESS_DENIED_CALLBACK_OBJECT = "XU"
    SYSTEM_AUDIT_CALLBACK = "XF"
    SYSTEM_ALARM_CALLBACK = "ZG"
    SYSTEM_AUDIT_CALLBACK_OBJECT = "ZS"
    SYSTEM_ALARM_CALLBACK_OBJECT = "ZU"
    MANDATORY_LABEL = "ML"

class AceFlag(Enum):
    CONTAINER_INHERIT = "CI"
    OBJECT_INHERIT = "OI"
    NO_PROPAGATE_INHERIT = "NP"
    INHERIT_ONLY = "IO"
    INHERITED = "ID"
    SUCCESSFUL_ACCESS = "SA"
    FAILED_ACCESS = "FA"
    TRUST_PROTECTED_FILTER = "TP"
    CRITICAL = "CR"

class StandardRight(Enum):
    """
    Enum for standard access rights.
    """
    READ_CONTROL = "RC"
    DELETE = "SD"
    WRITE_DAC = "WD"
    WRITE_OWNER = "WO"
    SYNCHRONIZE = "SY"
    ACCESS_SYSTEM_SECURITY = "AS"
    GENERIC_ALL = "GA"
    GENERIC_EXECUTE = "GX"
    GENERIC_WRITE = "GW"
    GENERIC_READ = "GR"

class FileRight(Enum):
    """
    Enum for file-specific access rights.
    """
    FILE_READ_DATA = "FR"
    FILE_WRITE_DATA = "FW"
    FILE_APPEND_DATA = "FA"
    FILE_READ_EA = "FE"
    FILE_WRITE_EA = "WE"
    FILE_EXECUTE = "FX"
    FILE_DELETE_CHILD = "DC"
    FILE_READ_ATTRIBUTES = "RA"
    FILE_WRITE_ATTRIBUTES = "WA"

class RegistryRight(Enum):
    """
    Enum for registry-specific access rights.
    """
    KEY_QUERY_VALUE = "KQ"
    KEY_SET_VALUE = "KS"
    KEY_CREATE_SUB_KEY = "KC"
    KEY_ENUMERATE_SUB_KEYS = "KE"
    KEY_NOTIFY = "KN"
    KEY_CREATE_LINK = "KL"
    KEY_WOW64_64KEY = "K64"
    KEY_WOW64_32KEY = "K32"
    KEY_WOW64_RES = "KR"

class DirectoryServiceRight(Enum):
    """
    Enum for directory service-specific access rights.
    """
    DS_CREATE_CHILD = "CC"
    DS_DELETE_CHILD = "DC"
    DS_LIST_CONTENTS = "LC"
    DS_SELF = "SW"
    DS_READ_PROP = "RP"
    DS_WRITE_PROP = "WP"
    DS_DELETE_TREE = "DT"
    DS_LIST_OBJECT = "LO"
    DS_CONTROL_ACCESS = "CR"

class MandatoryLabelRight(Enum):
    """
    Enum for mandatory label rights.
    """
    NO_READ_UP = "NR"
    NO_WRITE_UP = "NW"
    NO_EXECUTE_UP = "NX"

SDDL_FLAGS = {
    'P': "Protected - prevents the security descriptor from being modified by inheritable ACEs",
    'AR': "Auto Inherit Required - indicates that auto-inheritance is required",
    'AI': "Auto Inherited - indicates that the security descriptor or object is auto-inherited"
}

ACE_TYPES = {
    'A': 'ACCESS_ALLOWED',
    'D': 'ACCESS_DENIED',
    'OA': 'ACCESS_ALLOWED_OBJECT',
    'OD': 'ACCESS_DENIED_OBJECT',
    'AU': 'SYSTEM_AUDIT',
    'AL': 'SYSTEM_ALARM',
    'OU': 'SYSTEM_AUDIT_OBJECT',
    'OL': 'SYSTEM_ALARM_OBJECT',
    'ML': 'MANDATORY_LABEL',
    'XA': 'ACCESS_ALLOWED_COMPOUND',
    'ZA': 'ACCESS_ALLOWED_CALLBACK',
    'XD': 'ACCESS_DENIED_CALLBACK',
    'ZO': 'ACCESS_ALLOWED_CALLBACK_OBJECT',
    'XU': 'ACCESS_DENIED_CALLBACK_OBJECT',
    'XF': 'SYSTEM_AUDIT_CALLBACK',
    'ZG': 'SYSTEM_ALARM_CALLBACK',
    'ZS': 'SYSTEM_AUDIT_CALLBACK_OBJECT',
    'ZU': 'SYSTEM_ALARM_CALLBACK_OBJECT',
    'OBJECT_ACCESS_ALLOWED': 'Object-specific Allow Access',
    'OBJECT_ACCESS_DENIED': 'Object-specific Deny Access',
    'OBJECT_SYSTEM_AUDIT': 'Object-specific System Audit'
}

ACE_FLAGS = {
    'CI': 'CONTAINER_INHERIT',
    'OI': 'OBJECT_INHERIT',
    'NP': 'NO_PROPAGATE_INHERIT',
    'IO': 'INHERIT_ONLY',
    'ID': 'INHERITED',
    'SA': 'SUCCESSFUL_ACCESS',
    'FA': 'FAILED_ACCESS',
    'TP': 'TRUST_PROTECTED_FILTER',
    'CR': 'CRITICAL'
}

RIGHTS = {
    # Standard rights
    'RC': 'READ_CONTROL',
    'SD': 'DELETE',
    'WD': 'WRITE_DAC',
    'WO': 'WRITE_OWNER',
    'SY': 'SYNCHRONIZE',
    'AS': 'ACCESS_SYSTEM_SECURITY',
    'GA': 'GENERIC_ALL',
    'GX': 'GENERIC_EXECUTE',
    'GW': 'GENERIC_WRITE',
    'GR': 'GENERIC_READ',
    # File rights
    'FA': 'FILE_ALL_ACCESS',
    'FR': 'FILE_READ_DATA',
    'FW': 'FILE_WRITE_DATA',
    'FX': 'FILE_EXECUTE',
    # Registry rights
    'KA': 'KEY_ALL_ACCESS',
    'KR': 'KEY_READ',
    'KW': 'KEY_WRITE',
    'KX': 'KEY_EXECUTE',
    # Directory service rights
    'RP': 'Read properties',
    'WP': 'Modify properties',
    'CC': 'Create child objects',
    'DC': 'Delete child objects',
    'LC': 'List folder contents',
    'SW': 'Self-write operations',
    'LO': 'List object contents',
    'DT': 'Delete entire folder trees',
    'CR': 'Special control operations',
    # Mandatory label rights
    'NR': 'No read up',
    'NW': 'No write up',
    'NX': 'No execute up',
    # Common AD permission combinations
    'SWWPRC': 'Special Write, Write Property, Read Control',
    'CCDCLCSWRPWPDTLOCRSDRCWDWO': 'Create/Delete Child, List Contents, Read/Write Properties, Delete Tree, List Object, Control Access, Delete, Read/Write DACL, Read/Write Owner',
    'LCRPLORC': 'List Contents, Read Properties, List Object, Read Control',
    'CCLCSWRPWPLOCRSDRCWDWO': 'Create Child, List Contents, Write/Read Properties, List Object, Control Access, Delete, Read/Write DACL, Write Owner'
}

TRUSTEES = {
    'AO': 'Account Operators',
    'AC': 'Authenticated Users',
    'AN': 'Anonymous Logon',
    'AU': 'Authenticated Users',
    'BA': 'Built-in Administrators',
    'BG': 'Built-in Guests',
    'BO': 'Backup Operators',
    'BU': 'Built-in Users',
    'CA': 'Certificate Server Administrators',
    'CD': 'Certificate Issuers',
    'CG': 'Creator Group',
    'CO': 'Creator Owner',
    'DA': 'Domain Administrators',
    'DC': 'Domain Computers',
    'DD': 'Domain Controllers',
    'DG': 'Domain Guests',
    'DU': 'Domain Users',
    'EA': 'Enterprise Administrators',
    'ED': 'Enterprise Domain Controllers',
    'EF': 'Everyone',
    'ER': 'Event Log Readers',
    'ES': 'Authenticated Users',
    'IU': 'Interactively Logged On User',
    'LA': 'Local Administrator',
    'LG': 'Local Guest',
    'LS': 'Local Service',
    'LU': 'Local Users',
    'MU': 'Performance Monitor Users',
    'NO': 'Network Configuration Operators',
    'NS': 'Network Service',
    'NU': 'Network Users',
    'OW': 'Owner Rights',
    'PA': 'Group Policy Administrators',
    'PO': 'Printer Operators',
    'PS': 'Self',
    'PU': 'Power Users',
    'RC': 'Restricted Code',
    'RD': 'Terminal Server Users',
    'RE': 'Replicator',
    'RO': 'Enterprise Read-only Domain Controllers',
    'RS': 'RAS Servers',
    'RU': 'Alias to allow previous Windows 2000',
    'SA': 'Schema Administrators',
    'SO': 'Server Operators',
    'SU': 'Service',
    'SY': 'Local System',
    'UD': 'Users',
    'WD': 'Everyone'
}

SDDL_EXAMPLES = {
    "Deny Everyone Write DAC": {
        "sddl": "D:(D;;WD;;;WD)",
        "description": "Denies write access to the DACL (Discretionary Access Control List) to Everyone. This prevents any user, regardless of their other permissions, from modifying the permissions on the object."
    },
    "Allow Authenticated Users Read and Execute": {
        "sddl": "D:(A;;0x1200a9;;;AU)",
        "description": "Grants Authenticated Users read access (0x1200a9) to the object. This allows any user who has logged in with a valid username and password to read the contents and attributes of the object."
    },
    "Allow Administrators Full Control": {
        "sddl": "D:(A;;FA;;;BA)",
        "description": "Grants the Built-in Administrators group full control (FA) over the object. This allows members of the Administrators group to perform any operation on the object, including reading, writing, modifying, and deleting it."
    },
    "Deny Anonymous Logon Read Access": {
        "sddl": "D:(D;;GR;;;AN)",
        "description": "Denies read access (GR) to the Anonymous Logon group. This prevents users who have not logged in with a valid username and password from reading the object."
    },
    "Allow Everyone Read, Write, and Execute": {
        "sddl": "D:(A;;GA;;;WD)",
        "description": "Grants Everyone full control (GA) over the object. This is generally not recommended for security reasons, as it allows any user, even unauthenticated ones, to perform any operation on the object."
    },
    "Allow Creator Owner Modify": {
        "sddl": "D:(A;;0x1301bf;;;CO)",
        "description": "Grants the Creator Owner specific modify permissions (0x1301bf) over the object. This allows the user who created the object to modify its contents and attributes."
    },
    "Deny Network Users Delete": {
        "sddl": "D:(D;;SD;;;NU)",
        "description": "Denies delete access (SD) to Network Users. This prevents users who are accessing the object over the network from deleting it."
    },
    "Allow Interactive Users Read and Write": {
        "sddl": "D:(A;;0x120116;;;IU)",
        "description": "Grants Interactive Users specific read and write permissions (0x120116) over the object. This allows users who are logged in locally to the machine to read and modify the object."
    },
    "Audit Failure for Everyone Delete": {
        "sddl": "S:(AU;FA;SD;;;WD)",
        "description": "Sets up auditing to log failed attempts (FA) by Everyone to delete (SD) the object. This helps track unsuccessful attempts to delete the object for security monitoring."
    },
    "Allow System Full Control with Inheritance": {
        "sddl": "D:(A;OICI;FA;;;SY)",
        "description": "Grants the Local System account full control (FA) over the object and specifies that these permissions should be inherited (OICI) by child objects (both containers and objects)."
    },
    "Deny Guests Write Access": {
        "sddl": "D:(D;;0x100002;;;BG)",
        "description": "Denies write access (0x100002) to the Built-in Guests group. This prevents members of the Guests group from modifying the object."
    },
    "Allow Backup Operators Read": {
        "sddl": "D:(A;;GR;;;BO)",
        "description": "Grants read access (GR) to Backup Operators. This allows members of the Backup Operators group to read the object, typically for backup purposes."
    },
    "Audit Success for Authenticated Users Write": {
        "sddl": "S:(AU;SA;GW;;;AU)",
        "description": "Sets up auditing to log successful attempts (SA) by Authenticated Users to write (GW) to the object. This helps track successful modifications to the object for security monitoring."
    },
    "Allow Power Users Modify with Container Inherit": {
        "sddl": "D:(A;CI;0x1301bf;;;PU)",
        "description": "Grants Power Users specific modify permissions (0x1301bf) over the object and specifies that these permissions should be inherited (CI) by child containers (folders)."
    },
    "Deny Anonymous Logon Write and Execute": {
        "sddl": "D:(D;;0x100112;;;AN)",
        "description": "Denies write and execute access (0x100112) to the Anonymous Logon group. This prevents users who have not logged in with a valid username and password from modifying or executing the object."
    },
    "Allow Domain Admins Full Control with Object Inherit": {
        "sddl": "D:(A;OI;FA;;;DA)",
        "description": "Grants the Domain Admins group full control (FA) over the object and specifies that these permissions should be inherited (OI) by child objects (files)."
    },
    "Audit Failure for Guests Read": {
        "sddl": "S:(AU;FA;GR;;;BG)",
        "description": "Sets up auditing to log failed attempts (FA) by the Built-in Guests group to read (GR) the object. This helps track unsuccessful attempts to read the object for security monitoring."
    },
    "Allow Everyone Read with No Propagate": {
        "sddl": "D:(A;NP;GR;;;WD)",
        "description": "Grants Everyone read access (GR) over the object but prevents these permissions from being inherited (NP) by child objects."
    },
    "Deny Creator Owner Delete Child": {
        "sddl": "D:(D;CIIO;DC;;;CO)",
        "description": "Denies the Creator Owner the ability to delete child objects (DC) and specifies that this denial should be inherited (CIIO) by child containers (folders) and objects (files)."
    },
    "Allow Authenticated Users Read, Write, and Execute with Inherit Only": {
        "sddl": "D:(A;IO;0x120116;;;AU)",
        "description": "Grants Authenticated Users specific read, write, and execute permissions (0x120116) over the object but specifies that these permissions should only be inherited (IO) by child objects and not applied directly to the object itself."
    },
    "Audit Success for Interactive Users Full Control": {
        "sddl": "S:(AU;SA;FA;;;IU)",
        "description": "Sets up auditing to log successful attempts (SA) by Interactive Users to perform any operation (FA) on the object. This helps track successful access and modifications to the object for security monitoring."
    },
    "Deny Network Service Write DAC": {
        "sddl": "D:(D;;WD;;;NS)",
        "description": "Denies write access to the DACL (WD) to the Network Service account. This prevents the Network Service from modifying the permissions on the object."
    },
    "Allow Local Service Read and Execute": {
        "sddl": "D:(A;;0x1200a9;;;LS)",
        "description": "Grants the Local Service account specific read and execute permissions (0x1200a9) over the object. This allows the Local Service to read the contents and attributes of the object and execute it if it's an executable."
    },
    "Audit Failure for Everyone Write Attributes": {
        "sddl": "S:(AU;FA;0x100080;;;WD)",
        "description": "Sets up auditing to log failed attempts (FA) by Everyone to write attributes (0x100080) to the object. This helps track unsuccessful attempts to modify the object's attributes for security monitoring."
    },
    "Allow System Full Control with Container and Object Inherit": {
        "sddl": "D:(A;CIOI;FA;;;SY)",
        "description": "Grants the Local System account full control (FA) over the object and specifies that these permissions should be inherited by both child containers (CI) and objects (OI)."
    },
    "Deny Guests Read Attributes": {
        "sddl": "D:(D;;RA;;;BG)",
        "description": "Denies read attributes access (RA) to the Built-in Guests group. This prevents members of the Guests group from viewing the attributes of the object."
    },
    "Allow Backup Operators Execute with Container Inherit": {
        "sddl": "D:(A;CI;GX;;;BO)",
        "description": "Grants Backup Operators execute access (GX) over the object and specifies that these permissions should be inherited (CI) by child containers (folders)."
    },
    "Audit Success for Authenticated Users Read with Object Inherit": {
        "sddl": "S:(AU;OI;SA;GR;;;AU)",
        "description": "Sets up auditing to log successful attempts (SA) by Authenticated Users to read (GR) the object and specifies that this audit setting should be inherited (OI) by child objects (files)."
    },
    "Allow Power Users Delete with Inherit Only": {
        "sddl": "D:(A;IO;SD;;;PU)",
        "description": "Grants Power Users delete access (SD) over the object but specifies that these permissions should only be inherited (IO) by child objects and not applied directly to the object itself."
    },
    "Deny Anonymous Logon Delete": {
        "sddl": "D:(D;;SD;;;AN)",
        "description": "Denies delete access (SD) to the Anonymous Logon group. This prevents users who have not logged in with a valid username and password from deleting the object."
    },
    "Allow Domain Admins Write DAC with Container and Object Inherit": {
        "sddl": "D:(A;CIOI;WD;;;DA)",
        "description": "Grants the Domain Admins group write access to the DACL (WD) over the object and specifies that these permissions should be inherited (CI) by child containers (folders)."
    },
    "Audit Failure for Guests Read and Execute": {
        "sddl": "S:(AU;FA;0x1200a9;;;BG)",
        "description": "Sets up auditing to log failed attempts (FA) by the Built-in Guests group to perform specific read and execute operations (0x1200a9) on the object. This helps track unsuccessful attempts to access or execute the object for security monitoring."
    },
    "Allow Everyone Full Control with No Propagate": {
        "sddl": "D:(A;NP;FA;;;WD)",
        "description": "Grants Everyone full control (FA) over the object but prevents these permissions from being inherited (NP) by child objects."
    },
    "Deny Creator Owner Write": {
        "sddl": "D:(D;OI;GW;;;CO)",
        "description": "Denies write access (GW) to the Creator Owner and specifies that this denial should be inherited (OI) by child objects (files)."
    },
    "Allow Authenticated Users Read and Execute with Container Inherit": {
        "sddl": "D:(A;CI;0x1200a9;;;AU)",
        "description": "Grants Authenticated Users specific read and execute permissions (0x1200a9) over the object and specifies that these permissions should be inherited (CI) by child containers (folders)."
    },
    "Audit Success for Interactive Users Full Control": {
        "sddl": "S:(AU;SA;FA;;;IU)",
        "description": "Sets up auditing to log successful attempts (SA) by Interactive Users to perform any operation (FA) on the object. This helps track successful access and modifications to the object for security monitoring."
    },
    "Deny Network Service Write": {
        "sddl": "D:(D;;GW;;;NS)",
        "description": "Denies write access (GW) to the Network Service account. This prevents the Network Service from modifying the object."
    },
    "Allow Local Service Delete": {
        "sddl": "D:(A;;SD;;;LS)",
        "description": "Grants the Local Service account delete access (SD) over the object. This allows the Local Service to delete the object."
    },
    "Audit Failure for Everyone Read Attributes": {
        "sddl": "S:(AU;FA;RA;;;WD)",
        "description": "Sets up auditing to log failed attempts (FA) by Everyone to read the attributes (RA) of the object. This helps track unsuccessful attempts to view the object's attributes for security monitoring."
    },
    "Allow System Modify with Container and Object Inherit": {
        "sddl": "D:(A;CIOI;0x1301bf;;;SY)",
        "description": "Grants the Local System account specific modify permissions (0x1301bf) over the object and specifies that these permissions should be inherited by both child containers (CI) and objects (OI)."
    },
    "Deny Guests Delete": {
        "sddl": "D:(D;;SD;;;BG)",
        "description": "Denies delete access (SD) to the Built-in Guests group. This prevents members of the Guests group from deleting the object."
    },
    "Allow Backup Operators Read and Execute with No Propagate Inherit": {
        "sddl": "D:(A;NP;0x1200a9;;;BO)",
        "description": "Grants Backup Operators specific read and execute permissions (0x1200a9) over the object but prevents these permissions from being inherited (NP) by child objects."
    },
    "Audit Success for Authenticated Users Write with Object Inherit": {
        "sddl": "S:(AU;OI;SA;GW;;;AU)",
        "description": "Sets up auditing to log successful attempts (SA) by Authenticated Users to write (GW) to the object and specifies that this audit setting should be inherited (OI) by child objects (files)."
    },
    "Allow Power Users Execute with Container and Object Inherit": {
        "sddl": "D:(A;CIOI;GX;;;PU)",
        "description": "Grants Power Users execute access (GX) over the object and specifies that these permissions should be inherited by both child containers (CI) and objects (OI)."
    },
    "Deny Anonymous Logon Read": {
        "sddl": "D:(D;;GR;;;AN)",
        "description": "Denies read access (GR) to the Anonymous Logon group. This prevents users who have not logged in with a valid username and password from reading the object."
    },
    "Allow Domain Admins Delete with Inherit Only": {
        "sddl": "D:(A;IO;SD;;;DA)",
        "description": "Grants the Domain Admins group delete access (SD) over the object but specifies that these permissions should only be inherited (IO) by child objects and not applied directly to the object itself."
    },
    "Audit Failure for Guests Modify": {
        "sddl": "S:(AU;FA;0x1301bf;;;BG)",
        "description": "Sets up auditing to log failed attempts (FA) by the Built-in Guests group to perform specific modify operations (0x1301bf) on the object. This helps track unsuccessful attempts to modify the object for security monitoring."
    },
    "Allow Everyone Read with Container Inherit": {
        "sddl": "D:(A;CI;GR;;;WD)",
        "description": "Grants Everyone read access (GR) over the object and specifies that these permissions should be inherited (CI) by child containers (folders)."
    },
    "Deny Creator Owner Execute": {
        "sddl": "D:(D;OI;GX;;;CO)",
        "description": "Denies execute access (GX) to the Creator Owner and specifies that this denial should be inherited (OI) by child objects (files)."
    },
    "Allow Authenticated Users Delete with No Propagate": {
        "sddl": "D:(A;NP;SD;;;AU)",
        "description": "Grants Authenticated Users delete access (SD) over the object but prevents these permissions from being inherited (NP) by child objects."
    },
    "Audit Success for Interactive Users Read": {
        "sddl": "S:(AU;SA;GR;;;IU)",
        "description": "Sets up auditing to log successful attempts (SA) by Interactive Users to read (GR) the object. This helps track successful reads of the object for security monitoring."
    },
    "Deny Network Service Read and Execute": {
        "sddl": "D:(D;;0x1200a9;;;NS)",
        "description": "Denies specific read and execute permissions (0x1200a9) to the Network Service account. This prevents the Network Service from reading or executing the object."
    },
    "Allow Local Service Write": {
        "sddl": "D:(A;;GW;;;LS)",
        "description": "Grants the Local Service account write access (GW) over the object. This allows the Local Service to modify the object."
    },
    "Audit Failure for Everyone Delete": {
        "sddl": "S:(AU;FA;SD;;;WD)",
        "description": "Sets up auditing to log failed attempts (FA) by Everyone to delete (SD) the object. This helps track unsuccessful attempts to delete the object for security monitoring."
    },
    "Allow System Read with Container and Object Inherit": {
        "sddl": "D:(A;CIOI;GR;;;SY)",
        "description": "Grants the Local System account read access (GR) over the object and specifies that these permissions should be inherited by both child containers (CI) and objects (OI)."
    },
    "Deny Guests Read": {
        "sddl": "D:(D;;GR;;;BG)",
        "description": "Denies read access (GR) to the Built-in Guests group. This prevents members of the Guests group from reading the object."
    },
    "Allow Backup Operators Write": {
        "sddl": "D:(A;;GW;;;BO)",
        "description": "Grants Backup Operators write access (GW) over the object. This allows Backup Operators to modify the object."
    },
    "Audit Success for Authenticated Users Execute": {
        "sddl": "S:(AU;SA;GX;;;AU)",
        "description": "Sets up auditing to log successful attempts (SA) by Authenticated Users to execute (GX) the object. This helps track successful execution of the object for security monitoring."
    },
    "Allow Power Users Read": {
        "sddl": "D:(A;;GR;;;PU)",
        "description": "Grants Power Users read access (GR) over the object. This allows Power Users to read the object."
    },
    "Deny Anonymous Logon Write": {
        "sddl": "D:(D;;GW;;;AN)",
        "description": "Denies write access (GW) to the Anonymous Logon group. This prevents users who have not logged in with a valid username and password from modifying the object."
    },
    "Allow Domain Admins Full Control with Inherit Only": {
        "sddl": "D:(A;IO;FA;;;DA)",
        "description": "Grants the Domain Admins group full control (FA) over the object but specifies that these permissions should only be inherited (IO) by child objects and not applied directly to the object itself."
    },
    "Audit Failure for Guests Delete": {
        "sddl": "S:(AU;FA;SD;;;BG)",
        "description": "Sets up auditing to log failed attempts (FA) by the Built-in Guests group to delete (SD) the object. This helps track unsuccessful attempts to delete the object for security monitoring."
    },
    "Allow Everyone Write": {
        "sddl": "D:(A;;GW;;;WD)",
        "description": "Grants Everyone write access (GW) over the object. This allows anyone to modify the object."
    },
    "Deny Creator Owner Read and Execute": {
        "sddl": "D:(D;OI;0x1200a9;;;CO)",
        "description": "Denies specific read and execute permissions (0x1200a9) to the Creator Owner and specifies that this denial should be inherited (OI) by child objects (files)."
    },
    "Allow Authenticated Users Full Control with No Propagate": {
        "sddl": "D:(A;NP;FA;;;AU)",
        "description": "Grants Authenticated Users full control (FA) over the object but prevents these permissions from being inherited (NP) by child objects."
    },
    "Audit Success for Interactive Users Write": {
        "sddl": "S:(AU;SA;GW;;;IU)",
        "description": "Sets up auditing to log successful attempts (SA) by Interactive Users to write (GW) to the object. This helps track successful modifications to the object for security monitoring."
    },
    "Deny Network Service Delete": {
        "sddl": "D:(D;;SD;;;NS)",
        "description": "Denies delete access (SD) to the Network Service account. This prevents the Network Service from deleting the object."
    },
    "Allow Local Service Execute": {
        "sddl": "D:(A;;GX;;;LS)",
        "description": "Grants the Local Service account execute access (GX) over the object. This allows the Local Service to execute the object if it's an executable."
    },
    "Audit Failure for Everyone Write": {
        "sddl": "S:(AU;FA;GW;;;WD)",
        "description": "Sets up auditing to log failed attempts (FA) by Everyone to write (GW) to the object. This helps track unsuccessful attempts to modify the object for security monitoring."
    },
    "Allow System Execute with Container and Object Inherit": {
        "sddl": "D:(A;CIOI;GX;;;SY)",
        "description": "Grants the Local System account execute access (GX) over the object and specifies that these permissions should be inherited by both child containers (CI) and objects (OI)."
    },
    "Deny Guests Full Control": {
        "sddl": "D:(D;;FA;;;BG)",
        "description": "Denies full control (FA) to the Built-in Guests group. This prevents members of the Guests group from performing any operation on the object."
    },
    "Allow Backup Operators Delete": {
        "sddl": "D:(A;;SD;;;BO)",
        "description": "Grants Backup Operators delete access (SD) over the object. This allows Backup Operators to delete the object."
    },
    "Audit Success for Authenticated Users Delete": {
        "sddl": "S:(AU;SA;SD;;;AU)",
        "description": "Sets up auditing to log successful attempts (SA) by Authenticated Users to delete (SD) the object. This helps track successful deletions of the object for security monitoring."
    },
    "Allow Power Users Write": {
        "sddl": "D:(A;;GW;;;PU)",
        "description": "Grants Power Users write access (GW) over the object. This allows Power Users to modify the object."
    },
    "Deny Anonymous Logon Execute": {
        "sddl": "D:(D;;GX;;;AN)",
        "description": "Denies execute access (GX) to the Anonymous Logon group. This prevents users who have not logged in with a valid username and password from executing the object if it's an executable."
    },
    "Allow Domain Admins Read and Execute with Inherit Only": {
        "sddl": "D:(A;IO;0x1200a9;;;DA)",
        "description": "Grants the Domain Admins group specific read and execute permissions (0x1200a9) over the object but specifies that these permissions should only be inherited (IO) by child objects and not applied directly to the object itself."
    },
    "Audit Failure for Guests Read and Execute": {
        "sddl": "S:(AU;FA;0x1200a9;;;BG)",
        "description": "Sets up auditing to log failed attempts (FA) by the Built-in Guests group to perform specific read and execute operations (0x1200a9) on the object. This helps track unsuccessful attempts to access or execute the object for security monitoring."
    },
    "Allow Everyone Read Attributes": {
        "sddl": "D:(A;;RA;;;WD)",
        "description": "Grants Everyone read attributes access (RA) over the object. This allows anyone to view the attributes of the object."
    },
    "Deny Creator Owner Write Attributes": {
        "sddl": "D:(D;OI;WA;;;CO)",
        "description": "Denies write attributes access (WA) to the Creator Owner and specifies that this denial should be inherited (OI) by child objects (files)."
    },
    "Allow Authenticated Users Read and Write with Container Inherit": {
        "sddl": "D:(A;CI;0x120116;;;AU)",
        "description": "Grants Authenticated Users specific read and write permissions (0x120116) over the object and specifies that these permissions should be inherited (CI) by child containers (folders)."
    },
    "Audit Success for Interactive Users Read and Write": {
        "sddl": "S:(AU;SA;0x120116;;;IU)",
        "description": "Sets up auditing to log successful attempts (SA) by Interactive Users to perform specific read and write operations (0x120116) on the object. This helps track successful access and modifications to the object for security monitoring."
    },
    "Deny Network Service Read": {
        "sddl": "D:(D;;GR;;;NS)",
        "description": "Denies read access (GR) to the Network Service account. This prevents the Network Service from reading the object."
    }
}

WELL_KNOWN_SIDS = {
    # System and Built-in SIDs
    "S-1-5-18": "NT AUTHORITY\\SYSTEM",
    "S-1-5-19": "NT AUTHORITY\\LOCAL SERVICE",
    "S-1-5-20": "NT AUTHORITY\\NETWORK SERVICE",
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-32-546": "BUILTIN\\Guests",
    
    # Service SIDs
    "S-1-5-80": "NT SERVICE",
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464": "NT SERVICE\\WinDefend",
    "S-1-5-80-3880718306-3832830129-1677859214-2598158968-1052248003": "NT SERVICE\\wuauserv",
    "S-1-5-80-3245704983-3664226991-764670653-2504430226-901976451": "NT SERVICE\\MSSQLSERVER",
    "S-1-5-80-2652535364-2169709536-2857650723-2622804123-1107741775": "NT SERVICE\\SQLAgent",
    "S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420": "NT SERVICE\\WdiServiceHost",
    
    # Application Package SIDs
    "S-1-15-2-1": "ALL APPLICATION PACKAGES",
    "S-1-15-2-2": "ALL RESTRICTED APPLICATION PACKAGES",
    
    # IIS Application Pool SIDs
    "S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415": "IIS APPPOOL\\DefaultAppPool",
    
    # Common Application SIDs
    "S-1-5-80-3263513310-3392720605-1798839546-683002060-3227631582": "NT SERVICE\\MpsSvc",
    "S-1-5-80-1770670200-1234567890-1234567890-1234567890": "NT SERVICE\\Spooler",
    
    # Virtualization SIDs
    "S-1-5-83-1-2208521892-2773530980-1950616755-1856941799": "NT VIRTUAL MACHINE",
    
    # Security Package SIDs
    "S-1-5-64-10": "NT AUTHORITY\\NTLM Authentication",
    "S-1-5-64-14": "NT AUTHORITY\\SChannel Authentication",
    "S-1-5-64-21": "NT AUTHORITY\\Digest Authentication"
}

_ACCESS_ENUMS_DATA = []

def _load_access_enums_data():
    """Parses the access enums CSV file and caches the results."""
    global _ACCESS_ENUMS_DATA
    if not _ACCESS_ENUMS_DATA:
        csv_path = os.path.join(os.path.dirname(__file__), "accessenums.csv")
        try:
            with open(csv_path, "r") as f:
                reader = csv.DictReader(f)
                _ACCESS_ENUMS_DATA = list(reader)
        except Exception as e:
            print(f"Warning: Failed to load accessenums.csv: {e}")
    return _ACCESS_ENUMS_DATA

def get_flag_description(flag: str) -> str:
    """Provides detailed explanation of what each flag means"""
    descriptions = {
        'CI': 'This permission will be inherited by child containers (like subfolders)',
        'OI': 'This permission will be inherited by child objects (like files)',
        'NP': 'This permission will not propagate to child objects',
        'IO': 'This ACE only applies to inherited objects',
        'ID': 'This ACE was inherited from a parent object',
        'SA': 'Generates audit messages for successful access attempts',
        'FA': 'Generates audit messages for failed access attempts',
        'TP': 'ACE is trust-protected',
        'CR': 'ACE is critical and cannot be removed'
    }
    return descriptions.get(flag, 'No description available')

def get_right_description(right: str) -> str:
    """Get a human-readable description of a right."""
    if right in RIGHTS:
        return RIGHTS[right]
    
    permissions = parse_complex_permission(right)
    if permissions:
        if len(permissions) == 1:
            return permissions[0]
        return ' + '.join(permissions)
    
    return "Custom or undefined permission set"

def get_trustee_description(trustee: str) -> str:
    """Provides context about who the trustee is"""
    if trustee in WELL_KNOWN_SIDS:
        return f"Security Principal: {WELL_KNOWN_SIDS[trustee]}"
    
    if trustee.startswith('S-1-'):
        for sid_prefix, description in WELL_KNOWN_SIDS.items():
            if trustee.startswith(sid_prefix):
                return f"Security Principal (type: {description})"
        return f"Security Identifier (SID): {trustee}"

def get_access_details(access_mask, access_type="FileSystemRights"):
    """Get detailed access rights information from hex mask"""
    data = _load_access_enums_data()
    results = []
    try:
        if isinstance(access_mask, str):
            access_mask = int(access_mask, 16) if '0x' in access_mask else int(access_mask)
            
        for entry in data:
            if entry["Type"] == access_type:
                hex_value = int(entry["HexValue"], 16)
                if access_mask & hex_value == hex_value:
                    results.append({
                        "Name": entry["Name"],
                        "HexValue": entry["HexValue"],
                        "Value": entry["Value"],
                        "Description": entry["Description"],
                        "Details": entry["Details"]
                    })
    except Exception as e:
        print(f"Warning: Error processing access mask {access_mask}: {e}")
    
    return results

def get_access_type_description(rights_str: str) -> str:
    """Determine what type of access this is based on accessenums.csv data"""
    data = _load_access_enums_data()
    try:
        if rights_str.startswith('0x'):
            rights_val = int(rights_str, 16)
            
            rights_by_type = {}
            for entry in data:
                if rights_val & int(entry['HexValue'], 16) == int(entry['HexValue'], 16):
                    rights_type = entry['Type']
                    if rights_type not in rights_by_type:
                        rights_by_type[rights_type] = []
                    rights_by_type[rights_type].append(entry)
            
            if rights_by_type:
                primary_type = max(rights_by_type.items(), key=lambda x: len(x[1]))[0]
                matching_rights = rights_by_type[primary_type]
                
                full_rights = [r for r in matching_rights if 'Full' in r['Name'] or 'GenericAll' in r['Name']]
                if full_rights:
                    return f"full {primary_type.lower().replace('rights', '')} access"
                
                rights_names = [r['Name'].lower() for r in matching_rights]
                return f"{primary_type.lower().replace('rights', '')} {', '.join(rights_names)}"
        
        rights_mapping = {
            'FA': 'full file access',
            'KA': 'full registry access',
            'GA': 'full generic access',
            'FR': 'file read access',
            'KR': 'registry read access',
            'GR': 'generic read access',
            'FW': 'file write access',
            'KW': 'registry write access',
            'GW': 'generic write access'
        }
        
        return rights_mapping.get(rights_str, 'access')
        
    except Exception as e:
        return f"access (error: {str(e)})"

def generate_sddl_summary(sddl_string: str) -> Dict[str, Any]:
    """Enhanced SDDL summary generation with comprehensive security analysis."""
    summary = {
        'impact_level': 'Low',
        'impact': 'Limited impact - restricted access',
        'key_findings': [],
        'recommendations': []
    }
    
    if 'D:' in sddl_string:
        dacl_part = sddl_string.split('D:')[1].split('S:')[0] if 'S:' in sddl_string else sddl_string.split('D:')[1]
        
        high_risk_perms = ['GA', 'WD', 'WO', 'FA', 'GW', 'GX']
        found_risks = [p for p in high_risk_perms if p in dacl_part]
        
        if found_risks:
            summary['impact_level'] = 'High'
            summary['impact'] = 'High impact - includes powerful permissions that could affect system security'
            for risk in found_risks:
                summary['key_findings'].append(f'Contains {RIGHTS.get(risk, risk)} permission')
                summary['recommendations'].append(f'Review necessity of {RIGHTS.get(risk, risk)} permission')

        inheritance_flags = ['CI', 'OI', 'IO', 'NP']
        found_flags = [f for f in inheritance_flags if f in dacl_part]
        if found_flags:
            summary['key_findings'].append('Inheritance settings detected:')
            for flag in found_flags:
                summary['key_findings'].append(f'- {ACE_FLAGS[flag]}: {get_flag_description(flag)}')
            summary['recommendations'].append('Verify inheritance settings align with security requirements')

        if 'D;' in dacl_part:
            summary['key_findings'].append('Contains explicit deny rules')
            summary['recommendations'].append('Verify deny rules are properly ordered (they should come first)')
            summary['recommendations'].append('Test deny rules to ensure they don\'t unintentionally block legitimate access')

        if 'WD' in dacl_part or 'AN' in dacl_part:
            summary['key_findings'].append('Contains permissions for Everyone or Anonymous users')
            summary['recommendations'].append('Review and justify any permissions granted to Everyone or Anonymous')
            summary['impact_level'] = 'High'

        if 'SY' in dacl_part or 'BA' in dacl_part:
            summary['key_findings'].append('Contains System or Built-in Admin permissions')
            summary['recommendations'].append('Ensure elevated permissions are required')

    if 'S:' in sddl_string:
        sacl_part = sddl_string.split('S:')[1]
        summary['key_findings'].append('Includes auditing rules (SACL)')
        
        if 'SA' in sacl_part:
            summary['key_findings'].append('- Success auditing enabled')
        if 'FA' in sacl_part:
            summary['key_findings'].append('- Failure auditing enabled')
        
        summary['recommendations'].extend([
            'Configure audit log retention policy',
            'Monitor audit logs regularly',
            'Set up alerts for critical events',
            'Ensure audit policy aligns with security requirements'
        ])

    if not summary['recommendations']:
        summary['recommendations'].extend([
            'Document these permissions in security baseline',
            'Implement regular permission reviews',
            'Consider implementing least-privilege access'
        ])

    if summary['impact_level'] == 'Low' and (summary['key_findings'] or summary['recommendations']):
        summary['impact_level'] = 'Moderate'
        summary['impact'] = 'Moderate impact - contains standard permission settings'

    return summary

def parse_ace(ace_string: str) -> Dict:
    """Parse individual ACE string into components"""
    ace_string = ace_string.strip('()')
    ace_string = ace_string.strip('()')
    
    parts = [p.strip() for p in ace_string.split(';')]
    
    def parse_rights(rights_str):
        if rights_str.startswith('0x'):
            return rights_str
        return rights_str

    while len(parts) < 6:
        parts.append('')

    return {
        'type': parts[0],
        'flags': parts[1],
        'rights': parse_rights(parts[2]),
        'object_guid': parts[3],
        'inherit_object_guid': parts[4],
        'trustee': parts[5]
    }

def format_ace_details(ace_dict: dict) -> dict:
    """Formats ACE details for display."""
    formatted_details = {
        'type': {
            'value': ACE_TYPES.get(ace_dict['type'], ace_dict['type']),
            'description': get_flag_description(ace_dict['type'])
        },
        'flags': [],
        'rights': [],
        'trustee': {
            'value': TRUSTEES.get(ace_dict['trustee'], ace_dict['trustee']),
            'description': get_trustee_description(ace_dict['trustee'])
        }
    }

    if ace_dict['flags']:
        for flag in ace_dict['flags'].split():
            formatted_details['flags'].append({
                'name': ACE_FLAGS.get(flag, flag),
                'description': get_flag_description(flag)
            })

    rights_str = ace_dict['rights']
    if rights_str.startswith('0x'):
        details = get_access_details(rights_str)
        for detail in details:
            formatted_details['rights'].append({
                'name': detail['Name'],
                'description': detail['Description'] or detail['Details']
            })
    else:
        for right in rights_str.split():
            formatted_details['rights'].append({
                'name': RIGHTS.get(right, right),
                'description': get_right_description(right)
            })

    return formatted_details

def get_ace_display_data(ace_str: str) -> Dict:
    try:
        ace_parts = parse_ace(ace_str)
        if not ace_parts:
            return {'error': 'Invalid ACE format'}

        access_type = ace_parts['type']
        if access_type.startswith('OA'):
            access_type = 'OBJECT_ACCESS_ALLOWED'
        elif access_type.startswith('OD'):
            access_type = 'OBJECT_ACCESS_DENIED'
        elif access_type.startswith('OU'):
            access_type = 'OBJECT_SYSTEM_AUDIT'
        elif access_type.startswith('A'):
            access_type = 'ACCESS_ALLOWED'
        elif access_type.startswith('D'):
            access_type = 'ACCESS_DENIED'
        elif access_type.startswith('AU'):
            access_type = 'SYSTEM_AUDIT'
        
        permissions = []
        if ace_parts.get('rights'):
            rights = ace_parts['rights'].split()
            for right in rights:
                right_info = {
                    'name': RIGHTS.get(right, right),
                    'description': get_right_description(right)
                }
                permissions.append(right_info)

        return {
            'what': access_type,
            'who': ace_parts.get('trustee', ''),
            'who_details': get_trustee_description(ace_parts.get('trustee', '')),
            'permissions': permissions,
            'special_conditions': [{'name': flag, 'description': get_flag_description(flag)} 
                                 for flag in ace_parts.get('flags', '').split()],
            'type_description': ACE_TYPES.get(access_type, access_type)
        }
    except Exception as e:
        return {'error': f'Error parsing ACE: {str(e)}'}

def _process_acl_for_summary(acl_content: str, acl_type: str) -> List[str]:
    """Process ACL content and return a list of human-readable summaries."""
    summaries = []
    
    aces = [ace.strip() for ace in acl_content.split(')') if ace.strip()]
    aces = [f"{ace})" for ace in aces]
    
    for ace in aces:
        try:
            ace_data = get_ace_display_data(ace.strip())
            if 'error' in ace_data:
                summaries.append(f"⚠️ Error processing ACE: {ace_data['error']}")
                continue
                
            action = "Allow" if ace_data['what'].startswith("ACCESS_ALLOWED") else "Deny"
            who = ace_data['who']
            rights = [right['name'] for right in ace_data['permissions']]
            conditions = [flag['name'] for flag in ace_data['special_conditions']]
            
            summary = f"- {action}: {who} can {', '.join(rights)}"
            if conditions:
                summary += f" (with conditions: {', '.join(conditions)})"
            
            summaries.append(summary)
            
        except Exception as e:
            summaries.append(f"⚠️ Error processing ACE {ace}: {str(e)}")
    
    return summaries

def _generate_impact_assessment(permissions: List[str]) -> str:
    """Generate an impact assessment based on the permissions list."""
    if not permissions:
        return "No permissions specified"
        
    allows = len([p for p in permissions if p.startswith("- Allow")])
    denies = len([p for p in permissions if p.startswith("- Deny")])
    
    high_impact_keywords = ["Full control", "Write", "Modify", "Delete", "Take ownership"]
    has_high_impact = any(keyword.lower() in str(permissions).lower() 
                         for keyword in high_impact_keywords)
    
    # Generate assessment
    if has_high_impact:
        return "⚠️ High impact - contains permissions that can modify or delete content"
    elif allows > denies:
        return "📊 Moderate impact - primarily grants access"
    elif denies > allows:
        return "🛡️ Restrictive - primarily denies access"
    else:
        return "ℹ️ Mixed impact - balanced between grants and denies"

def get_access_type_description(ace_type: str) -> str:
    """Get a human-readable description of an access type."""
    descriptions = {
        'A': "Allows the specified permissions",
        'D': "Denies the specified permissions",
        'OA': "Object-specific allow permissions",
        'OD': "Object-specific deny permissions",
        'AU': "Audit success and failure",
        'AL': "Audit success only",
        'AF': "Audit failure only"
    }
    return descriptions.get(ace_type, "Custom or undefined access type")

def parse_complex_permission(permission: str) -> List[str]:
    """Break down a complex permission string into its components."""
    if permission in RIGHTS:
        return [RIGHTS[permission]]
    
    for context, perms in CONTEXT_PERMISSIONS.items():
        if permission in perms:
            return [f"{perms[permission]} ({context})"]
    
    known_segments = {
        'FA': 'File All Access',
        'FR': 'File Read',
        'FW': 'File Write',
        'FX': 'File Execute',
        
        # Registry
        'KA': 'Key All Access',
        'KR': 'Key Read',
        'KW': 'Key Write',
        'KX': 'Key Execute',
        
        # Generic
        'GA': 'Generic All',
        'GR': 'Generic Read',
        'GW': 'Generic Write',
        'GX': 'Generic Execute',
        
        # Common Operations
        'CC': 'Create Child',
        'DC': 'Delete Child',
        'LC': 'List Contents',
        'SW': 'Self Write',
        'RP': 'Read Property',
        'WP': 'Write Property',
        'DT': 'Delete Tree',
        'LO': 'List Object',
        'CR': 'Control Rights',
        'SD': 'Delete',
        'RC': 'Read Control',
        'WD': 'Write DACL',
        'WO': 'Write Owner',
        
        # Extended Operations
        'CA': 'Change Password',
        'DS': 'Delete Subtree',
        'PS': 'Personal Info',
        'SS': 'Service State',
        'DU': 'Duplicate',
        'IO': 'Identity Object',
        
        # Common Combinations
        'RPWP': 'Read/Write Property',
        'CCDC': 'Create/Delete Child',
        'WDWO': 'Write DACL/Owner'
    }
    
    result = []
    i = 0
    while i < len(permission):
        found = False
        for length in [4, 3, 2]:
            if i + length <= len(permission):
                segment = permission[i:i+length]
                if segment in known_segments:
                    result.append(known_segments[segment])
                    i += length
                    found = True
                    break
        if not found:
            i += 1
    
    if not result and any(x in permission for x in ['CCDCLCSWRPWPDTLOCRSDRCWDWO', 'CCLCSWRPWPLOCRSDRCWDWO']):
        return ['Full Control (All Permissions)']
    
    return result if result else ["Custom or undefined permission set"]

# Add to the RIGHTS dictionary
RIGHTS.update({
    # File System Rights
    'FA': 'File All Access',
    'FR': 'File Read',
    'FW': 'File Write',
    'FX': 'File Execute',
    'SD': 'Delete',
    'RC': 'Read Control',
    'WD': 'Write DAC',
    'WO': 'Write Owner',

    # Registry Rights
    'KA': 'Key All Access',
    'KR': 'Key Read',
    'KW': 'Key Write',
    'KX': 'Key Execute',
    
    # Active Directory Rights
    'RPWP': 'Read Property, Write Property',
    'CCDC': 'Create Child, Delete Child',
    'LCSWRP': 'List Contents, Write Property, Read Property',
    'WDWO': 'Write DAC, Write Owner',
    'LCRP': 'List Contents, Read Property',
    'DCLC': 'Delete Child, List Contents',
    'WPRP': 'Write Property, Read Property',
    'GWGR': 'Generic Write, Generic Read',
    
    # Generic Rights
    'GA': 'Generic All',
    'GR': 'Generic Read',
    'GW': 'Generic Write',
    'GX': 'Generic Execute',
    
    # Common Combined Rights
    'SYNC': 'Synchronize',
    'RP': 'Read Property',
    'WP': 'Write Property',
    'CC': 'Create Child',
    'DC': 'Delete Child',
    'LC': 'List Contents',
    'LO': 'List Object',
    'DT': 'Delete Tree',
    'CR': 'Control Rights',
    'SW': 'Self Write',
    'RC': 'Read Control',
    'WD': 'Write DACL',
    'WO': 'Write Owner',

    # Extended Rights
    'CA': 'Change Password',
    'DS': 'Delete Subtree',
    'PS': 'Personal Information',
    'SS': 'Service State',
    'DU': 'Duplicate',
    'LO': 'List Object',
    'IO': 'Identity Object',
    
    # Common AD Permission Combinations
    'RPWPCR': 'Read Property, Write Property, Control Rights',
    'LCRPLORC': 'List Contents, Read Property, List Object, Read Control',
    'CCDCLCSWRPWPDTLOCRSDRCWDWO': 'Full Control (Create/Delete Child, List Contents, Read/Write Properties, Delete Tree, etc.)',
    'SWWPRC': 'Self Write, Write Property, Read Control',
    'LCCCRCWP': 'List Contents, Create Child, Control Rights, Write Property'
})

# Add context-specific permission sets
CONTEXT_PERMISSIONS = {
    'FileSystem': {
        'FA': 'Full Control',
        'FR': 'Read',
        'FW': 'Write',
        'FX': 'Execute',
        'SD': 'Delete',
        'RC': 'Read Control',
        'WD': 'Write DAC',
        'WO': 'Write Owner'
    },
    'Registry': {
        'KA': 'Full Control',
        'KR': 'Read',
        'KW': 'Write',
        'KX': 'Execute',
        'RC': 'Read Control',
        'WD': 'Write DAC',
        'WO': 'Write Owner'
    },
    'ActiveDirectory': {
        'DS': 'Delete Subtree',
        'CR': 'Control Rights',
        'CC': 'Create Child',
        'DC': 'Delete Child',
        'LC': 'List Contents',
        'LO': 'List Object',
        'RP': 'Read Property',
        'WP': 'Write Property',
        'DT': 'Delete Tree'
    }
}

def parse_rights(rights_str: str) -> List[str]:
    """Parse rights string into individual rights."""
    if not rights_str:
        return []
    # Handle hex format
    if rights_str.startswith('0x'):
        return [rights_str]
    # Split rights by any non-alphanumeric character
    return [r for r in re.split(r'[^A-Za-z0-9]+', rights_str) if r]

__all__ = [
    'SDDL_FLAGS',
    'ACE_TYPES', 
    'ACE_FLAGS',
    'RIGHTS',
    'TRUSTEES',
    'SDDL_EXAMPLES',
    'WELL_KNOWN_SIDS',
    'get_flag_description',
    'get_right_description',
    'get_trustee_description',
    'get_access_details',
    'get_access_type_description',
    'generate_sddl_summary',
    'parse_ace'
]
