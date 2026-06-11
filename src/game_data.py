"""
Scenario and mission content for KQL Detective.
"""

from __future__ import annotations

from typing import Any, Dict, List


TABLE_SCHEMAS: Dict[str, List[str]] = {
    "DeviceProcessEvents": [
        "Timestamp",
        "DeviceName",
        "AccountName",
        "FileName",
        "ProcessCommandLine",
        "InitiatingProcessFileName",
        "SHA1",
    ],
    "DeviceNetworkEvents": [
        "Timestamp",
        "DeviceName",
        "InitiatingProcessFileName",
        "InitiatingProcessCommandLine",
        "RemoteIP",
        "RemotePort",
        "Protocol",
    ],
    "DeviceRegistryEvents": [
        "Timestamp",
        "DeviceName",
        "ActionType",
        "RegistryKey",
        "RegistryValueName",
        "RegistryValueData",
        "InitiatingProcessFileName",
    ],
    "DeviceLogonEvents": [
        "Timestamp",
        "DeviceName",
        "AccountName",
        "LogonType",
        "InitiatingProcessFileName",
        "IsLocalAdmin",
    ],
}


KEYWORDS = [
    "where",
    "project",
    "distinct",
    "summarize",
    "count",
    "order",
    "by",
    "take",
    "top",
    "contains",
    "has",
    "startswith",
    "endswith",
    "and",
    "or",
    "not",
    "join",
]


SCENARIO: Dict[str, Any] = {
    "title": "KQL Detective: Attachment Breach",
    "subtitle": "A suspicious document execution triggered a Defender alert minutes before outbound beaconing.",
    "briefing": (
        "You are the junior analyst on shift. A finance user opened a document from email. "
        "The alert queue is noisy, your lead is busy, and you need to reconstruct what happened "
        "by writing KQL queries against Defender-like telemetry."
    ),
    "stakes": (
        "If you miss the pivot points, the attacker may keep persistence on the endpoint and "
        "expand access before containment."
    ),
    "missions": [
        {
            "id": "m1",
            "title": "Find The Compromised Device",
            "goal": "Identify which device ran the suspicious encoded PowerShell command.",
            "narrative": (
                "The initial alert mentions obfuscated PowerShell. Start in process telemetry "
                "and isolate the device behind the execution."
            ),
            "illustration": "mail",
            "allowed_tables": ["DeviceProcessEvents"],
            "concepts": ["where", "contains", "project or distinct"],
            "starting_query": (
                "DeviceProcessEvents\n"
                "| where FileName == \"powershell.exe\"\n"
                "| where ProcessCommandLine contains \"EncodedCommand\"\n"
                "| project Timestamp, DeviceName, AccountName, ProcessCommandLine"
            ),
            "checks": [
                {"type": "contains", "value": "deviceprocessevents", "message": "Start from process telemetry."},
                {"type": "contains", "value": "powershell.exe", "message": "Target the PowerShell execution."},
                {"type": "any", "values": ["encodedcommand", "processcommandline contains"], "message": "Filter on the obfuscated command line."},
            ],
            "success_answer": "FIN-WS-17",
            "success_rows": [
                {
                    "Timestamp": "2026-06-02T08:12:41Z",
                    "DeviceName": "FIN-WS-17",
                    "AccountName": "emma.clark",
                    "ProcessCommandLine": "powershell.exe -EncodedCommand SQBFAFgA",
                }
            ],
            "success_message": "The infected workstation is `FIN-WS-17`. You have your first solid pivot.",
            "hint": "Look for `powershell.exe` plus a command line clue such as `EncodedCommand`.",
        },
        {
            "id": "m2",
            "title": "Trace The Parent Process",
            "goal": "Determine what launched the suspicious PowerShell instance on FIN-WS-17.",
            "narrative": (
                "Now that the host is known, identify the parent process. If this came from Office, "
                "you may be dealing with a malicious attachment."
            ),
            "illustration": "document",
            "allowed_tables": ["DeviceProcessEvents"],
            "concepts": ["where", "project", "DeviceName"],
            "starting_query": (
                "DeviceProcessEvents\n"
                "| where DeviceName == \"FIN-WS-17\"\n"
                "| where FileName == \"powershell.exe\"\n"
                "| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine"
            ),
            "checks": [
                {"type": "contains", "value": "deviceprocessevents", "message": "Keep using process telemetry."},
                {"type": "contains", "value": "fin-ws-17", "message": "Scope the query to the compromised host."},
                {"type": "any", "values": ["initiatingprocessfilename", "project"], "message": "Project the parent process field."},
            ],
            "success_answer": "WINWORD.EXE",
            "success_rows": [
                {
                    "Timestamp": "2026-06-02T08:12:41Z",
                    "DeviceName": "FIN-WS-17",
                    "InitiatingProcessFileName": "WINWORD.EXE",
                    "ProcessCommandLine": "powershell.exe -EncodedCommand SQBFAFgA",
                }
            ],
            "success_message": "PowerShell was launched by `WINWORD.EXE`. This now looks like document-driven execution.",
            "hint": "On Defender-style process logs, the parent is usually exposed through `InitiatingProcess...` fields.",
        },
        {
            "id": "m3",
            "title": "Pivot To Network Activity",
            "goal": "Find the suspicious remote IP contacted by the malicious process from FIN-WS-17.",
            "narrative": (
                "Execution alone is not enough. You need the network IOC so the team can block "
                "the beacon or download source."
            ),
            "illustration": "network",
            "allowed_tables": ["DeviceNetworkEvents"],
            "concepts": ["where", "RemoteIP", "DeviceName"],
            "starting_query": (
                "DeviceNetworkEvents\n"
                "| where DeviceName == \"FIN-WS-17\"\n"
                "| where InitiatingProcessFileName == \"powershell.exe\"\n"
                "| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessCommandLine"
            ),
            "checks": [
                {"type": "contains", "value": "devicenetworkevents", "message": "Switch to network telemetry."},
                {"type": "contains", "value": "fin-ws-17", "message": "Keep the host scope."},
                {"type": "any", "values": ["remoteip", "remoteport"], "message": "Surface the outbound destination."},
            ],
            "success_answer": "185.220.101.14",
            "success_rows": [
                {
                    "Timestamp": "2026-06-02T08:13:02Z",
                    "DeviceName": "FIN-WS-17",
                    "RemoteIP": "185.220.101.14",
                    "RemotePort": 443,
                    "InitiatingProcessCommandLine": "powershell.exe -EncodedCommand SQBFAFgA",
                }
            ],
            "success_message": "You recovered the outbound IOC `185.220.101.14`. Containment can now pivot on the network side.",
            "hint": "Use `DeviceNetworkEvents` and project the remote endpoint fields.",
        },
        {
            "id": "m4",
            "title": "Catch Persistence",
            "goal": "Confirm whether the attacker established Run-key persistence on the compromised device.",
            "narrative": (
                "The lead analyst suspects the document was only stage one. Check the registry events "
                "for startup persistence before the attacker reconnects."
            ),
            "illustration": "registry",
            "allowed_tables": ["DeviceRegistryEvents"],
            "concepts": ["where", "RegistryKey", "RegistryValueData"],
            "starting_query": (
                "DeviceRegistryEvents\n"
                "| where DeviceName == \"FIN-WS-17\"\n"
                "| where RegistryKey contains \"\\\\CurrentVersion\\\\Run\"\n"
                "| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName"
            ),
            "checks": [
                {"type": "contains", "value": "deviceregistryevents", "message": "Persistence lives in registry telemetry here."},
                {"type": "contains", "value": "currentversion", "message": "Target the Run key path."},
                {"type": "any", "values": ["registryvaluedata", "registryvaluename"], "message": "Project the value that was written."},
            ],
            "success_answer": "C:\\Users\\emma.clark\\AppData\\Roaming\\updater.exe",
            "success_rows": [
                {
                    "Timestamp": "2026-06-02T08:14:10Z",
                    "RegistryKey": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "RegistryValueName": "Updater",
                    "RegistryValueData": "C:\\Users\\emma.clark\\AppData\\Roaming\\updater.exe",
                    "InitiatingProcessFileName": "powershell.exe",
                }
            ],
            "success_message": "Persistence confirmed. The Run key launches `updater.exe` from the user's roaming profile.",
            "hint": "Search the compromised host in `DeviceRegistryEvents` and filter on the classic Run path.",
        },
        {
            "id": "m5",
            "title": "Scope The User Context",
            "goal": "Identify the account used on the compromised workstation and whether it had local admin rights.",
            "narrative": (
                "You have the device, the network IOC, and persistence. Finish the triage by scoping "
                "who was active on the box and whether privilege escalation is likely."
            ),
            "illustration": "user",
            "allowed_tables": ["DeviceLogonEvents"],
            "concepts": ["where", "AccountName", "IsLocalAdmin"],
            "starting_query": (
                "DeviceLogonEvents\n"
                "| where DeviceName == \"FIN-WS-17\"\n"
                "| project Timestamp, DeviceName, AccountName, LogonType, IsLocalAdmin"
            ),
            "checks": [
                {"type": "contains", "value": "devicelogonevents", "message": "Scope the user from logon telemetry."},
                {"type": "contains", "value": "fin-ws-17", "message": "Limit to the compromised endpoint."},
                {"type": "any", "values": ["accountname", "islocaladmin"], "message": "Return the account and privilege context."},
            ],
            "success_answer": "emma.clark / false",
            "success_rows": [
                {
                    "Timestamp": "2026-06-02T08:09:55Z",
                    "DeviceName": "FIN-WS-17",
                    "AccountName": "emma.clark",
                    "LogonType": "Interactive",
                    "IsLocalAdmin": False,
                }
            ],
            "success_message": "The compromised user is `emma.clark`, and the session did not have local admin rights.",
            "hint": "Project both the user field and the local admin flag to close the triage story.",
        },
    ],
}
