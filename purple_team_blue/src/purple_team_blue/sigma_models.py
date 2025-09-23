import uuid
from datetime import date
from typing import Any, Dict, List, Literal, Optional, Union

from pydantic import BaseModel, Field


class LogSource(BaseModel):
    """
    Defines the log source for which the rule is intended.
    """
    category: Optional[str] = Field(
        None,
        description="The log category, e.g., 'process_creation', 'firewall', 'proxy'.",
        examples=["process_creation"]
    )
    product: Optional[str] = Field(
        None,
        description="The product that generates the log, e.g., 'windows', 'linux', 'aws'.",
        examples=["windows"]
    )
    service: Optional[str] = Field(
        None,
        description="The specific service or log file, e.g., 'security', 'sysmon', 'cloudtrail'.",
        examples=["security"]
    )
    definition: Optional[str] = Field(
        None,
        description="A free-text definition of the log source for special cases."
    )

class SigmaRule(BaseModel):
    """
    A Pydantic model representing a complete Sigma rule structure.
    """
    title: str = Field(
        ...,
        description="A brief and descriptive title for the rule.",
        examples=["Suspicious PowerShell Execution Policy Bypass"]
    )
    id: uuid.UUID = Field(
        default_factory=uuid.uuid4,
        description="A unique identifier for the rule."
    )
    status: Optional[Literal["stable", "test", "experimental"]] = Field(
        "experimental",
        description="The development status of the rule."
    )
    description: Optional[str] = Field(
        None,
        description="A detailed explanation of the rule's purpose and the threat it detects."
    )
    author: Optional[str] = Field(
        None,
        description="The name or handle of the rule's author.",
        examples=["John Doe, @johndoe"]
    )
    creation_date: date = Field(
        default_factory=date.today,
        alias="date",
        description="The creation date of the rule."
    )
    modified_date: Optional[date] = Field(
        None,
        alias="modified",
        description="The date the rule was last modified."
    )
    references: List[str] = Field(
        default_factory=list,
        description="A list of URLs or references to related information.",
        examples=[
            "https://attack.mitre.org/techniques/T1059/001/",
            "https://blog.example.com/powershell-attacks"
        ]
    )
    logsource: LogSource = Field(
        ...,
        description="Specifies the log data source for the rule."
    )
    detection: Dict[str, Union[List[Dict[str, Any]], Dict[str, Any]]] = Field(
        ...,
        description="The core detection logic, containing search identifiers and their conditions."
    )
    condition: str = Field(
        ...,
        description="The logical combination of the search identifiers from the 'detection' field.",
        examples=["selection and not filter"]
    )
    falsepositives: List[str] = Field(
        default_factory=list,
        description="A list of known legitimate activities that may trigger this rule.",
        examples=["Legitimate administrator scripts.", "Software deployment systems."]
    )
    level: Literal["informational", "low", "medium", "high", "critical"] = Field(
        "medium",
        description="The severity level of the detected event."
    )
    tags: List[str] = Field(
        default_factory=list,
        description="A list of tags for categorization, often mapping to ATT&CK.",
        examples=["attack.execution", "attack.t1059.001"]
    )
    fields: Optional[List[str]] = Field(
        None,
        description="A list of interesting fields to include in the alert output."
    )

    
class SigmaRuleList(BaseModel):
   
    rules: List[SigmaRule] = Field(
        ...,
        description="A list of Sigma rules."
    )

