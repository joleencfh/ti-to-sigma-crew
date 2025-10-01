import os, re, json
from typing import Any, Type
from ..sigma_models import SigmaRuleList
from ruamel.yaml import YAML
from crewai.tools import BaseTool
from pydantic import BaseModel, ValidationError, Field



class SigmaRuleOutputTool(BaseTool):
    """
    A tool to validate and structure a Sigma rule into a Pydantic model.
    It takes all the necessary fields for a Sigma rule, validates them,
    and returns the final, structured rule as a JSON string.
    """
    name: str = "Sigma Rule Structuring Tool"
    description: str = (
        "Use this tool to format the final Sigma rule. "
        "Provide all the required fields to create a complete and valid rule. "
        "The tool will validate the inputs and return the final rule in a structured format."
    )
    args_schema: Type[BaseModel] = SigmaRuleList  

    def _run(self, **kwargs: Any) -> str:
        """
        Takes keyword arguments matching the SigmaRule model fields,
        validates them, and returns a JSON representation of the rule.
        """
        try:
            sigma_rule = SigmaRuleList.model_validate(kwargs)
            return sigma_rule.model_dump_json(by_alias=True, indent=2)

        except ValidationError as e:
            error_details = e.errors()
            return (
                "Error: Validation failed. The provided data is invalid for a Sigma rule. "
                f"Please correct the following errors and try again:\n{json.dumps(error_details, indent=2)}"
            )
        


class YAMLWriterToolInput(BaseModel):
    """Input for the YAMLWriterTool."""
    json_string: str = Field(..., description="A JSON string containing an array of sigma rule objects to be written to separate YAML files.")
    output_directory: str = Field("sigma_rules", description="The directory where the YAML files will be saved. Defaults to 'sigma_rules'.")

class YAMLWriterTool(BaseTool):
    """A tool to write sigma rules from a JSON string to separate YAML files."""
    name: str = "YAML File Writer"
    description: str = "Writes each sigma rule from a JSON array to its own YAML file. Requires a JSON string and an optional output directory."
    args_schema: Type[BaseModel] = YAMLWriterToolInput

    def _run(self, json_string: str, output_directory: str = "sigma_rules") -> str:
        """
        Parses a JSON string of sigma rules and writes each rule to a separate YAML file.
        
        Args:
            json_string (str): A JSON string containing a list of sigma rules.
            output_directory (str): The directory where the files will be saved.
        
        Returns:
            str: A message indicating the number of files created.
        """
        try:
            rules_data = json.loads(json_string)
            if not isinstance(rules_data, list):
                return "Error: JSON input must be a list of rule objects."
        except json.JSONDecodeError:
            return "Error: Invalid JSON input. Please provide a valid JSON string."
        except Exception as e:
            return f"An unexpected error occurred during JSON parsing: {str(e)}"

        if not rules_data:
            return "No sigma rules found in the provided JSON."

        script_dir = os.path.dirname(os.path.abspath(__file__))
       
        project_root = os.path.dirname(script_dir)
        final_output_folder_name = "detections"
        full_output_path = os.path.join(project_root, final_output_folder_name)

        os.makedirs(full_output_path, exist_ok=True)
        
        
        yaml = YAML()
        yaml.preserve_quotes = True
        
        files_created = 0
        
        for rule in rules_data:
            if "title" not in rule:
                continue

            title = rule["title"]
            slugified_title = re.sub(r'[^a-zA-Z0-9\s]', '', title)
            slugified_title = slugified_title.replace(' ', '_').lower()
            
            file_name = f"{slugified_title}.yml"
            file_path = os.path.join(full_output_path, file_name)

            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    yaml.dump(rule, f)
                files_created += 1
            except Exception as e:
                print(f"Failed to write file for title '{title}': {e}")
                
        if files_created > 0:
            return f"Successfully created {files_created} YAML files in the '{output_directory}' directory."
        else:
            return "No valid sigma rules with a 'title' field were processed."