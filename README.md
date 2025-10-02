
## TI-to-Sigma Rule Generator

A specialized, multi-agent system built with **CrewAI** designed to automate **Detection Engineering**. This system converts unstructured Threat Intelligence (TI) reports into Sigma detection rules.


### Setup and Run

#### Prerequisites

-   Python 3.10+
-   LLM API Kyy (e.g., Gemini, OpenAI)
-   Serper API Key
    
#### Instructions

1.  **Clone the Repository:** `git clone [Repo URL]`
    
2.  **Install Dependencies:** `pip install -r requirements.txt`
    
3.  **Configure API Key:** Set your LLM API key as an environment variable.
    
4.  **Execute:** Run the crew from the repository root: `uv run run_crew`
    

The generated rules will be placed in the `detections/` directory.
