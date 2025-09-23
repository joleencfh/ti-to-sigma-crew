from crewai import Agent, Crew, Process, Task
from crewai.project import CrewBase, agent, crew, task
from crewai.agents.agent_builder.base_agent import BaseAgent
from crewai_tools import RagTool, SerperDevTool
from typing import List
from .sigma_models import SigmaRuleList

# load_dotenv()
# GITHUB_PAT_TOKEN=os.getenv('GITHUB_PAT_TOKEN')

# github_search_tool = GithubSearchTool(
# 	github_repo='https://github.com/SigmaHQ/sigma',
# 	gh_token=GITHUB_PAT_TOKEN,
# 	content_types=['code'] 
# )

# scrape_website_tool = ScrapeWebsiteTool(
    # website_url=''
    # )

serper_dev_tool = SerperDevTool()

rag_tool_threat_intel = RagTool()
rag_tool_threat_intel.add(data_type='web_page', source=r'https://www.ic3.gov/CSA/2025/250729.pdf')

rag_tool_detection_engineering = RagTool()
rag_tool_detection_engineering.add(data_type='web_page', source=r'https://github.com/SigmaHQ/sigma/wiki/Rule-Creation-Guide')
rag_tool_detection_engineering.add(data_type="text_file", source=r'sigma-detection-rule-schema.json')
rag_tool_detection_engineering.add(data_type='text_file', source=r'sigma_robust_example.yml')
rag_tool_detection_engineering.add(data_type='text_file', source=r'sigma_robust_example2.yml')


@CrewBase
class PurpleTeamBlue():
    """PurpleTeamBlue crew"""

    agents: List[BaseAgent]
    tasks: List[Task]

   
    @agent
    def threat_analyst_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['threat_analyst_agent'], tools=[rag_tool_threat_intel], 
            verbose=True
        )

    @agent
    def metadata_specialist_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['metadata_specialist_agent'], tools=[rag_tool_detection_engineering],
            verbose=True
        )
    
    @agent
    def detection_logic_engineer(self) -> Agent:
        return Agent(
            config=self.agents_config['detection_logic_engineer'], tools=[serper_dev_tool], 
            verbose=True
        )
    
    
    @agent
    def false_positives_analyst(self) -> Agent:
        return Agent(
            config=self.agents_config['false_positives_analyst'], tools=[serper_dev_tool], 
            verbose=True
        )

    @agent
    def principal_detection_engineer(self) -> Agent:
        return Agent(
            config=self.agents_config['principal_detection_engineer'], tools=[rag_tool_detection_engineering, serper_dev_tool], 
            verbose=True
        )
    

    
    @task
    def analyze_threat_requirements(self) -> Task:
        return Task(
            config=self.tasks_config['analyze_threat_requirements'], 
        )

    @task
    def create_rule_metadata(self) -> Task:
        return Task(
            config=self.tasks_config['create_rule_metadata'] 
        )

    @task
    def develop_detection_logic(self) -> Task:
        return Task(
            config=self.tasks_config['develop_detection_logic'] 
        )

   # @task
   # def validate_sigma_rule(self) -> Task:
   #     return Task(
   #         config=self.tasks_config['validate_sigma_rule'], 
   #         output_file='sigma.yml'
   #     )
    
    @task
    def analyze_false_positives(self) -> Task:
        return Task(
            config=self.tasks_config['analyze_false_positives']
        )
    
    @task
    def generate_atomic_sigma_rules(self) -> Task:
        return Task(
            config=self.tasks_config['generate_atomic_sigma_rules'], 
            output_pydantic=SigmaRuleList,
            output_file="final_rules.txt"
        )

    @crew
    def crew(self) -> Crew:        

        return Crew(
            agents=self.agents, 
            tasks=self.tasks, 
            process=Process.sequential,
            verbose=True,
        )
