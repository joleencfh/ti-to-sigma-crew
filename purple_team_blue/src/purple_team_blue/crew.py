from crewai import Agent, Crew, Process, Task
from crewai.project import CrewBase, agent, crew, task
from crewai.agents.agent_builder.base_agent import BaseAgent
from typing import List
from crewai_tools import ScrapeWebsiteTool
from crewai_tools import GithubSearchTool
from dotenv import load_dotenv
import os

load_dotenv()
GITHUB_PAT_TOKEN=os.getenv('GITHUB_PAT_TOKEN')

github_search_tool = GithubSearchTool(
	github_repo='https://github.com/SigmaHQ/sigma',
	gh_token=GITHUB_PAT_TOKEN,
	content_types=['code'] 
)

scrape_website_tool = ScrapeWebsiteTool(
    website_url='https://cloud.google.com/blog/topics/threat-intelligence/unc3944-proactive-hardening-recommendations'
    )



@CrewBase
class PurpleTeamBlue():
    """PurpleTeamBlue crew"""

    agents: List[BaseAgent]
    tasks: List[Task]

   
    @agent
    def intel_analyst(self) -> Agent:
        return Agent(
            config=self.agents_config['intel_analyst'], tools=[scrape_website_tool], 
            verbose=True
        )

    @agent
    def detection_engineer(self) -> Agent:
        return Agent(
            config=self.agents_config['detection_engineer'], tools=[github_search_tool], 
            verbose=True
        )

    
    @task
    def cti_analysis_task(self) -> Task:
        return Task(
            config=self.tasks_config['cti_analysis_task'], 
        )

    @task
    def initial_rule_creation_task(self) -> Task:
        return Task(
            config=self.tasks_config['initial_rule_creation_task'], 
            output_file='sigma.yml'
        )

    @crew
    def crew(self) -> Crew:
        """Creates the TestCrew crew"""
        

        return Crew(
            agents=self.agents, 
            tasks=self.tasks, 
            process=Process.sequential,
            verbose=True,
        )
