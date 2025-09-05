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

    # Learn more about YAML configuration files here:
    # Agents: https://docs.crewai.com/concepts/agents#yaml-configuration-recommended
    # Tasks: https://docs.crewai.com/concepts/tasks#yaml-configuration-recommended
    
    # If you would like to add tools to your agents, you can learn more about it here:
    # https://docs.crewai.com/concepts/agents#agent-tools
    @agent
    def intel_analyst(self) -> Agent:
        return Agent(
            config=self.agents_config['intel_analyst'], tools=[scrape_website_tool], # type: ignore[index]
            verbose=True
        )

    @agent
    def detection_engineer(self) -> Agent:
        return Agent(
            config=self.agents_config['detection_engineer'], tools=[github_search_tool], # type: ignore[index]
            verbose=True
        )

    # To learn more about structured task outputs,
    # task dependencies, and task callbacks, check out the documentation:
    # https://docs.crewai.com/concepts/tasks#overview-of-a-task
    @task
    def cti_analysis_task(self) -> Task:
        return Task(
            config=self.tasks_config['cti_analysis_task'], # type: ignore[index]
        )

    @task
    def initial_rule_creation_task(self) -> Task:
        return Task(
            config=self.tasks_config['initial_rule_creation_task'], # type: ignore[index]
            output_file='sigma.yml'
        )

    @crew
    def crew(self) -> Crew:
        """Creates the TestCrew crew"""
        # To learn how to add knowledge sources to your crew, check out the documentation:
        # https://docs.crewai.com/concepts/knowledge#what-is-knowledge

        return Crew(
            agents=self.agents, # Automatically created by the @agent decorator
            tasks=self.tasks, # Automatically created by the @task decorator
            process=Process.sequential,
            verbose=True,
            # process=Process.hierarchical, # In case you wanna use that instead https://docs.crewai.com/how-to/Hierarchical/
        )
