"""Quote triage crew for the Vantor Logistics freight desk."""

import os
from pathlib import Path

import yaml
from crewai import Agent, Crew, Process, Task
from langchain_openai import ChatOpenAI

CONFIG_DIR = Path(__file__).parent / "config"


def _load(name: str) -> dict:
    return yaml.safe_load((CONFIG_DIR / f"{name}.yaml").read_text(encoding="utf-8"))


def build_crew() -> Crew:
    llm = ChatOpenAI(
        model=os.environ.get("FREIGHT_CREW_MODEL", "gpt-4o-mini"),
        api_key=os.environ["OPENAI_API_KEY"],
        temperature=0.1,
    )
    agents_cfg = _load("agents")
    tasks_cfg = _load("tasks")
    quote_analyst = Agent(llm=llm, **agents_cfg["quote_analyst"])
    lane_planner = Agent(llm=llm, **agents_cfg["lane_planner"])
    tasks = [
        Task(agent=quote_analyst, **tasks_cfg["score_quotes"]),
        Task(agent=lane_planner, **tasks_cfg["plan_lanes"]),
    ]
    return Crew(
        agents=[quote_analyst, lane_planner],
        tasks=tasks,
        process=Process.sequential,
    )
