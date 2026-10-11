"""A stub `crewai` package for driving CrewAIAdapter.run() offline.

CrewAI is an optional extra and not installed in the test environment, so
the adapter's run() -- the agent/task/crew construction, the max_iter budget,
the tool wrapping, the final trace -- had no coverage at all. This installs
`crewai` and `crewai.tools` modules into sys.modules whose Crew.kickoff()
plays a script of tool calls the way the framework's model loop would, then
returns a final answer. The one piece of real CrewAI behaviour it reproduces
on purpose is argument validation: BaseTool.run validates kwargs against
`args_schema` and forwards EVERY field, so an optional the model never set
arrives as None (the shape that broke two-argument tool impls).
"""

from __future__ import annotations

import sys
import types
from typing import Any


class FakeCrewAI:
    def __init__(self, script: list[tuple[str, dict[str, Any]]], final: str = "All done.") -> None:
        self.script = script
        self.final = final
        self.agents: list[dict[str, Any]] = []
        self.tasks: list[dict[str, Any]] = []
        self.llms: list[dict[str, Any]] = []
        self.crews: list[dict[str, Any]] = []

    def install(self, monkeypatch) -> "FakeCrewAI":
        fake = self

        class BaseTool:
            name: str
            description: str
            args_schema: type

            def run(self, **kwargs: Any) -> str:
                validated = self.args_schema(**kwargs).model_dump()
                return self._run(**validated)

        class LLM:
            def __init__(self, **kwargs: Any) -> None:
                fake.llms.append(kwargs)

        class Agent:
            def __init__(self, **kwargs: Any) -> None:
                self.kwargs = kwargs
                self.tools = kwargs.get("tools", [])
                fake.agents.append(kwargs)

        class Task:
            def __init__(self, **kwargs: Any) -> None:
                fake.tasks.append(kwargs)

        class Crew:
            def __init__(self, **kwargs: Any) -> None:
                self.agents = kwargs.get("agents", [])
                fake.crews.append(kwargs)

            def kickoff(self):
                tools = {t.name: t for agent in self.agents for t in agent.tools}
                for name, kwargs in fake.script:
                    tool = tools.get(name)
                    if tool is not None:  # an unknown tool never reaches a tool object
                        tool.run(**kwargs)
                return types.SimpleNamespace(raw=fake.final)

        crewai = types.ModuleType("crewai")
        crewai.Agent, crewai.Task, crewai.Crew, crewai.LLM = Agent, Task, Crew, LLM
        crewai_tools = types.ModuleType("crewai.tools")
        crewai_tools.BaseTool = BaseTool
        crewai.tools = crewai_tools
        monkeypatch.setitem(sys.modules, "crewai", crewai)
        monkeypatch.setitem(sys.modules, "crewai.tools", crewai_tools)
        return self
