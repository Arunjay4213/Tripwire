"""Step 3 — the agent loop: model asks for a tool, we run it, feed the result
back, and repeat until the model gives a final answer.

Key idea: the model only *asks* to call a function; our code runs it and reports
the result back. Looping that is what makes an "agent".

Run with:  python spike/tool_calling.py
"""

import json
import os

from dotenv import load_dotenv
from openai import OpenAI

# --- identical setup to step 1 ---
load_dotenv()
client = OpenAI(
    api_key=os.getenv("GROQ_API_KEY"),
    base_url=os.getenv("GROQ_BASE_URL"),
)


def get_weather(city):
    """A real version would call a weather API. We fake the result for now."""
    return f"It is 72F and sunny in {city}."


def add(a, b):
    return a + b

AVAILABLE_TOOLS = {
    "get_weather": get_weather,
    "add": add,
}


# A "tool" is just a JSON description of a function the model is ALLOWED to ask
# for. It tells the model: the name, what it does, and what arguments it takes.
# Note: this is only a *description* — the real Python function lives separately
# (we don't even write it yet; today we just watch the model request it).
tools = [
    {
        "type": "function",
        "function": {
            "name": "get_weather",
            "description": "Get the current weather for a city.",
            "parameters": {
                "type": "object",
                "properties": {
                    "city": {
                        "type": "string",
                        "description": "City name, e.g. 'Madison'",
                    },
                },
                "required": ["city"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "add",
            "description": "adds two numbers",
            "parameters": {
                "type": "object",
                "properties": {
                    "a": {
                        "type": "number",
                        "description": "the first number being added"
                    },
                    "b": {
                        "type": "number",
                        "description": "the second number being added"
                    }
                },
                "required": ["a", "b"]
            }
        }
    }
]

messages = [
    {"role": "system", "content": "You can look up the weather and add numbers using tools."},
    {"role": "user", "content": "What's the weather in Madison right now? also what is 4 + 19?"},
]

# --- the agent loop ---------------------------------------------------------
# Keep talking to the model until it stops asking for tools. Each pass through
# the loop:
#   1. send the whole conversation (+ tools) to the model
#   2. if it asks for tool(s): run them, add the results to the conversation,
#      then loop again so the model can see what happened
#   3. if it doesn't ask for a tool: it gave a final answer in words -> print, stop
while True:
    response = client.chat.completions.create(
        model=os.getenv("GROQ_MODEL"),
        messages=messages,
        tools=tools,
    )
    message = response.choices[0].message

    # No tool request -> the model is done. Print its final answer and stop.
    if not message.tool_calls:
        print("\nFinal answer:", message.content)
        break

    # The model asked for one or more tools. First, record ITS request message
    # in the conversation so the model remembers what it asked for next time.
    messages.append(message)

    # Run each requested tool and add ITS result back into the conversation.
    for call in message.tool_calls:
        name = call.function.name
        args = json.loads(call.function.arguments)   # JSON string -> dict
        result = AVAILABLE_TOOLS[name](**args)        # look up + run the function
        print(f"Ran {name}({args}) -> {result}")

        # A "tool" message carries the result back to the model. tool_call_id
        # ties this result to the exact request it answers.
        messages.append({
            "role": "tool",
            "tool_call_id": call.id,
            "content": str(result),
        })
    # loop repeats: the model now sees the results and decides its next move
