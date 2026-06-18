"""Step 1 — prove we can call a model from our own code.

Run it with:  python spike/hello_groq.py
(make sure your .venv is activated and you've created a .env file first)
"""

import os

# `python-dotenv` reads a .env file and loads its KEY=value lines into the
# environment, so os.getenv("GROQ_API_KEY") can find your key. We keep secrets
# in .env (never in code) so we never accidentally commit them.
from dotenv import load_dotenv

# The OpenAI library isn't only for OpenAI — any server that speaks the same
# API "dialect" can be reached with it. Groq does, so we reuse this client.
from openai import OpenAI

# Load .env into the environment. Call this once, near the top.
load_dotenv()

# Build the client. Two things make it talk to Groq instead of OpenAI:
#   - api_key:  your Groq key
#   - base_url: Groq's address (instead of OpenAI's default)
client = OpenAI(
    api_key=os.getenv("GROQ_API_KEY"),
    base_url=os.getenv("GROQ_BASE_URL"),
)

# A "chat completion" is the basic call: you send a list of messages, the model
# replies. Each message has a "role" (system / user / assistant) and "content".
#   - system: standing instructions for how the model should behave
#   - user:   what the human is saying
response = client.chat.completions.create(
    model=os.getenv("GROQ_MODEL"),
    messages=[
        {"role": "system", "content": "You are a clown who only speaks in rhymes."},
        {"role": "user", "content": "In one sentence, what is prompt injection?"},
    ],
)

# The reply text lives a few layers deep in the response object. We'll unpack
# what this structure is together after you run it.
print(response.choices[0].message.content)
