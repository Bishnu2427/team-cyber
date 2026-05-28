import os
from langchain_groq import ChatGroq


class ModelRouter:
    def __init__(self):
        self._key = os.getenv("GROQ_API_KEY", "")

    def fast(self) -> ChatGroq:
        return ChatGroq(model="llama3-8b-8192", api_key=self._key, temperature=0.0)

    def reasoning(self) -> ChatGroq:
        return ChatGroq(model="llama3-70b-8192", api_key=self._key, temperature=0.0)


router = ModelRouter()
