import os
from langchain_groq import ChatGroq
from langchain_community.llms import Ollama


class ModelRouter:
    def __init__(self):
        self._key  = os.getenv("GROQ_API_KEY", "")
        self._host = os.getenv("OLLAMA_HOST", "http://ollama:11434")
        self._model = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b")

    def fast(self) -> ChatGroq:
        """Quick classification / summarisation."""
        return ChatGroq(model="llama3-8b-8192", api_key=self._key, temperature=0.1)

    def reasoning(self) -> ChatGroq:
        """Root-cause analysis and remediation."""
        return ChatGroq(model="llama3-70b-8192", api_key=self._key, temperature=0.2)

    def code(self) -> Ollama:
        """Local code analysis via Qwen2.5-Coder."""
        return Ollama(base_url=self._host, model=self._model, temperature=0.1)


router = ModelRouter()
