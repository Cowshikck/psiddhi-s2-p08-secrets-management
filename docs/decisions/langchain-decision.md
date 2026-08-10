\# Architecture Decision: LangChain Integration



\*\*Decision:\*\* Closed — deliberate simplification. Direct API calls used instead of LangChain.



\*\*Date:\*\* 2026-08-10



\*\*Status:\*\* Final



\## Context



The approved proposal listed LangChain (open-source Python framework) for AI pipeline orchestration — connecting Gemini and Groq calls into managed chains with document loading, prompt templates, and output parsing.



LangChain was installed during project setup (`pip install langchain langchain-google-genai`) and remains in requirements.txt.



\## Decision



After implementation, direct Gemini API and Groq SDK calls were used instead of LangChain chains. LangChain is installed but not imported in any production code.



\## Rationale



1\. \*\*Scope mismatch.\*\* VaultGuard's AI layer consists of three independent, single-model API calls — anomaly narration (Groq), rotation policies (Gemini), compliance docs (Gemini). Each call follows the same pattern: build prompt, call API, parse JSON. No multi-step chains, no document retrieval, no conversation memory, no agent routing. LangChain's orchestration abstractions add complexity without adding capability for this pattern.



2\. \*\*Gemini JSON parsing reliability.\*\* Gemini 2.5 Flash includes thinking blocks in responses unless thinkingBudget is set to 0. LangChain's default Gemini wrapper (langchain-google-genai) did not expose this parameter cleanly, causing intermittent JSON parse failures. Direct API calls with generationConfig thinkingBudget 0 resolved this immediately.



3\. \*\*Debuggability.\*\* With direct calls, every request and response is visible in a single function. With LangChain, errors surface inside chain abstractions that obscure which step failed and why.



4\. \*\*Testability.\*\* Each AI module (anomaly\_detector.py, rotation\_policies.py, compliance\_docs.py) is independently testable — 25 AI output tests validate structure and content without chain dependencies.



\## Consequences



\- Three direct API call modules instead of one LangChain chain definition.

\- Each module is independently testable with clear inputs and outputs.

\- If future enhancements require multi-step orchestration (e.g., RAG over audit logs, agent-based policy generation), LangChain can be introduced at that point with clear justification.



\## Evidence



\- LangChain is installed: pip list confirms langchain and langchain-google-genai present.

\- No import langchain in any src/ file confirms deliberate non-use.

\- thinkingBudget:0 parameter visible in rotation\_policies.py confirms the parsing issue.

\- Disclosed as deviation in mid-term document Section 8.

