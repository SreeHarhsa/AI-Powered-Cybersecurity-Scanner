#!/usr/bin/env python
# coding: utf-8

# In[15]:


from docx import Document

# Load the Word document
doc = Document("/home/harsha/Downloads/Gemini -API.docx")

# Extract the text (assuming the key is in the first paragraph)
gemini_api_key = doc.paragraphs[0].text.strip()


# In[17]:


import os
import streamlit as st
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.memory import ConversationBufferMemory
from langchain.agents import AgentType, initialize_agent
from langchain.tools import Tool

# Initialize Gemini Model
llm = ChatGoogleGenerativeAI(model="gemini-pro", google_api_key=gemini_api_key)

# Memory for conversation
memory = ConversationBufferMemory(memory_key="chat_history", return_messages=True)

# Define cybersecurity tasks
def vulnerability_scan(domain: str):
    """Simulated function for vulnerability scanning."""
    return f"Performed vulnerability scan on {domain}. No critical issues found."

def threat_intelligence():
    """Simulated function for threat intelligence gathering."""
    return "Threat intelligence gathered: No active threats detected."

# Define LangChain Tools
tools = [
    Tool(name="Vulnerability Scan", func=vulnerability_scan, description="Scans a domain for security vulnerabilities."),
    Tool(name="Threat Intelligence", func=threat_intelligence, description="Gathers cybersecurity threat intelligence."),
]

# Initialize Agent
agent = initialize_agent(
    tools=tools,
    llm=llm,
    agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
    verbose=True,
    memory=memory
)

# Streamlit UI
st.title("Cybersecurity AI Assistant")
st.write("Perform automated cybersecurity tasks using AI.")

# User input
user_query = st.text_input("Enter a cybersecurity task:", "Scan example.com for vulnerabilities")

if st.button("Run Task"):
    with st.spinner("Processing..."):
        try:
            response = agent.run(user_query)
            st.success(f"Task Completed: {response}")
        except Exception as e:
            st.error(f"Error: {e}")


# In[ ]:




