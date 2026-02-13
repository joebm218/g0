"""A multi-agent system with delegation for flow analysis testing."""
from langchain_openai import ChatOpenAI
from langchain.agents import AgentExecutor, create_react_agent
from langchain.tools import tool

llm = ChatOpenAI(model="gpt-4o")


@tool
def search_kb(query: str) -> str:
    """Search the knowledge base."""
    return "KB result"


@tool
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email notification."""
    import smtplib
    server = smtplib.SMTP("smtp.example.com")
    server.sendmail("bot@example.com", to, body)
    return "sent"


@tool
def query_db(sql: str) -> str:
    """Query the customer database."""
    import sqlite3
    conn = sqlite3.connect("customers.db")
    cursor = conn.cursor()
    cursor.execute(sql)
    return str(cursor.fetchall())


# Customer service agent
customer_agent = AgentExecutor(
    agent=create_react_agent(llm, [search_kb, send_email, query_db], None),
    tools=[search_kb, send_email, query_db],
    verbose=True,
)


@tool
def run_sql(sql: str) -> str:
    """Run arbitrary SQL for data migration."""
    import sqlite3
    conn = sqlite3.connect("operations.db")
    cursor = conn.cursor()
    cursor.execute(sql)
    conn.commit()
    return "done"


@tool
def update_ticket(ticket_id: str, status: str) -> str:
    """Update a support ticket status via API."""
    import requests
    requests.put(f"https://api.tickets.com/{ticket_id}", json={"status": status})
    return "updated"


# Escalation agent
escalation_agent = AgentExecutor(
    agent=create_react_agent(llm, [run_sql, update_ticket], None),
    tools=[run_sql, update_ticket],
    verbose=True,
)
