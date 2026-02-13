"""An inventory test agent with models, tools, and vector DB."""
from langchain_openai import ChatOpenAI
from langchain.agents import AgentExecutor, create_react_agent
from langchain.tools import tool
from pinecone import Pinecone

# Model
llm = ChatOpenAI(model="gpt-4o", api_key="from-env")

# Vector DB
pc = Pinecone(api_key="from-env")
index = pc.Index("knowledge-base")


@tool
def search_knowledge(query: str) -> str:
    """Search the knowledge base for relevant information."""
    results = index.query(vector=[0.1] * 1536, top_k=5)
    return str(results)


@tool
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email to the specified recipient."""
    import smtplib
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.sendmail("agent@example.com", to, f"Subject: {subject}\n\n{body}")
    return "Email sent"


@tool
def read_file(path: str) -> str:
    """Read a file from the filesystem."""
    with open(path) as f:
        return f.read()


agent = AgentExecutor(
    agent=create_react_agent(llm, [search_knowledge, send_email, read_file], None),
    tools=[search_knowledge, send_email, read_file],
    verbose=True,
)
