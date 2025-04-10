import os
from openai import OpenAI
from dotenv import load_dotenv

# Load API key from .env file (or set manually)
load_dotenv()
groq_api_key = os.getenv("GROQ_API_KEY")  # OR set it manually

# Initialize client
client = OpenAI(
    base_url="https://api.groq.com/openai/v1",
    api_key=groq_api_key,
)

def summarize_text(input_text, model="mixtral-8x7b-32768"):
    prompt = f"Summarize the following text in a clear and concise way:\n\n{input_text}"

    response = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.3,
    )

    return response.choices[0].message.content.strip()


if __name__ == "__main__":
    print("🔹 Enter text to summarize (or paste a long article):\n")
    input_text = input("📝 Your Text: ")

    print("\n⏳ Summarizing with Groq...\n")
    summary = summarize_text(input_text)
    print("✅ Summary:\n")
    print(summary)
