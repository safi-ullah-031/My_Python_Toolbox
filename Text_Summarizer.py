import os
from openai import OpenAI
from dotenv import load_dotenv
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
from PyPDF2 import PdfReader

# Load API key from .env file
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

def summarize_from_file(file_path):
    try:
        if file_path.endswith(".txt"):
            with open(file_path, "r") as file:
                text = file.read()
        elif file_path.endswith(".pdf"):
            pdf = PdfReader(file_path)
            text = ""
            for page in pdf.pages:
                text += page.extract_text()
        else:
            raise ValueError("File format not supported. Only .txt and .pdf are allowed.")
        
        return summarize_text(text)

    except Exception as e:
        messagebox.showerror("Error", f"Error reading file: {e}")
        return None

def save_summary(summary, file_path="summary.txt"):
    try:
        with open(file_path, "w") as file:
            file.write(summary)
        messagebox.showinfo("Success", f"Summary saved to {file_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Error saving summary: {e}")

# Tkinter GUI for the summarizer tool
def gui_summarizer():
    def on_summarize_text():
        input_text = text_input.get("1.0", "end-1c")
        if not input_text.strip():
            messagebox.showwarning("Input Error", "Please enter some text to summarize.")
            return
        summary = summarize_text(input_text)
        result_text.config(state="normal")
        result_text.delete("1.0", "end")
        result_text.insert("1.0", summary)
        result_text.config(state="disabled")

    def on_upload_file():
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt"), ("PDF Files", "*.pdf")])
        if not file_path:
            return
        summary = summarize_from_file(file_path)
        if summary:
            result_text.config(state="normal")
            result_text.delete("1.0", "end")
            result_text.insert("1.0", summary)
            result_text.config(state="disabled")

    def on_save_summary():
        summary = result_text.get("1.0", "end-1c")
        if summary.strip():
            save_summary(summary)
        else:
            messagebox.showwarning("Summary Error", "No summary to save.")

    window = tk.Tk()
    window.title("Groq Text Summarizer")

    tk.Label(window, text="Enter text to summarize:").pack(pady=10)

    text_input = tk.Text(window, height=6, width=60)
    text_input.pack(pady=10)

    summarize_button = tk.Button(window, text="Summarize Text", command=on_summarize_text)
    summarize_button.pack(pady=5)

    upload_button = tk.Button(window, text="Upload Text/PDF File", command=on_upload_file)
    upload_button.pack(pady=5)

    result_label = tk.Label(window, text="Summary:")
    result_label.pack(pady=10)

    result_text = tk.Text(window, height=10, width=60, wrap=tk.WORD, state="disabled")
    result_text.pack(pady=10)

    save_button = tk.Button(window, text="Save Summary", command=on_save_summary)
    save_button.pack(pady=10)

    window.mainloop()

if __name__ == "__main__":
    gui_summarizer()
