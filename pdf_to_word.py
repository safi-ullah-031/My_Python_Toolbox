import os
import sys
import pdf2docx
import tkinter as tk
from tkinter import filedialog, messagebox

# Function to convert PDF to Word
def convert_pdf_to_word():
    try:
        # Ask user to select a PDF file
        pdf_file = filedialog.askopenfilename(title="Select PDF File", filetypes=[("PDF Files", "*.pdf")])
        
        if not pdf_file:  # If user cancels file selection
            messagebox.showwarning("No File Selected", "Please select a PDF file to convert.")
            return

        # Ensure the selected file is a PDF
        if not pdf_file.lower().endswith(".pdf"):
            messagebox.showerror("Invalid File", "Please select a valid PDF file.")
            return
        
        # Generate output Word file path
        output_file = os.path.splitext(pdf_file)[0] + ".docx"

        # Convert PDF to Word
        pdf2docx.Converter(pdf_file).convert(output_file, start=0, end=None)
        
        # Show success message with saved location
        messagebox.showinfo("Conversion Successful", f"Your file has been converted and saved at:\n{output_file}")

    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

# GUI Setup
root = tk.Tk()
root.title("PDF to Word Converter")
root.geometry("400x200")
root.configure(bg="#f5f5f5")

# Title Label
label = tk.Label(root, text="Convert PDF to Word", font=("Arial", 14, "bold"), bg="#f5f5f5")
label.pack(pady=20)

# Convert Button
convert_button = tk.Button(root, text="Select PDF & Convert", command=convert_pdf_to_word, font=("Arial", 12), bg="#4CAF50", fg="white", padx=10, pady=5)
convert_button.pack(pady=10)

# Run GUI
root.mainloop()
