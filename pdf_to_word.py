import os
import pdf2docx
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# Function to convert multiple PDFs to Word
def convert_pdfs_to_word():
    try:
        pdf_files = filedialog.askopenfilenames(title="Select PDF Files", filetypes=[("PDF Files", "*.pdf")])
        
        if not pdf_files:  # If user cancels file selection
            messagebox.showwarning("No Files Selected", "Please select at least one PDF file.")
            return
        
        saved_files = []  # Store converted file paths
        
        progress["maximum"] = len(pdf_files)  # Set progress bar limit
        progress["value"] = 0

        for pdf_file in pdf_files:
            try:
                output_file = os.path.splitext(pdf_file)[0] + ".docx"
                pdf2docx.Converter(pdf_file).convert(output_file, start=0, end=None)
                saved_files.append(output_file)
                progress["value"] += 1  # Update progress bar
                root.update_idletasks()  # Refresh UI
            except Exception as e:
                messagebox.showerror("Error", f"Failed to convert {os.path.basename(pdf_file)}: {e}")

        if saved_files:
            messagebox.showinfo("Conversion Successful", f"Converted files:\n" + "\n".join(saved_files))
        else:
            messagebox.showwarning("Conversion Failed", "No files were converted.")

    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

# GUI Setup
root = tk.Tk()
root.title("PDF to Word Converter")
root.geometry("500x300")
root.configure(bg="#222222")

# Title Label
label = tk.Label(root, text="Batch PDF to Word Converter", font=("Arial", 14, "bold"), fg="white", bg="#222222")
label.pack(pady=20)

# Convert Button
convert_button = tk.Button(root, text="Select PDFs & Convert", command=convert_pdfs_to_word, font=("Arial", 12), bg="#4CAF50", fg="white", padx=10, pady=5)
convert_button.pack(pady=10)

# Progress Bar
progress = ttk.Progressbar(root, length=400, mode='determinate')
progress.pack(pady=20)

# Run GUI
root.mainloop()
