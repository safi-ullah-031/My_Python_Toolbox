import os
import pdf2docx
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinterdnd2 import DND_FILES, TkinterDnD

# Function to convert selected PDFs
def convert_pdfs_to_word(pdf_files):
    if not pdf_files:  
        messagebox.showwarning("No Files Selected", "Please select or drop at least one PDF file.")
        return
    
    saved_files = []  
    progress["maximum"] = len(pdf_files)  
    progress["value"] = 0  

    for pdf_file in pdf_files:
        try:
            pdf_file = pdf_file.strip("{}")  # Remove curly braces (Windows drag issue)
            if not pdf_file.lower().endswith(".pdf"):
                continue  # Skip non-PDF files
            
            # Ask user where to save the converted file
            save_location = filedialog.asksaveasfilename(
                defaultextension=".docx",
                filetypes=[("Word Documents", "*.docx")],
                initialfile=os.path.splitext(os.path.basename(pdf_file))[0] + ".docx",
                title="Save As"
            )
            
            if not save_location:  
                continue  

            # Convert PDF to Word
            pdf2docx.Converter(pdf_file).convert(save_location, start=0, end=None)
            saved_files.append(save_location)
            progress["value"] += 1  
            root.update_idletasks()  

        except Exception as e:
            messagebox.showerror("Error", f"Failed to convert {os.path.basename(pdf_file)}: {e}")

    if saved_files:
        messagebox.showinfo("Conversion Successful", f"Converted files:\n" + "\n".join(saved_files))
    else:
        messagebox.showwarning("Conversion Failed", "No files were converted.")

# Function to open file dialog manually
def open_file_dialog():
    pdf_files = filedialog.askopenfilenames(title="Select PDF Files", filetypes=[("PDF Files", "*.pdf")])
    convert_pdfs_to_word(pdf_files)

# Function to handle drag & drop files
def on_drop(event):
    pdf_files = event.data.split()  
    convert_pdfs_to_word(pdf_files)

# GUI Setup
root = TkinterDnD.Tk()  
root.title("PDF to Word Converter")
root.geometry("500x350")
root.configure(bg="#222222")

# Title Label
label = tk.Label(root, text="Drag & Drop PDFs or Click 'Select Files'", font=("Arial", 14, "bold"), fg="white", bg="#222222")
label.pack(pady=20)

# Drop Area
drop_area = tk.Label(root, text="Drop PDFs Here", font=("Arial", 12), fg="white", bg="#444444", width=30, height=2)
drop_area.pack(pady=10)
drop_area.drop_target_register(DND_FILES)
drop_area.dnd_bind("<<Drop>>", on_drop)

# Select Files Button
convert_button = tk.Button(root, text="Select Files", command=open_file_dialog, font=("Arial", 12), bg="#4CAF50", fg="white", padx=10, pady=5)
convert_button.pack(pady=10)

# Progress Bar
progress = ttk.Progressbar(root, length=400, mode='determinate')
progress.pack(pady=20)

# Run GUI
root.mainloop()
