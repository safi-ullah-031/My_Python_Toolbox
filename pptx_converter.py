import os
import shutil
import fitz  # PyMuPDF for PDF conversion
import gradio as gr
from pptx import Presentation
from pptx2pdf import convert
from PIL import Image

# Function to convert PPTX to images
def pptx_to_images(pptx_path):
    try:
        if not pptx_path.lower().endswith(".pptx"):
            return "Error: Please upload a valid PPTX file."

        output_dir = pptx_path.replace(".pptx", "_images")
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        presentation = Presentation(pptx_path)
        image_paths = []

        for i, slide in enumerate(presentation.slides):
            img_path = os.path.join(output_dir, f"slide_{i+1}.png")
            slide.shapes._spTree.write(img_path)  # Extract slide as an image
            image_paths.append(img_path)

        return image_paths if image_paths else "Error: No slides found in the PPTX."

    except Exception as e:
        return f"Error: {e}"

# Function to convert PPTX to PDF
def pptx_to_pdf(pptx_path):
    try:
        if not pptx_path.lower().endswith(".pptx"):
            return "Error: Please upload a valid PPTX file."

        output_pdf = pptx_path.replace(".pptx", ".pdf")
        convert(pptx_path, output_pdf)  # Convert using pptx2pdf

        return output_pdf if os.path.exists(output_pdf) else "Error: PDF conversion failed."

    except Exception as e:
        return f"Error: {e}"

# Function to handle file upload and conversion
def convert_pptx(pptx_file, output_type):
    try:
        if pptx_file is None:
            return "Error: No file uploaded."

        # Save uploaded file
        file_path = os.path.join("uploads", pptx_file.name)
        with open(file_path, "wb") as f:
            f.write(pptx_file.read())

        # Process based on user choice
        if output_type == "Images":
            result = pptx_to_images(file_path)
        elif output_type == "PDF":
            result = pptx_to_pdf(file_path)
        else:
            result = "Error: Invalid output type selected."

        return result

    except Exception as e:
        return f"Error: {e}"

# Gradio UI
with gr.Blocks() as app:
    gr.Markdown("# 📂 PPTX to Image & PDF Converter")
    gr.Markdown("### Upload a PowerPoint file and choose the desired output format")

    pptx_file = gr.File(label="Upload PPTX File")
    output_type = gr.Radio(["Images", "PDF"], label="Select Output Format")
    convert_btn = gr.Button("Convert")
    output_display = gr.Gallery(label="Converted Files", type="filepath")

    convert_btn.click(convert_pptx, inputs=[pptx_file, output_type], outputs=output_display)

# Run the Gradio App
app.launch()
