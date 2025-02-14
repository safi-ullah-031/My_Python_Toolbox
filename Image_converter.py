from PIL import Image
import os

def convert_image(input_path, output_format):
    try:
        # Open the image file
        img = Image.open(input_path)
        
        # Extract file name without extension
        file_name, _ = os.path.splitext(input_path)
        
        # Create the output file name
        output_path = f"{file_name}.{output_format.lower()}"
        
        # Save the image in the new format
        img.save(output_path, format=output_format.upper())
        
        print(f"Image successfully converted to {output_format.upper()} and saved as {output_path}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    # User input for file path
    input_file = input("Enter the image file path (e.g., image.jpg): ").strip()
    
    # User input for output format
    output_format = input("Enter the desired output format (e.g., png, jpg, webp): ").strip().lower()
    
    # Convert the image
    convert_image(input_file, output_format)
