import pyautogui
import time
import keyboard

def send_whatsapp_message(contact_name, message):
    try:
        # Open WhatsApp Desktop (Make sure it's already running)
        pyautogui.hotkey('win', 's')  # Open Windows search
        time.sleep(1)
        pyautogui.write('WhatsApp')  # Type "WhatsApp"
        time.sleep(1)
        pyautogui.press('enter')  # Open WhatsApp
        time.sleep(5)  # Wait for WhatsApp to open

        # Search for the contact
        pyautogui.hotkey('ctrl', 'f')  # Open search in WhatsApp
        time.sleep(1)
        pyautogui.write(contact_name)  # Type the contact's name
        time.sleep(2)
        pyautogui.press('enter')  # Open chat with contact
        time.sleep(2)

        # Ensure the message box is active
        pyautogui.click(x=500, y=900)  # Adjust coordinates to message box position
        time.sleep(1)

        # Type and send the message
        pyautogui.write(message)  # Type the message
        time.sleep(1)
        pyautogui.press('enter')  # Send the message
        time.sleep(1)

        print(f"✅ Message sent to {contact_name} successfully!")

    except Exception as e:
        print(f"❌ Error: {e}")

# Get user input
contact_name = input("Enter the contact name: ")
message = input("Enter your message: ")

# Send message
send_whatsapp_message(contact_name, message)
