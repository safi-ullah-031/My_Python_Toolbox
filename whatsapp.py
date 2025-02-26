import pywhatkit as kit
import datetime

# Function to send a WhatsApp message
def send_whatsapp_message(phone_number, message, hours, minutes):
    try:
        kit.sendwhatmsg(phone_number, message, hours, minutes)
        print(f"Message scheduled successfully to {phone_number} at {hours}:{minutes}")
    except Exception as e:
        print(f"Error: {e}")

# User input for phone number and message
phone_number = input("Enter phone number (with country code, e.g., +92XXXXXXXXXX): ")
message = input("Enter the message: ")

# Get current time and schedule message 1 minute later
now = datetime.datetime.now()
send_time_hours = now.hour
send_time_minutes = now.minute + 1  # Sending after 1 minute

# Send WhatsApp message
send_whatsapp_message(phone_number, message, send_time_hours, send_time_minutes)
