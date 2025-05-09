import cv2
from pyzbar.pyzbar import decode
import tkinter as tk
from tkinter import messagebox

# Function to prompt a pop-up with the scan result
def show_scan_result(success, qr_data=None):
    root = tk.Tk()
    root.withdraw()  # Hide the root window

    if success:
        messagebox.showinfo("Scan Successful", f"QR Code successfully scanned!\n\nData: {qr_data}")
    else:
        messagebox.showerror("Scan Failed", "Failed to scan a valid QR code.")
    
    root.quit()  # Close the Tkinter window after showing the message

def scan_qr():
    cap = cv2.VideoCapture(0)
    print("📸 QR Scanner started — Show any QR code to the webcam.")
    print("🛑 Press 'q' to quit.\n")

    while True:
        ret, frame = cap.read()
        if not ret:
            continue

        decoded_objs = decode(frame)
        if decoded_objs:
            for obj in decoded_objs:
                qr_data = obj.data.decode("utf-8").strip()

                # Display the scan result in a pop-up
                show_scan_result(success=True, qr_data=qr_data)

                # Close the camera after successful scan
                cap.release()
                cv2.destroyAllWindows()
                return  # Exit the function after a successful scan

        # Show the live video feed
        cv2.imshow("🔍 QR Code Scanner - Press 'q' to exit", frame)

        # Stop the program if 'q' is pressed
        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

    cap.release()
    cv2.destroyAllWindows()
    print("👋 QR Scanner closed.")

if __name__ == "__main__":
    scan_qr()
