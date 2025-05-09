import qrcode

def generate_solana_qr(data, mode='wallet'):
    """
    Generate a QR code for a Solana wallet address or transaction.

    :param data: Wallet address or transaction signature
    :param mode: 'wallet' or 'transaction'
    """
    # Format link for Solana Explorer
    if mode == 'wallet':
        url = f"https://explorer.solana.com/address/{data}"
    elif mode == 'transaction':
        url = f"https://explorer.solana.com/tx/{data}"
    else:
        raise ValueError("Mode must be 'wallet' or 'transaction'.")

    # Create QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=4
    )
    qr.add_data(url)
    qr.make(fit=True)

    # Create image
    img = qr.make_image(fill_color="black", back_color="white")
    img_filename = f"solana_qr_{mode}.png"
    img.save(img_filename)

    print(f"✅ QR Code saved as {img_filename}")
    img.show()

# Example Usage
if __name__ == "__main__":
    print("🔗 Solana QR Generator")
    user_input = input("Enter Solana wallet address or transaction hash: ")
    mode_input = input("Is this a 'wallet' or 'transaction'? ").lower().strip()

    generate_solana_qr(user_input, mode_input)
