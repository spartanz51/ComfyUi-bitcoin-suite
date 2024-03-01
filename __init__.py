import qrcode
import numpy as np
import torch
import hashlib
import ecdsa
import base58

def generatePrivateKeyFromImage(image_data):
    sha256_hash = hashlib.sha256(image_data).digest()
    rng = ecdsa.util.PRNG(sha256_hash)
    private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1, entropy=rng)
    return private_key.to_string()

def getQrCodeFromString(string):
    qr = qrcode.QRCode(box_size=1)
    qr.add_data(string)
    qr.make(fit=True)
    img = qr.make_image()
    img = img.resize((512, 512))
    img_array = np.array(img)
    tensor = torch.from_numpy(img_array).unsqueeze(0)
    return tensor

def getChecksum(data):
    hash1 = hashlib.sha256()
    hash1.update(data)
    hash2 = hashlib.sha256()
    hash2.update(hash1.digest())
    checksum = hash2.hexdigest()[0:8]
    return checksum

def privateKeyToPublicKey(private_key):
    return '04' + private_key.get_verifying_key().to_string().hex()

def publicKeyToCompressedPublickey(public_key):
    if int(public_key[-1], 16) % 2 == 0:
        return '02' + public_key[:64]
    else:
        return '03' + public_key[:64]

def publicKeyToBitcoinAddress(public_key):
    hash256FromPublicKey = hashlib.sha256()
    hash256FromPublicKey.update(bytes.fromhex(public_key))
    ridemp160FromHash256 = hashlib.new('ripemd160')
    ridemp160FromHash256.update(hash256FromPublicKey.digest())
    checksum = getChecksum(bytes.fromhex('00' + ridemp160FromHash256.hexdigest()))
    bitcoinAddress = base58.b58encode(bytes.fromhex('00' + ridemp160FromHash256.hexdigest() + checksum))
    return bitcoinAddress.decode('utf8')

def privateKeyToWIF(private_key, compressed=False):
    if compressed:
        data = '80' + private_key + '01'
    else:
        data = '80' + private_key
    checksum = getChecksum(bytes.fromhex(data))
    return base58.b58encode(bytes.fromhex(data + checksum)).decode('utf-8')

def generateWallet(rng):
    private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1, entropy=rng)
    private_key_hex = private_key.to_string().hex()
    public_key = privateKeyToPublicKey(private_key)
    bitcoin_address = publicKeyToBitcoinAddress(public_key)
    return {
        'private_key': private_key_hex,
        'public_key': public_key,
        'bitcoin_address': bitcoin_address,
        'wif_uncompressed': privateKeyToWIF(private_key_hex),
        'wif_compressed': privateKeyToWIF(private_key_hex, compressed=True)
    }

class ComfyUiBitcoinSuite:
    @classmethod
    def INPUT_TYPES(s):
        return {
            "required": {
                "image": ("IMAGE",),
            },
            "optional": {
                "salt": ("STRING", {"multiline": False, "default": "", "defaultBehavior": "input"}),
            },
        }
    RETURN_TYPES = ("STRING","IMAGE", "STRING","IMAGE",)
    RETURN_NAMES = ("PUBLIC_KEY", "PUBLIC_KEY_QR", "PRIVATE_KEY", "PRIVATE_KEY_QR")
    FUNCTION = "start"
    CATEGORY = "text"

    def start(self, image, salt = ""):
        image_str = (str(image.tolist()) + salt).encode()
        sha256_hash = hashlib.sha256(image_str).digest()
        rng = ecdsa.util.PRNG(sha256_hash)
        wallet = generateWallet(rng)
        public_address = wallet['bitcoin_address']
        public_address_qr = getQrCodeFromString(public_address)
        private_wif = wallet['wif_uncompressed']
        private_wif_qr = getQrCodeFromString(private_wif)

        return (public_address, public_address_qr, private_wif, private_wif_qr,)

NODE_CLASS_MAPPINGS = {
    "ComfyUiBitcoinSuite": ComfyUiBitcoinSuite,
}

NODE_DISPLAY_NAME_MAPPINGS = {
    "ComfyUiBitcoinSuite": "ComfyUi Bitcoin Suite ₿",
}