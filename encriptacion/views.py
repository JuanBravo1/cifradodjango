from django.shortcuts import render
from Crypto.Cipher import ARC4  # RC4
from Crypto.PublicKey import ECC 
from Crypto.Random import get_random_bytes # ECDSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from .whirpool import whirlpool  # Whirlpool
from .forms import CifradoForm


def cifrar_rc4(data):
    key = get_random_bytes(16)  # Genera clave para RC4
    cipher = ARC4.new(key)
    encrypted_data = cipher.encrypt(data)
    return encrypted_data, key


def descifrar_rc4(data, key):
    cipher = ARC4.new(key)
    decrypted_data = cipher.decrypt(data)
    return decrypted_data


def firmar_ecdsa(data):
    key = ECC.generate(curve='P-256')
    h = SHA256.new(data)
    signer = DSS.new(key, 'fips-186-3')
    signature = signer.sign(h)
    return signature, key.public_key()


def hash_whirlpool(data):
    return whirlpool(data)


def encriptacion_view(request):
    if request.method == 'POST' and 'desencriptar' in request.POST:
        # Procesar desencriptado
        nombre_cifrado = request.POST.get('nombre_cifrado', '').encode('latin1')
        tarjeta_cifrada = request.POST.get('tarjeta_cifrada', '').encode('latin1')
        key_rc4_nombre = request.POST.get('key_rc4_nombre', '').encode('latin1')
        key_rc4_tarjeta = request.POST.get('key_rc4_tarjeta', '').encode('latin1')

        nombre_descifrado = descifrar_rc4(nombre_cifrado, key_rc4_nombre) if nombre_cifrado and key_rc4_nombre else 'No se pudo desencriptar'
        tarjeta_descifrada = descifrar_rc4(tarjeta_cifrada, key_rc4_tarjeta) if tarjeta_cifrada and key_rc4_tarjeta else 'No se pudo desencriptar'

        return render(request, 'encriptacion/resultados.html', {
            'nombre_cifrado': nombre_descifrado.decode('utf-8'),
            'tarjeta_cifrada': tarjeta_descifrada.decode('utf-8'),
            'key_rc4_nombre': key_rc4_nombre.decode('latin1'),
            'key_rc4_tarjeta': key_rc4_tarjeta.decode('latin1'),
            'firma_direccion': request.POST.get('firma_direccion', ''),
            'clave_publica_direccion': request.POST.get('clave_publica_direccion', ''),
            'password_hashed': request.POST.get('password_hashed', ''),
        })

    elif request.method == 'POST':
        # Procesar cifrado
        form = CifradoForm(request.POST)
        if form.is_valid():
            nombre = form.cleaned_data['nombre'].encode()
            direccion = form.cleaned_data['direccion'].encode()
            tarjeta_credito = form.cleaned_data['tarjeta_credito'].encode()
            password = form.cleaned_data['password'].encode()

            # Cifrar datos
            nombre_cifrado, key_rc4_nombre = cifrar_rc4(nombre)
            tarjeta_cifrada, key_rc4_tarjeta = cifrar_rc4(tarjeta_credito)

            # Firmar y hashear
            firma_direccion, clave_publica_direccion = firmar_ecdsa(direccion)
            password_hashed = hash_whirlpool(password)

            return render(request, 'encriptacion/resultados.html', {
                'nombre_cifrado': nombre_cifrado.decode('latin1'),
                'key_rc4_nombre': key_rc4_nombre.decode('latin1'),
                'tarjeta_cifrada': tarjeta_cifrada.decode('latin1'),
                'key_rc4_tarjeta': key_rc4_tarjeta.decode('latin1'),
                'firma_direccion': firma_direccion,
                'clave_publica_direccion': clave_publica_direccion,
                'password_hashed': password_hashed,
            })
    else:
        form = CifradoForm()

    return render(request, 'encriptacion/index.html', {'form': form})
