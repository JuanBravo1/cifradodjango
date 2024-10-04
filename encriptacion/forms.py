from django import forms

class CifradoForm(forms.Form):
    nombre = forms.CharField(max_length=100, label='Nombre Completo')
    direccion = forms.CharField(max_length=255, label='Dirección')
    email = forms.EmailField(label='Correo Electrónico')
    telefono = forms.CharField(max_length=15, label='Número de Teléfono')
    password = forms.CharField(widget=forms.PasswordInput, label='Contraseña')
    tarjeta_credito = forms.CharField(max_length=16, widget=forms.PasswordInput, label='Número de Tarjeta de Crédito')
