from django.urls import path
from . import views

urlpatterns = [
    path('', views.encriptacion_view, name='index'),  # Cambia 'views.index' a 'views.encriptacion_view'
]
