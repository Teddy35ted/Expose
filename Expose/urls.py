"""
URL configuration for Expose project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from connexion import views

urlpatterns = [
    path('',views.home, name='home'),
    path('login/', views.user_login, name='login'),
    path('signup/', views.signin, name='signin'),
    path('logout/', views.user_logout, name='logout'),
    path('password_reset_request/', views.password_reset_request, name='password_reset_request'),
    path('password_reset_confirm/<int:user_id>/', views.password_reset_confirm, name='password_reset_confirm'),
    path('password_change/', views.password_change, name='password_change'),
    path('admin/', admin.site.urls),
]
