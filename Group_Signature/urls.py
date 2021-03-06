"""Group_Signature URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.10/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url
from django.contrib import admin, auth
from Groupsign import views

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^$', views.home),
    url(r'^home/', views.home),
    url(r'^about/', views.aboutview),
    url(r'^verify/', views.verifyview),
    url(r'^register/', views.register_user),
    url(r'^login/', views.user_login),
    url(r'^logout/', views.user_logout),
    url(r'^join/', views.user_join),
    url(r'^newmessege/', views.newmessegeview),
    url(r'^open/', views.openview),
]
