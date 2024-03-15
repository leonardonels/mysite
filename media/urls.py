from django.urls import path
from .views import *

app_name = "media"

urlpatterns = [

    path('upload', upload_image, name='upload'),
    path('search', search, name='search'),
    path('portfolio', portfolio, name='portfolio'),
    path('profile/', profile, name='profile'),
    path('profile/delete/', delete_account, name='delete_profile'),
    path('profile/change_username/', change_username, name='change_username'),
    path('profile/change_password/', change_password, name='change_password'),
]