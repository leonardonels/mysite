from django.urls import path
from .views import *
from mysite.views import login_view

app_name = "web_auth"

urlpatterns = [
    path('registration/', registration, name='registration'),
    path('new_registration/', new_registration, name='new_registration'),
    path('registration_verification/', registration_verification, name='registration_verification'),
    path('new_registration_verification/', new_registration_verification, name='new_registration_verification'),
    path('authentication/', authentication, name='authentication'),
    path('authentication_verification/', authentication_verification, name='authentication_verification'),
    path('remove_passkey/', remove_passkey, name='remove_passkey'),
    path('login_with_passkey/', login_with_passkey, name='login_with_passkey'),
    path('login_with_passkey/set_username/', set_username_in_session, name='set_username'),
    path('login/set_new_username/', set_new_username_in_session, name='set_new_username'),
    path('delete-user/<str:username>/', delete_user_view, name='delete_user'),
    path('login/', login_view, name='login'),

]
