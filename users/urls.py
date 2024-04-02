from django.urls import path
from . import views
from rest_framework_simplejwt import views as jwt_views
from .views import ForgotPasswordView, RegisterView, ResetForgotPasswordView, UserView, LogoutView, VerifyForgotPasswordTokenView, VerifyUserView


urlpatterns = [
    path('register', RegisterView.as_view(), name='register'),
    path('user', UserView.as_view(), name='user'),
    path('verify-user', VerifyUserView.as_view(), name='verify'),
    path('forgot-password', ForgotPasswordView.as_view(), name='forgot_password'),
    path('verify-forgot-password-token', VerifyForgotPasswordTokenView.as_view(), name='verify_forgot_password_token'),
    path('reset-forgot-password', ResetForgotPasswordView.as_view(), name='reset_forgot_password'),
    path('token',
         jwt_views.TokenObtainPairView.as_view(),
         name='token_obtain_pair'),
    path('token/refresh',
         jwt_views.TokenRefreshView.as_view(),
         name='token_refresh'),
    path('test', views.TestView.as_view(), name='test'),
    path('logout', LogoutView.as_view(), name='logout'),
]
