from django.urls import path
from rest_framework import routers
from rest_framework_simplejwt import views as jwt_views
from . import views

app_name = 'account'

urlpatterns = [
    path('login', jwt_views.TokenObtainPairView.as_view(),
         name='token_obtain_pair'),
    path('token/refresh', jwt_views.TokenRefreshView.as_view(),
         name='token_refresh'),
    path('password-update', views.ChangePassword.as_view(), name='password_update'),
    path('password/reset', views.ForgotPasswordView.as_view()),
    path('password/reset/confirm', views.ForgetPasswordConfirmView.as_view()),
    path('activate/<slug:eid>/<slug:token>', views.ActivateView.as_view()),
    path('logout', views.LogoutView.as_view()),
    path('signup', views.SignUpView.as_view()),

]
