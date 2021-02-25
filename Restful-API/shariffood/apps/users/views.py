from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User
import secrets
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.shortcuts import redirect

from .models import ForgotPasswordToken, Profile, ActivateUserToken, Token
from .serializers import ForgotPasswordSerializer, ChangePasswordSerializer, UserSerializer, ProfileSerializer
from django.utils import timezone
from django.contrib.auth import user_logged_in
from rest_framework.decorators import action
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework.generics import GenericAPIView, get_object_or_404
from rest_framework import viewsets, exceptions
from rest_framework.response import Response
from .service import send_email
from rest_framework import permissions, status
from django.core.mail import EmailMessage
from django.db import transaction
from .auth import TokenAuth


def get_verify_number():
    import random
    s = ''
    for _ in range(10):
        s += str(random.randint(1, 10))
    return s


class RegisterView(viewsets.ModelViewSet):
    permission_classes = [AllowAny]
    queryset = Profile.objects.none()
    serializer_class = UserSerializer

    def authenticate_user(self, token):

        with transaction.atomic():
            user, created = TokenAuth().authenticate_credentials(token=token)
        user_logged_in.send(sender=user.__class__, request=self.request, user=user)
        return user

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = User.objects.create(
                username=serializer.data['username'],
            )
            Profile.objects.create(user=user)
            auth_token, token = Token.objects.create(user=user)
            vc = get_verify_number()
            user.profile.cart['verify'] = vc
            user.profile.save()
            mail = EmailMessage('verify code', f'Your verify code is {vc}', [request.user.email])
            mail.send()
            return Response({'token': token, 'auth': auth_token}, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer._errors, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=['put'], detail=False, permission_classes=[IsAuthenticated])
    def verify(self, request):
        code = request.data.get('code', None)
        if not code:
            raise exceptions.NotAcceptable
        else:
            if code != request.user.profile.cart.get('verify', ''):
                raise exceptions.NotAcceptable
            else:
                return Response(dict(), status.HTTP_200_OK)


class ForgotPasswordView(GenericAPIView):
    serializer_class = ForgotPasswordSerializer

    def post(self, request):
        data = self.get_serializer(request.data).data
        user = get_object_or_404(User, email=data['email'])
        uid = urlsafe_base64_encode(force_bytes(user.id))
        ForgotPasswordToken.objects.filter(uid=uid).delete()
        reset_password_token = ForgotPasswordToken(
            uid=uid,
            token=secrets.token_urlsafe(32),
            expiration_date=timezone.now() + timezone.timedelta(hours=24),
        )
        email = send_email.SendEmail(reset_password_token, user)
        email.send_email(
            'Restful-API/shariffood/apps/users/service/forget_password.html',
            'Restful-API/shariffood/apps/users/service/forget_password.txt')
        reset_password_token.save()
        return Response({'detail': 'Successfully Sent Reset Password Email'}, status=200)


class ForgetPasswordConfirmView(GenericAPIView):
    serializer_class = ForgotPasswordSerializer

    def post(self, request):
        data = self.get_serializer(request.data).data

        rs_token = get_object_or_404(ForgotPasswordToken, uid=data['uid'], token=data['token'])
        if (timezone.now() - rs_token.expiration_date).total_seconds() > 24 * 60 * 60:
            return Response({'error': 'Token Expired'}, status=400)

        user = get_object_or_404(User, id=urlsafe_base64_decode(data['uid']).decode('utf-8'))
        user.password = make_password(data['new_password1'])
        user.save()
        return Response({'detail': 'Successfully Changed Password'}, status=200)


class ChangePassword(GenericAPIView):
    serializer_class = ChangePasswordSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            data = serializer.data
        if not request.user.check_password(data['password']):
            return Response(data={'errors': 'incorrect current password'}, status=status.HTTP_406_NOT_ACCEPTABLE)
        request.user.password = make_password(data['new_password'])
        request.user.save()
        return Response(data={'detail': 'password changed successfully'}, status=status.HTTP_200_OK)


class SignUpView(GenericAPIView):
    queryset = Profile.objects.all()
    serializer_class = UserSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid(raise_exception=True):

            activate_user_token = ActivateUserToken(
                token=secrets.token_urlsafe(32),
                eid=urlsafe_base64_encode(force_bytes(serializer.validated_data['email'])),
            )
            activate_user_token.save()
            email = send_email.SendEmail(activate_user_token, request.user)
            email.send_email(
                'Restful-API/shariffood/apps/users/service/activate_user.html',
                'Restful-API/shariffood/apps/users/service/activate_user.txt')
            return Response({'detail': 'User created successfully. Check your email for confirmation link'},
                            status=200)
        else:
            return Response({'error': 'Error occurred during User creation'}, status=500)


class ActivateView(GenericAPIView):

    def get(self, request, eid, token):
        activate_user_token = get_object_or_404(ActivateUserToken,
                                                eid=eid, token=token)

        email = urlsafe_base64_decode(activate_user_token.eid).decode('utf-8')
        user = get_object_or_404(User, email=email)
        user.is_active = True
        user.save()

        return redirect('http://shariffood.ir/login')


class LogoutView(GenericAPIView):
    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        request.user.auth_token.delete()
        return Response(status=status.HTTP_200_OK)
