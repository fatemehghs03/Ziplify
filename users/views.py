from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken


from .serializers import RegisterSerializer, LoginSerializer, LogoutSerializer


class RegisterAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        refresh_token = RefreshToken.for_user(user)

        return Response(
            {
                "detail": "User created successfully",
                "user": RegisterSerializer(user).data,
                "access": str(refresh_token.access_token),
                "refresh": str(refresh_token),
            },
            status=status.HTTP_201_CREATED
        )


class LoginAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data["user"]

        refresh_token = RefreshToken.for_user(user)

        return Response(
            {
                "access": str(refresh_token.access_token),
                "refresh": str(refresh_token),
            },
            status=status.HTTP_200_OK
        )


class LogoutAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = LogoutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(
            {"detail": "logout successfully."},
            status=status.HTTP_205_RESET_CONTENT
        )
