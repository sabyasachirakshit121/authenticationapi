from rest_framework import routers
from django.urls import path, include
from .views import AuthViewSet

router = routers.DefaultRouter(trailing_slash=False)
router.register('api/auth', AuthViewSet, basename='auth')

urlpatterns = [path('api/password_reset/', include(
    'django_rest_passwordreset.urls', namespace='password_reset'))]+router.urls
