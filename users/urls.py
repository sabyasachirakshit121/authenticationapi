from rest_framework import routers
from django.urls import path, include
from .views import AuthViewSet
from django.views.generic import TemplateView

router = routers.DefaultRouter(trailing_slash=False)
router.register('api/auth', AuthViewSet, basename='auth')

urlpatterns = [path('api/password_reset/', include(
    'django_rest_passwordreset.urls', namespace='password_reset')), path('', TemplateView.as_view(template_name="home.html"), name='home'), ]+router.urls
