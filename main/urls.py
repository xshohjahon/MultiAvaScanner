from django.urls import path
from . import views

urlpatterns = [
    path('', views.HomeView.as_view(), name='home'),
    path('scan/url/', views.ScanURLView.as_view(), name='scan_url'),
    path('scan/file/', views.ScanFileView.as_view(), name='scan_file'),
    path('history/', views.HistoryView.as_view(), name='history'),
    path('scan/<int:scan_id>/', views.ScanDetailView.as_view(), name='scan_detail'),
    path('scan/qr/', views.ScanQRView.as_view(), name='scan_qr'),
    path('scan/password/', views.ScanPasswordView.as_view(), name='scan_password'),
]