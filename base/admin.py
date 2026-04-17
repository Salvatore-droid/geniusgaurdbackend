from django.contrib import admin
from .models import *

# Register your models here.
admin.site.register(Scan)
admin.site.register(Vulnerability)
admin.site.register(ScheduledScan)
admin.site.register(Notification)