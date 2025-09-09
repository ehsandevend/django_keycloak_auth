import uuid

from datetime import timezone
from django.db import models

class AccessToken(models.Model):
    token = models.TextField()
    expires_at = models.DateTimeField()

    def is_expired(self):
        return timezone.now() >= self.expires_at
